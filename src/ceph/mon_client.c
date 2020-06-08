// SPDX-License-Identifier: GPL-2.0
#include "ceph/ceph_debug.h"

#include "module.h"
#include "types.h"
#include "slab.h"
#include "random.h"
#include "sched.h"

#include <linux/utsname.h>

#include "ceph/ceph_features.h"
#include "ceph/mon_client.h"
#include "ceph/libceph.h"
#include "ceph/debugfs.h"
#include "ceph/decode.h"
#include "ceph/auth.h"

/*
 * Interact with Ceph monitor cluster.  Handle requests for new map
 * versions, and periodically resend as needed.  Also implement
 * statfs() and umount().
 *
 * A small cluster of Ceph "monitors" are responsible for managing critical
 * cluster configuration and state information.  An odd number (e.g., 3, 5)
 * of cmon daemons use a modified version of the Paxos part-time parliament
 * algorithm to manage the MDS map (mds cluster membership), OSD map, and
 * list of clients who have mounted the file system.
 *
 * We maintain an open, active session with a monitor at all times in order to
 * receive timely MDSMap updates.  We periodically send a keepalive byte on the
 * TCP socket to ensure we detect a failure.  If the connection does break, we
 * randomly hunt for a new monitor.  Once the connection is reestablished, we
 * resend any outstanding requests.
 */

static const struct ceph_connection_operations mon_con_ops;

static int __validate_auth(struct ceph_mon_client *monc);

/*
 * Decode a monmap blob (e.g., during mount).
 */
static struct ceph_monmap *ceph_monmap_decode(void *p, void *end)
{
	struct ceph_monmap *m = NULL;
	int i, err = -EINVAL;
	struct ceph_fsid fsid;
	u32 epoch, num_mon;
	u32 len;

	ceph_decode_32_safe(&p, end, len, bad);
	ceph_decode_need(&p, end, len, bad);

	dout("monmap_decode %p %p len %d (%d)\n", p, end, len, (int)(end-p));
	p += sizeof(u16);  /* skip version */

	ceph_decode_need(&p, end, sizeof(fsid) + 2*sizeof(u32), bad);
	ceph_decode_copy(&p, &fsid, sizeof(fsid));
	epoch = ceph_decode_32(&p);

	num_mon = ceph_decode_32(&p);

	if (num_mon > CEPH_MAX_MON)
		goto bad;
	m = kmalloc(struct_size(m, mon_inst, num_mon), GFP_NOFS);
	if (m == NULL)
		return ERR_PTR(-ENOMEM);
	m->fsid = fsid;
	m->epoch = epoch;
	m->num_mon = num_mon;
	for (i = 0; i < num_mon; ++i) {
		struct ceph_entity_inst *inst = &m->mon_inst[i];

		/* copy name portion */
		ceph_decode_copy_safe(&p, end, &inst->name,
					sizeof(inst->name), bad);
		err = ceph_decode_entity_addr(&p, end, &inst->addr);
		if (err)
			goto bad;
	}
	dout("monmap_decode epoch %d, num_mon %d\n", m->epoch,
	     m->num_mon);
	for (i = 0; i < m->num_mon; i++)
		dout("monmap_decode  mon%d is %s\n", i,
		     ceph_pr_addr(&m->mon_inst[i].addr));
	return m;
bad:
	dout("monmap_decode failed with %d\n", err);
	kfree(m);
	return ERR_PTR(err);
}

/*
 * return true if *addr is included in the monmap.
 */
int ceph_monmap_contains(struct ceph_monmap *m, struct ceph_entity_addr *addr)
{
	int i;

	for (i = 0; i < m->num_mon; i++)
		if (memcmp(addr, &m->mon_inst[i].addr, sizeof(*addr)) == 0)
			return 1;
	return 0;
}

/*
 * Send an auth request.
 */
static void __send_prepared_auth_request(struct ceph_mon_client *monc, int len)
{
	monc->pending_auth = 1;
	monc->m_auth->front.iov_len = len;
	monc->m_auth->hdr.front_len = cpu_to_le32(len);
	ceph_msg_revoke(monc->m_auth);
	ceph_msg_get(monc->m_auth);  /* keep our ref */
	ceph_con_send(&monc->con, monc->m_auth);
}

/*
 * Close monitor session, if any.
 */
static void __close_session(struct ceph_mon_client *monc)
{
	dout("__close_session closing mon%d\n", monc->cur_mon);
	ceph_msg_revoke(monc->m_auth);
	ceph_msg_revoke_incoming(monc->m_auth_reply);
	ceph_msg_revoke(monc->m_subscribe);
	ceph_msg_revoke_incoming(monc->m_subscribe_ack);
	ceph_con_close(&monc->con);

	monc->pending_auth = 0;
	ceph_auth_reset(monc->auth);
}

/*
 * Pick a new monitor at random and set cur_mon.  If we are repicking
 * (i.e. cur_mon is already set), be sure to pick a different one.
 */
static void pick_new_mon(struct ceph_mon_client *monc)
{
	int old_mon = monc->cur_mon;

	BUG_ON(monc->monmap->num_mon < 1);

	if (monc->monmap->num_mon == 1) {
		monc->cur_mon = 0;
	} else {
		int max = monc->monmap->num_mon;
		int o = -1;
		int n;

		if (monc->cur_mon >= 0) {
			if (monc->cur_mon < monc->monmap->num_mon)
				o = monc->cur_mon;
			if (o >= 0)
				max--;
		}

		n = prandom_u32() % max;
		if (o >= 0 && n >= o)
			n++;

		monc->cur_mon = n;
	}

	dout("%s mon%d -> mon%d out of %d mons\n", __func__, old_mon,
	     monc->cur_mon, monc->monmap->num_mon);
}

/*
 * Open a session with a new monitor.
 */
static void __open_session(struct ceph_mon_client *monc)
{
	int ret;

	pick_new_mon(monc);

	monc->hunting = true;
	if (monc->had_a_connection) {
		monc->hunt_mult *= CEPH_MONC_HUNT_BACKOFF;
		if (monc->hunt_mult > CEPH_MONC_HUNT_MAX_MULT)
			monc->hunt_mult = CEPH_MONC_HUNT_MAX_MULT;
	}

	monc->sub_renew_after = jiffies; /* i.e., expired */
	monc->sub_renew_sent = 0;

	dout("%s opening mon%d\n", __func__, monc->cur_mon);
	ceph_con_open(&monc->con, CEPH_ENTITY_TYPE_MON, monc->cur_mon,
		      &monc->monmap->mon_inst[monc->cur_mon].addr);

	/*
	 * send an initial keepalive to ensure our timestamp is valid
	 * by the time we are in an OPENED state
	 */
	ceph_con_keepalive(&monc->con);

	/* initiate authentication handshake */
	ret = ceph_auth_build_hello(monc->auth,
				    monc->m_auth->front.iov_base,
				    monc->m_auth->front_alloc_len);
	BUG_ON(ret <= 0);
	__send_prepared_auth_request(monc, ret);
}

static void reopen_session(struct ceph_mon_client *monc)
{
	if (!monc->hunting)
		pr_info("mon%d %s session lost, hunting for new mon\n",
		    monc->cur_mon, ceph_pr_addr(&monc->con.peer_addr));

	__close_session(monc);
	__open_session(monc);
}

void ceph_monc_reopen_session(struct ceph_mon_client *monc)
{
	mutex_lock(&monc->mutex);
	reopen_session(monc);
	mutex_unlock(&monc->mutex);
}

static void un_backoff(struct ceph_mon_client *monc)
{
	monc->hunt_mult /= 2; /* reduce by 50% */
	if (monc->hunt_mult < 1)
		monc->hunt_mult = 1;
	dout("%s hunt_mult now %d\n", __func__, monc->hunt_mult);
}

/*
 * Reschedule delayed work timer.
 */
static void __schedule_delayed(struct ceph_mon_client *monc)
{
	unsigned long delay;

	if (monc->hunting)
		delay = CEPH_MONC_HUNT_INTERVAL * monc->hunt_mult;
	else
		delay = CEPH_MONC_PING_INTERVAL;

	dout("__schedule_delayed after %lu\n", delay);
	mod_delayed_work(system_wq, &monc->delayed_work,
			 round_jiffies_relative(delay));
}

/*
 * Reschedule beacon send
 */
static void __schedule_beacon_send(struct ceph_mon_client *monc)
{
	struct ceph_messenger *msgr = &monc->client->msgr;
	unsigned long delay = CEPH_MONC_BEACON_INTERVAL;

	if (msgr->inst.name.type != CEPH_ENTITY_TYPE_OSD)
		/* This is only for OSD */
		return;

	dout("__schedule_beacon_send after %lu\n", delay);
	mod_delayed_work(system_wq, &monc->beacon_work,
			 round_jiffies_relative(delay));
}

const char *ceph_sub_str[] = {
	[CEPH_SUB_MONMAP] = "monmap",
	[CEPH_SUB_OSDMAP] = "osdmap",
	[CEPH_SUB_FSMAP]  = "fsmap.user",
	[CEPH_SUB_MDSMAP] = "mdsmap",
};

/*
 * Send subscribe request for one or more maps, according to
 * monc->subs.
 */
static void __send_subscribe(struct ceph_mon_client *monc)
{
	struct ceph_msg *msg = monc->m_subscribe;
	void *p = msg->front.iov_base;
	void *const end = p + msg->front_alloc_len;
	int num = 0;
	int i;

	dout("%s sent %lu\n", __func__, monc->sub_renew_sent);

	BUG_ON(monc->cur_mon < 0);

	if (!monc->sub_renew_sent)
		monc->sub_renew_sent = jiffies | 1; /* never 0 */

	msg->hdr.version = cpu_to_le16(2);

	for (i = 0; i < ARRAY_SIZE(monc->subs); i++) {
		if (monc->subs[i].want)
			num++;
	}
	BUG_ON(num < 1); /* monmap sub is always there */
	ceph_encode_32(&p, num);
	for (i = 0; i < ARRAY_SIZE(monc->subs); i++) {
		char buf[32];
		int len;

		if (!monc->subs[i].want)
			continue;

		len = sprintf(buf, "%s", ceph_sub_str[i]);
		if (i == CEPH_SUB_MDSMAP &&
		    monc->fs_cluster_id != CEPH_FS_CLUSTER_ID_NONE)
			len += sprintf(buf + len, ".%d", monc->fs_cluster_id);

		dout("%s %s start %llu flags 0x%x\n", __func__, buf,
		     le64_to_cpu(monc->subs[i].item.start),
		     monc->subs[i].item.flags);
		ceph_encode_string(&p, end, buf, len);
		memcpy(p, &monc->subs[i].item, sizeof(monc->subs[i].item));
		p += sizeof(monc->subs[i].item);
	}

	BUG_ON(p > end);
	msg->front.iov_len = p - msg->front.iov_base;
	msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);
	ceph_msg_revoke(msg);
	ceph_con_send(&monc->con, ceph_msg_get(msg));
}

static void handle_subscribe_ack(struct ceph_mon_client *monc,
				 struct ceph_msg *msg)
{
	unsigned int seconds;
	struct ceph_mon_subscribe_ack *h = msg->front.iov_base;

	if (msg->front.iov_len < sizeof(*h))
		goto bad;
	seconds = le32_to_cpu(h->duration);

	mutex_lock(&monc->mutex);
	if (monc->sub_renew_sent) {
		/*
		 * This is only needed for legacy (infernalis or older)
		 * MONs -- see delayed_work().
		 */
		monc->sub_renew_after = monc->sub_renew_sent +
					    (seconds >> 1) * HZ - 1;
		dout("%s sent %lu duration %d renew after %lu\n", __func__,
		     monc->sub_renew_sent, seconds, monc->sub_renew_after);
		monc->sub_renew_sent = 0;
	} else {
		dout("%s sent %lu renew after %lu, ignoring\n", __func__,
		     monc->sub_renew_sent, monc->sub_renew_after);
	}
	mutex_unlock(&monc->mutex);
	return;
bad:
	pr_err("got corrupt subscribe-ack msg\n");
	ceph_msg_dump(msg);
}

/*
 * Register interest in a map
 *
 * @sub: one of CEPH_SUB_*
 * @epoch: X for "every map since X", or 0 for "just the latest"
 */
static bool __ceph_monc_want_map(struct ceph_mon_client *monc, int sub,
				 u32 epoch, bool continuous)
{
	__le64 start = cpu_to_le64(epoch);
	u8 flags = !continuous ? CEPH_SUBSCRIBE_ONETIME : 0;

	dout("%s %s epoch %u continuous %d\n", __func__, ceph_sub_str[sub],
	     epoch, continuous);

	if (monc->subs[sub].want &&
	    monc->subs[sub].item.start == start &&
	    monc->subs[sub].item.flags == flags)
		return false;

	monc->subs[sub].item.start = start;
	monc->subs[sub].item.flags = flags;
	monc->subs[sub].want = true;

	return true;
}

bool ceph_monc_want_map(struct ceph_mon_client *monc, int sub, u32 epoch,
			bool continuous)
{
	bool need_request;

	mutex_lock(&monc->mutex);
	need_request = __ceph_monc_want_map(monc, sub, epoch, continuous);
	mutex_unlock(&monc->mutex);

	return need_request;
}
EXPORT_SYMBOL(ceph_monc_want_map);

/*
 * Keep track of which maps we have
 *
 * @sub: one of CEPH_SUB_*
 */
static void __ceph_monc_got_map(struct ceph_mon_client *monc, int sub,
				u32 epoch)
{
	dout("%s %s epoch %u\n", __func__, ceph_sub_str[sub], epoch);

	if (monc->subs[sub].want) {
		if (monc->subs[sub].item.flags & CEPH_SUBSCRIBE_ONETIME)
			monc->subs[sub].want = false;
		else
			monc->subs[sub].item.start = cpu_to_le64(epoch + 1);
	}

	monc->subs[sub].have = epoch;
}

void ceph_monc_got_map(struct ceph_mon_client *monc, int sub, u32 epoch)
{
	mutex_lock(&monc->mutex);
	__ceph_monc_got_map(monc, sub, epoch);
	mutex_unlock(&monc->mutex);
}
EXPORT_SYMBOL(ceph_monc_got_map);

void ceph_monc_renew_subs(struct ceph_mon_client *monc)
{
	mutex_lock(&monc->mutex);
	__send_subscribe(monc);
	mutex_unlock(&monc->mutex);
}
EXPORT_SYMBOL(ceph_monc_renew_subs);

/*
 * Wait for an osdmap with a given epoch.
 *
 * @epoch: epoch to wait for
 * @timeout: in jiffies, 0 means "wait forever"
 */
int ceph_monc_wait_osdmap(struct ceph_mon_client *monc, u32 epoch,
			  unsigned long timeout)
{
	unsigned long started = jiffies;
	long ret;

	mutex_lock(&monc->mutex);
	while (monc->subs[CEPH_SUB_OSDMAP].have < epoch) {
		mutex_unlock(&monc->mutex);

		if (timeout && time_after_eq(jiffies, started + timeout))
			return -ETIMEDOUT;

		ret = wait_event_interruptible_timeout(monc->client->auth_wq,
				     monc->subs[CEPH_SUB_OSDMAP].have >= epoch,
				     ceph_timeout_jiffies(timeout));
		if (ret < 0)
			return ret;

		mutex_lock(&monc->mutex);
	}

	mutex_unlock(&monc->mutex);
	return 0;
}
EXPORT_SYMBOL(ceph_monc_wait_osdmap);

/*
 * Open a session with a random monitor.  Request monmap and osdmap,
 * which are waited upon in __ceph_open_session().
 */
int ceph_monc_open_session(struct ceph_mon_client *monc)
{
	mutex_lock(&monc->mutex);
	__ceph_monc_want_map(monc, CEPH_SUB_MONMAP, 0, true);
	__ceph_monc_want_map(monc, CEPH_SUB_OSDMAP, 0, false);
	__open_session(monc);
	__schedule_delayed(monc);
	__schedule_beacon_send(monc);
	mutex_unlock(&monc->mutex);
	return 0;
}
EXPORT_SYMBOL(ceph_monc_open_session);

static void ceph_monc_handle_map(struct ceph_mon_client *monc,
				 struct ceph_msg *msg)
{
	struct ceph_client *client = monc->client;
	struct ceph_monmap *monmap = NULL, *old = monc->monmap;
	void *p, *end;

	mutex_lock(&monc->mutex);

	dout("handle_monmap\n");
	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	monmap = ceph_monmap_decode(p, end);
	if (IS_ERR(monmap)) {
		pr_err("problem decoding monmap, %d\n",
		       (int)PTR_ERR(monmap));
		ceph_msg_dump(msg);
		goto out;
	}

	if (ceph_check_fsid(monc->client, &monmap->fsid) < 0) {
		kfree(monmap);
		goto out;
	}

	client->monc.monmap = monmap;
	kfree(old);

	__ceph_monc_got_map(monc, CEPH_SUB_MONMAP, monc->monmap->epoch);
	client->have_fsid = true;

out:
	mutex_unlock(&monc->mutex);
	wake_up_all(&client->auth_wq);
}

/*
 * generic requests (currently statfs, mon_get_version)
 */
DEFINE_RB_FUNCS(generic_request, struct ceph_mon_generic_request, tid, node)

static void release_generic_request(struct kref *kref)
{
	struct ceph_mon_generic_request *req =
		container_of(kref, struct ceph_mon_generic_request, kref);

	dout("%s greq %p request %p reply %p\n", __func__, req, req->request,
	     req->reply);
	WARN_ON(!RB_EMPTY_NODE(&req->node));

	if (req->reply)
		ceph_msg_put(req->reply);
	if (req->request)
		ceph_msg_put(req->request);

	kfree(req);
}

static void put_generic_request(struct ceph_mon_generic_request *req)
{
	if (req)
		kref_put(&req->kref, release_generic_request);
}

static void get_generic_request(struct ceph_mon_generic_request *req)
{
	kref_get(&req->kref);
}

static struct ceph_mon_generic_request *
alloc_generic_request(struct ceph_mon_client *monc, gfp_t gfp)
{
	struct ceph_mon_generic_request *req;

	req = kzalloc(sizeof(*req), gfp);
	if (!req)
		return NULL;

	req->monc = monc;
	kref_init(&req->kref);
	RB_CLEAR_NODE(&req->node);
	init_completion(&req->completion);

	dout("%s greq %p\n", __func__, req);
	return req;
}

static void set_tid_generic_request(struct ceph_mon_generic_request *req)
{
	struct ceph_mon_client *monc = req->monc;

	req->tid = ++monc->last_tid;
}

static void register_generic_request(struct ceph_mon_generic_request *req)
{
	struct ceph_mon_client *monc = req->monc;

	WARN_ON(req->tid);

	get_generic_request(req);
	set_tid_generic_request(req);
	insert_generic_request(&monc->generic_request_tree, req);
}

static void send_generic_request(struct ceph_mon_client *monc,
				 struct ceph_mon_generic_request *req)
{
	WARN_ON(!req->tid);

	dout("%s greq %p tid %llu\n", __func__, req, req->tid);
	req->request->hdr.tid = cpu_to_le64(req->tid);
	ceph_con_send(&monc->con, ceph_msg_get(req->request));
}

static void __finish_generic_request(struct ceph_mon_generic_request *req)
{
	struct ceph_mon_client *monc = req->monc;

	dout("%s greq %p tid %llu\n", __func__, req, req->tid);
	erase_generic_request(&monc->generic_request_tree, req);

	ceph_msg_revoke(req->request);
	ceph_msg_revoke_incoming(req->reply);
}

static void finish_generic_request(struct ceph_mon_generic_request *req)
{
	__finish_generic_request(req);
	put_generic_request(req);
}

static void complete_generic_request(struct ceph_mon_generic_request *req)
{
	if (req->complete_cb)
		req->complete_cb(req);
	else
		complete_all(&req->completion);
	put_generic_request(req);
}

static void cancel_generic_request(struct ceph_mon_generic_request *req)
{
	struct ceph_mon_client *monc = req->monc;
	struct ceph_mon_generic_request *lookup_req;

	dout("%s greq %p tid %llu\n", __func__, req, req->tid);

	mutex_lock(&monc->mutex);
	lookup_req = lookup_generic_request(&monc->generic_request_tree,
					    req->tid);
	if (lookup_req) {
		WARN_ON(lookup_req != req);
		finish_generic_request(req);
	}

	mutex_unlock(&monc->mutex);
}

static int wait_generic_request(struct ceph_mon_generic_request *req)
{
	int ret;

	dout("%s greq %p tid %llu\n", __func__, req, req->tid);
	ret = wait_for_completion_interruptible(&req->completion);
	if (ret)
		cancel_generic_request(req);
	else
		ret = req->result; /* completed */

	return ret;
}

static struct ceph_msg *get_generic_reply(struct ceph_connection *con,
					 struct ceph_msg_header *hdr,
					 int *skip)
{
	struct ceph_mon_client *monc = con->private;
	struct ceph_mon_generic_request *req;
	u64 tid = le64_to_cpu(hdr->tid);
	struct ceph_msg *m;

	mutex_lock(&monc->mutex);
	req = lookup_generic_request(&monc->generic_request_tree, tid);
	if (!req) {
		dout("get_generic_reply %lld dne\n", tid);
		*skip = 1;
		m = NULL;
	} else {
		dout("get_generic_reply %lld got %p\n", tid, req->reply);
		if (req->reply) {
			*skip = 0;
			m = ceph_msg_get(req->reply);
		} else {
			*skip = 1;
			m = NULL;
		}
		/*
		 * we don't need to track the connection reading into
		 * this reply because we only have one open connection
		 * at a time, ever.
		 */
	}
	mutex_unlock(&monc->mutex);
	return m;
}

/*
 * statfs
 */
static void handle_statfs_reply(struct ceph_mon_client *monc,
				struct ceph_msg *msg)
{
	struct ceph_mon_generic_request *req;
	struct ceph_mon_statfs_reply *reply = msg->front.iov_base;
	u64 tid = le64_to_cpu(msg->hdr.tid);

	dout("%s msg %p tid %llu\n", __func__, msg, tid);

	if (msg->front.iov_len != sizeof(*reply))
		goto bad;

	mutex_lock(&monc->mutex);
	req = lookup_generic_request(&monc->generic_request_tree, tid);
	if (!req) {
		mutex_unlock(&monc->mutex);
		return;
	}

	req->result = 0;
	*req->u.st = reply->st; /* struct */
	__finish_generic_request(req);
	mutex_unlock(&monc->mutex);

	complete_generic_request(req);
	return;

bad:
	pr_err("corrupt statfs reply, tid %llu\n", tid);
	ceph_msg_dump(msg);
}

/*
 * Do a synchronous statfs().
 */
int ceph_monc_do_statfs(struct ceph_mon_client *monc, u64 data_pool,
			struct ceph_statfs *buf)
{
	struct ceph_mon_generic_request *req;
	struct ceph_mon_statfs *h;
	int ret = -ENOMEM;

	req = alloc_generic_request(monc, GFP_NOFS);
	if (!req)
		goto out;

	req->request = ceph_msg_new(CEPH_MSG_STATFS, sizeof(*h), GFP_NOFS,
				    true);
	if (!req->request)
		goto out;

	req->reply = ceph_msg_new(CEPH_MSG_STATFS_REPLY, 64, GFP_NOFS, true);
	if (!req->reply)
		goto out;

	req->u.st = buf;
	req->request->hdr.version = cpu_to_le16(2);

	mutex_lock(&monc->mutex);
	register_generic_request(req);
	/* fill out request */
	h = req->request->front.iov_base;
	h->monhdr.have_version = 0;
	h->monhdr.session_mon = cpu_to_le16(-1);
	h->monhdr.session_mon_tid = 0;
	h->fsid = monc->monmap->fsid;
	h->contains_data_pool = (data_pool != CEPH_NOPOOL);
	h->data_pool = cpu_to_le64(data_pool);
	send_generic_request(monc, req);
	mutex_unlock(&monc->mutex);

	ret = wait_generic_request(req);
out:
	put_generic_request(req);
	return ret;
}
EXPORT_SYMBOL(ceph_monc_do_statfs);

static void handle_get_version_reply(struct ceph_mon_client *monc,
				     struct ceph_msg *msg)
{
	struct ceph_mon_generic_request *req;
	u64 tid = le64_to_cpu(msg->hdr.tid);
	void *p = msg->front.iov_base;
	void *end = p + msg->front_alloc_len;
	u64 handle;

	dout("%s msg %p tid %llu\n", __func__, msg, tid);

	ceph_decode_need(&p, end, 2*sizeof(u64), bad);
	handle = ceph_decode_64(&p);
	if (tid != 0 && tid != handle)
		goto bad;

	mutex_lock(&monc->mutex);
	req = lookup_generic_request(&monc->generic_request_tree, handle);
	if (!req) {
		mutex_unlock(&monc->mutex);
		return;
	}

	req->result = 0;
	req->u.newest = ceph_decode_64(&p);
	__finish_generic_request(req);
	mutex_unlock(&monc->mutex);

	complete_generic_request(req);
	return;

bad:
	pr_err("corrupt mon_get_version reply, tid %llu\n", tid);
	ceph_msg_dump(msg);
}

static struct ceph_mon_generic_request *
__ceph_monc_get_version(struct ceph_mon_client *monc, const char *what,
			ceph_monc_callback_t cb, u64 private_data)
{
	struct ceph_mon_generic_request *req;

	req = alloc_generic_request(monc, GFP_NOIO);
	if (!req)
		goto err_put_req;

	req->request = ceph_msg_new(CEPH_MSG_MON_GET_VERSION,
				    sizeof(u64) + sizeof(u32) + strlen(what),
				    GFP_NOIO, true);
	if (!req->request)
		goto err_put_req;

	req->reply = ceph_msg_new(CEPH_MSG_MON_GET_VERSION_REPLY, 32, GFP_NOIO,
				  true);
	if (!req->reply)
		goto err_put_req;

	req->complete_cb = cb;
	req->private_data = private_data;

	mutex_lock(&monc->mutex);
	register_generic_request(req);
	{
		void *p = req->request->front.iov_base;
		void *const end = p + req->request->front_alloc_len;

		ceph_encode_64(&p, req->tid); /* handle */
		ceph_encode_string(&p, end, what, strlen(what));
		WARN_ON(p != end);
	}
	send_generic_request(monc, req);
	mutex_unlock(&monc->mutex);

	return req;

err_put_req:
	put_generic_request(req);
	return ERR_PTR(-ENOMEM);
}

/*
 * Send MMonGetVersion and wait for the reply.
 *
 * @what: one of "mdsmap", "osdmap" or "monmap"
 */
int ceph_monc_get_version(struct ceph_mon_client *monc, const char *what,
			  u64 *newest)
{
	struct ceph_mon_generic_request *req;
	int ret;

	req = __ceph_monc_get_version(monc, what, NULL, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	ret = wait_generic_request(req);
	if (!ret)
		*newest = req->u.newest;

	put_generic_request(req);
	return ret;
}
EXPORT_SYMBOL(ceph_monc_get_version);

/*
 * Send MMonGetVersion,
 *
 * @what: one of "mdsmap", "osdmap" or "monmap"
 */
int ceph_monc_get_version_async(struct ceph_mon_client *monc, const char *what,
				ceph_monc_callback_t cb, u64 private_data)
{
	struct ceph_mon_generic_request *req;

	req = __ceph_monc_get_version(monc, what, cb, private_data);
	if (IS_ERR(req))
		return PTR_ERR(req);

	put_generic_request(req);
	return 0;
}
EXPORT_SYMBOL(ceph_monc_get_version_async);

static void handle_command_ack(struct ceph_mon_client *monc,
			       struct ceph_msg *msg)
{
	struct ceph_mon_generic_request *req;
	void *p = msg->front.iov_base;
	void *const end = p + msg->front_alloc_len;
	u64 tid = le64_to_cpu(msg->hdr.tid);

	dout("%s msg %p tid %llu\n", __func__, msg, tid);

	ceph_decode_need(&p, end, sizeof(struct ceph_mon_request_header) +
							    sizeof(u32), bad);
	p += sizeof(struct ceph_mon_request_header);

	mutex_lock(&monc->mutex);
	req = lookup_generic_request(&monc->generic_request_tree, tid);
	if (!req) {
		mutex_unlock(&monc->mutex);
		return;
	}

	req->result = ceph_decode_32(&p);
	__finish_generic_request(req);
	mutex_unlock(&monc->mutex);

	complete_generic_request(req);
	return;

bad:
	pr_err("corrupt mon_command ack, tid %llu\n", tid);
	ceph_msg_dump(msg);
}

__printf(2, 3)
static int ceph_monc_send_command_and_wait(struct ceph_mon_client *monc,
					   const char *format, ...)
{
	struct ceph_mon_generic_request *req;
	struct ceph_mon_command *h;
	va_list args;

	int ret = -ENOMEM;
	size_t max_sz;
	int len;

	req = alloc_generic_request(monc, GFP_NOIO);
	if (!req)
		goto out;

	va_start(args, format);
	max_sz = vsnprintf(NULL, 0, format, args);
	va_end(args);

	max_sz += sizeof(*h) + 1;

	req->request = ceph_msg_new(CEPH_MSG_MON_COMMAND, max_sz, GFP_NOIO,
				    true);
	if (!req->request)
		goto out;

	req->reply = ceph_msg_new(CEPH_MSG_MON_COMMAND_ACK, 512, GFP_NOIO,
				  true);
	if (!req->reply)
		goto out;

	h = req->request->front.iov_base;
	h->monhdr.have_version = 0;
	h->monhdr.session_mon = cpu_to_le16(-1);
	h->monhdr.session_mon_tid = 0;
	h->fsid = monc->monmap->fsid;
	h->num_strs = cpu_to_le32(1);

	va_start(args, format);
	len = vsnprintf(h->str, max_sz - sizeof(*h), format, args);
	va_end(args);
	h->str_len = cpu_to_le32(len);

	mutex_lock(&monc->mutex);
	register_generic_request(req);
	send_generic_request(monc, req);
	mutex_unlock(&monc->mutex);

	ret = wait_generic_request(req);
out:
	put_generic_request(req);
	return ret;

}

int ceph_monc_blacklist_add(struct ceph_mon_client *monc,
			    struct ceph_entity_addr *client_addr)
{
	const char *fmt = "{ \"prefix\": \"osd blacklist\", \
		             \"blacklistop\": \"add\",	\
			     \"addr\": \"%pISpc/%u\" }";
	int ret;

	ret = ceph_monc_send_command_and_wait(monc, fmt,
					      &client_addr->in_addr,
					      le32_to_cpu(client_addr->nonce));
	if (!ret)
		/*
		 * Make sure we have the osdmap that includes the blacklist
		 * entry.  This is needed to ensure that the OSDs pick up the
		 * new blacklist before processing any future requests from
		 * this client.
		 */
		ret = ceph_wait_for_latest_osdmap(monc->client, 0);

	return ret;
}
EXPORT_SYMBOL(ceph_monc_blacklist_add);

int ceph_monc_osd_to_crush_add(struct ceph_mon_client *monc,
			       int osd_id, const char *weight)
{
	/* FIXME: crush location is hardcoded for now */
	const char *fmt = "{ \"prefix\": \"osd crush create-or-move\", \
		             \"id\": %d,  \
			     \"weight\": %s, \
			     \"args\": [\"host=%s\", \"root=default\"] }";

	int ret = ceph_monc_send_command_and_wait(monc, fmt, osd_id, weight,
						  utsname()->nodename);

	return ret;
}
EXPORT_SYMBOL(ceph_monc_osd_to_crush_add);

int ceph_monc_osd_boot(struct ceph_mon_client *monc, int osd_id,
		       struct ceph_fsid *osd_fsid)
{
	struct ceph_osd_boot *cmd, osd_boot_cmd = {
		.monhdr = {
			.have_version    = cpu_to_le64(monc->monmap->epoch),
			.session_mon     = cpu_to_le16(-1),
			.session_mon_tid = 0,
		},
		.sb = {
			.struct_version = {
				.struct_v      = 9,
				.struct_compat = 5,
				.struct_len    = cpu_to_le32(
					sizeof(osd_boot_cmd.sb) -
					sizeof(osd_boot_cmd.sb.struct_version))
			},
			.cluster_fsid          = monc->monmap->fsid,
			.whoami                = cpu_to_le32(osd_id),
			.osd_fsid              = *osd_fsid,
		},
	};
	const size_t max_sz = 512;

	struct ceph_mon_generic_request *req;
	void *p, *end;

	/* XXX */
	struct ceph_entity_addr hb_back_addr = {
		.in_addr.ss_family = AF_INET
	};
	struct ceph_entity_addr hb_front_addr = {
		.in_addr.ss_family = AF_INET
	};
	struct ceph_entity_addr cluster_addr = {
		.in_addr.ss_family = AF_INET
	};
	int ret = -ENOMEM;

	req = alloc_generic_request(monc, GFP_NOIO);
	if (!req)
		goto out;

	req->request = ceph_msg_new(CEPH_MSG_OSD_BOOT, max_sz,
				    GFP_NOIO, true);
	if (!req->request)
		goto out;

	cmd = req->request->front.iov_base;
	memset(cmd, 0, max_sz);
	*cmd = osd_boot_cmd;

	p = cmd + 1;
	end = p + req->request->front_alloc_len - sizeof(*cmd);

	if (CEPH_HAVE_FEATURE(monc->con.peer_features, SERVER_NAUTILUS)) {
		req->request->hdr.version        = cpu_to_le16(7);
		req->request->hdr.compat_version = cpu_to_le16(7);

	} else {
		/* Compat path */
		req->request->hdr.version        = cpu_to_le16(6);
		req->request->hdr.compat_version = cpu_to_le16(6);
	}

	ceph_encode_single_entity_addrvec(&p, end, &hb_back_addr,
					  monc->con.peer_features);
	ceph_encode_single_entity_addrvec(&p, end, &cluster_addr,
					  monc->con.peer_features);
	/* boot_epoch */
	ceph_encode_32_safe(&p, end, monc->monmap->epoch, bad);
	ceph_encode_single_entity_addrvec(&p, end, &hb_front_addr,
					  monc->con.peer_features);
	/* metadata map which size is 0  */
	ceph_encode_32_safe(&p, end, 0, bad);
	/* osd_features */
	ceph_encode_64_safe(&p, end, CEPH_FEATURES_ALL, bad);

	mutex_lock(&monc->mutex);
	set_tid_generic_request(req);
	send_generic_request(monc, req);
	mutex_unlock(&monc->mutex);
	ret = 0;
out:
	put_generic_request(req);
	return ret;

bad:
	WARN(1, "Small buffer size?\n");
	put_generic_request(req);
	ret = -EINVAL;
	goto out;
}
EXPORT_SYMBOL(ceph_monc_osd_boot);

int ceph_monc_osd_mark_me_down(struct ceph_mon_client *monc, int osd_id)
{
	struct ceph_osd_mark_me_down *cmd, osd_mark_me_down_cmd = {
		.monhdr = {
			.have_version    = cpu_to_le64(monc->monmap->epoch),
			.session_mon     = cpu_to_le16(-1),
			.session_mon_tid = 0,
		},
		.fsid = monc->monmap->fsid,
	};

	struct ceph_mon_generic_request *req;
	const size_t max_sz = 256;
	void *p, *end;
	int ret;

	if (monc->hunting)
		/*
		 * Check a variable even without a lock, just leave
		 * the function immediately if not connected.
		 */
		return -ENOTCONN;

	ret = -ENOMEM;
	req = alloc_generic_request(monc, GFP_NOIO);
	if (!req)
		return ret;

	req->request = ceph_msg_new(CEPH_MSG_OSD_MARK_ME_DOWN, max_sz,
				    GFP_NOIO, true);
	if (!req->request)
		goto out;

	cmd = req->request->front.iov_base;
	memset(cmd, 0, max_sz);
	*cmd = osd_mark_me_down_cmd;

	p = cmd + 1;
	end = p + req->request->front_alloc_len - sizeof(*cmd);

	if (CEPH_HAVE_FEATURE(monc->con.peer_features, SERVER_NAUTILUS)) {
		int ret;

		req->request->hdr.version        = cpu_to_le16(3);
		req->request->hdr.compat_version = cpu_to_le16(3);

		ceph_encode_32_safe(&p, end, osd_id, bad);
		ret = ceph_encode_single_entity_addrvec(&p, end,
						ceph_client_addr(monc->client),
						monc->con.peer_features);
		if (ret)
			goto bad;

	} else  {
		/* Compat path */

		req->request->hdr.version        = cpu_to_le16(2);
		req->request->hdr.compat_version = cpu_to_le16(2);

		/* XXX */
		BUG();

#if 0
		encode(entity_inst_t(entity_name_t::OSD(target_osd),
				     target_addrs.legacy_addr()),
		       payload, features);
#endif
	}

	ceph_encode_32_safe(&p, end, monc->monmap->epoch, bad);
	/* Request ack */
	ceph_encode_8_safe(&p, end, 1, bad);

	mutex_lock(&monc->mutex);
	reinit_completion(&monc->m_osd_marked_down_comp);
	set_tid_generic_request(req);
	send_generic_request(monc, req);
	mutex_unlock(&monc->mutex);

	ret = wait_for_completion_interruptible(&monc->m_osd_marked_down_comp);
out:
	put_generic_request(req);
	return ret;

bad:
	WARN(1, "Small buffer size?\n");
	put_generic_request(req);
	ret = -EINVAL;
	goto out;
}
EXPORT_SYMBOL(ceph_monc_osd_mark_me_down);

static int ceph_monc_osd_send_beacon(struct ceph_mon_client *monc)
{
	struct ceph_osd_beacon *cmd, osd_beacon_cmd = {
		.monhdr = {
			.have_version    = cpu_to_le64(monc->monmap->epoch),
			.session_mon     = cpu_to_le16(-1),
			.session_mon_tid = 0,
		},
		.min_last_epoch_clean = cpu_to_le32(monc->monmap->epoch),
	};
	struct ceph_mon_generic_request *req;
	int ret = -ENOMEM;

	req = alloc_generic_request(monc, GFP_NOIO);
	if (!req)
		goto out;

	req->request = ceph_msg_new(CEPH_MSG_OSD_BEACON, sizeof(*cmd),
				    GFP_NOIO, true);
	if (!req->request)
		goto out;

	cmd = req->request->front.iov_base;
	*cmd = osd_beacon_cmd;

	mutex_lock(&monc->mutex);
	set_tid_generic_request(req);
	send_generic_request(monc, req);
	mutex_unlock(&monc->mutex);
	ret = 0;
out:
	put_generic_request(req);
	return ret;
}

/*
 * Resend pending generic requests.
 */
static void __resend_generic_request(struct ceph_mon_client *monc)
{
	struct ceph_mon_generic_request *req;
	struct rb_node *p;

	for (p = rb_first(&monc->generic_request_tree); p; p = rb_next(p)) {
		req = rb_entry(p, struct ceph_mon_generic_request, node);
		ceph_msg_revoke(req->request);
		ceph_msg_revoke_incoming(req->reply);
		ceph_con_send(&monc->con, ceph_msg_get(req->request));
	}
}

/*
 * Delayed work.  If we haven't mounted yet, retry.  Otherwise,
 * renew/retry subscription as needed (in case it is timing out, or we
 * got an ENOMEM).  And keep the monitor connection alive.
 */
static void delayed_work(struct work_struct *work)
{
	struct ceph_mon_client *monc =
		container_of(work, struct ceph_mon_client, delayed_work.work);

	dout("monc delayed_work\n");
	mutex_lock(&monc->mutex);
	if (monc->hunting) {
		dout("%s continuing hunt\n", __func__);
		reopen_session(monc);
	} else {
		int is_auth = ceph_auth_is_authenticated(monc->auth);
		if (ceph_con_keepalive_expired(&monc->con,
					       CEPH_MONC_PING_TIMEOUT)) {
			dout("monc keepalive timeout\n");
			is_auth = 0;
			reopen_session(monc);
		}

		if (!monc->hunting) {
			ceph_con_keepalive(&monc->con);
			__validate_auth(monc);
			un_backoff(monc);
		}

		if (is_auth &&
		    !(monc->con.peer_features & CEPH_FEATURE_MON_STATEFUL_SUB)) {
			unsigned long now = jiffies;

			dout("%s renew subs? now %lu renew after %lu\n",
			     __func__, now, monc->sub_renew_after);
			if (time_after_eq(now, monc->sub_renew_after))
				__send_subscribe(monc);
		}
	}
	__schedule_delayed(monc);
	mutex_unlock(&monc->mutex);
}

/*
 * Send beacon to monitors saying we are alive and healthy.
 */
static void send_beacon_work(struct work_struct *work)
{
	struct ceph_mon_client *monc;
	int ret;

	monc = container_of(work, typeof(*monc), beacon_work.work);
	dout("monc send_beacon_work\n");

	ret = ceph_monc_osd_send_beacon(monc);
	if (unlikely(ret))
		pr_err("ceph_monc_osd_send_beacon: failed %d\n", ret);

	/* Rearm work, it's ok here to rearm without locks */
	__schedule_beacon_send(monc);
}

/*
 * On startup, we build a temporary monmap populated with the IPs
 * provided by mount(2).
 */
static int build_initial_monmap(struct ceph_mon_client *monc)
{
	struct ceph_options *opt = monc->client->options;
	struct ceph_entity_addr *mon_addr = opt->mon_addr;
	int num_mon = opt->num_mon;
	int i;

	/* build initial monmap */
	monc->monmap = kzalloc(struct_size(monc->monmap, mon_inst, num_mon),
			       GFP_KERNEL);
	if (!monc->monmap)
		return -ENOMEM;
	for (i = 0; i < num_mon; i++) {
		monc->monmap->mon_inst[i].addr = mon_addr[i];
		monc->monmap->mon_inst[i].addr.nonce = 0;
		monc->monmap->mon_inst[i].name.type =
			CEPH_ENTITY_TYPE_MON;
		monc->monmap->mon_inst[i].name.num = cpu_to_le64(i);
	}
	monc->monmap->num_mon = num_mon;
	return 0;
}

int ceph_monc_init(struct ceph_mon_client *monc, struct ceph_client *cl)
{
	int err = 0;

	dout("init\n");
	memset(monc, 0, sizeof(*monc));
	monc->client = cl;
	monc->monmap = NULL;
	mutex_init(&monc->mutex);

	err = build_initial_monmap(monc);
	if (err)
		goto out;

	/* connection */
	/* authentication */
	monc->auth = ceph_auth_init(cl->options->name,
				    cl->options->key);
	if (IS_ERR(monc->auth)) {
		err = PTR_ERR(monc->auth);
		goto out_monmap;
	}
	monc->auth->want_keys =
		CEPH_ENTITY_TYPE_AUTH | CEPH_ENTITY_TYPE_MON |
		CEPH_ENTITY_TYPE_OSD | CEPH_ENTITY_TYPE_MDS;

	/* msgs */
	err = -ENOMEM;
	monc->m_subscribe_ack = ceph_msg_new(CEPH_MSG_MON_SUBSCRIBE_ACK,
				     sizeof(struct ceph_mon_subscribe_ack),
				     GFP_KERNEL, true);
	if (!monc->m_subscribe_ack)
		goto out_auth;

	monc->m_subscribe = ceph_msg_new(CEPH_MSG_MON_SUBSCRIBE, 128,
					 GFP_KERNEL, true);
	if (!monc->m_subscribe)
		goto out_subscribe_ack;

	monc->m_auth_reply = ceph_msg_new(CEPH_MSG_AUTH_REPLY, 4096,
					  GFP_KERNEL, true);
	if (!monc->m_auth_reply)
		goto out_subscribe;

	monc->m_auth = ceph_msg_new(CEPH_MSG_AUTH, 4096, GFP_KERNEL, true);
	monc->pending_auth = 0;
	if (!monc->m_auth)
		goto out_auth_reply;

	ceph_con_init(&monc->con, monc, &mon_con_ops,
		      &monc->client->msgr);

	monc->cur_mon = -1;
	monc->had_a_connection = false;
	monc->hunt_mult = 1;

	init_completion(&monc->m_osd_marked_down_comp);
	INIT_DELAYED_WORK(&monc->delayed_work, delayed_work);
	INIT_DELAYED_WORK(&monc->beacon_work, send_beacon_work);
	monc->generic_request_tree = RB_ROOT;
	monc->last_tid = 0;

	monc->fs_cluster_id = CEPH_FS_CLUSTER_ID_NONE;

	return 0;

out_auth_reply:
	ceph_msg_put(monc->m_auth_reply);
out_subscribe:
	ceph_msg_put(monc->m_subscribe);
out_subscribe_ack:
	ceph_msg_put(monc->m_subscribe_ack);
out_auth:
	ceph_auth_destroy(monc->auth);
out_monmap:
	kfree(monc->monmap);
out:
	return err;
}
EXPORT_SYMBOL(ceph_monc_init);

void ceph_monc_stop(struct ceph_mon_client *monc)
{
	dout("stop\n");
	cancel_delayed_work_sync(&monc->delayed_work);
	cancel_delayed_work_sync(&monc->beacon_work);

	mutex_lock(&monc->mutex);
	__close_session(monc);
	monc->cur_mon = -1;
	mutex_unlock(&monc->mutex);

	/*
	 * flush msgr queue before we destroy ourselves to ensure that:
	 *  - any work that references our embedded con is finished.
	 *  - any osd_client or other work that may reference an authorizer
	 *    finishes before we shut down the auth subsystem.
	 */
	ceph_msgr_flush();

	ceph_auth_destroy(monc->auth);

	WARN_ON(!RB_EMPTY_ROOT(&monc->generic_request_tree));

	ceph_msg_put(monc->m_auth);
	ceph_msg_put(monc->m_auth_reply);
	ceph_msg_put(monc->m_subscribe);
	ceph_msg_put(monc->m_subscribe_ack);

	kfree(monc->monmap);
}
EXPORT_SYMBOL(ceph_monc_stop);

static void finish_hunting(struct ceph_mon_client *monc)
{
	if (monc->hunting) {
		dout("%s found mon%d\n", __func__, monc->cur_mon);
		monc->hunting = false;
		monc->had_a_connection = true;
		un_backoff(monc);
		__schedule_delayed(monc);
	}
}

static void handle_auth_reply(struct ceph_mon_client *monc,
			      struct ceph_msg *msg)
{
	int ret;
	int was_auth = 0;

	mutex_lock(&monc->mutex);
	was_auth = ceph_auth_is_authenticated(monc->auth);
	monc->pending_auth = 0;
	ret = ceph_handle_auth_reply(monc->auth, msg->front.iov_base,
				     msg->front.iov_len,
				     monc->m_auth->front.iov_base,
				     monc->m_auth->front_alloc_len);
	if (ret > 0) {
		__send_prepared_auth_request(monc, ret);
		goto out;
	}

	finish_hunting(monc);

	if (ret < 0) {
		monc->client->auth_err = ret;
	} else if (!was_auth && ceph_auth_is_authenticated(monc->auth)) {
		struct ceph_messenger *msgr = &monc->client->msgr;

		dout("authenticated, starting session\n");

		if (msgr->inst.name.type == CEPH_ENTITY_TYPE_CLIENT)
			msgr->inst.name.num =
					cpu_to_le64(monc->auth->global_id);

		__send_subscribe(monc);
		__resend_generic_request(monc);

		pr_info("mon%d %s session established\n", monc->cur_mon,
			ceph_pr_addr(&monc->con.peer_addr));
	}

out:
	mutex_unlock(&monc->mutex);
	if (monc->client->auth_err < 0)
		wake_up_all(&monc->client->auth_wq);
}

static int __validate_auth(struct ceph_mon_client *monc)
{
	int ret;

	if (monc->pending_auth)
		return 0;

	ret = ceph_build_auth(monc->auth, monc->m_auth->front.iov_base,
			      monc->m_auth->front_alloc_len);
	if (ret <= 0)
		return ret; /* either an error, or no need to authenticate */
	__send_prepared_auth_request(monc, ret);
	return 0;
}

int ceph_monc_validate_auth(struct ceph_mon_client *monc)
{
	int ret;

	mutex_lock(&monc->mutex);
	ret = __validate_auth(monc);
	mutex_unlock(&monc->mutex);
	return ret;
}
EXPORT_SYMBOL(ceph_monc_validate_auth);

/*
 * handle incoming message
 */
static void dispatch(struct ceph_connection *con, struct ceph_msg *msg)
{
	struct ceph_mon_client *monc = con->private;
	int type = le16_to_cpu(msg->hdr.type);

	switch (type) {
	case CEPH_MSG_AUTH_REPLY:
		handle_auth_reply(monc, msg);
		break;

	case CEPH_MSG_MON_SUBSCRIBE_ACK:
		handle_subscribe_ack(monc, msg);
		break;

	case CEPH_MSG_STATFS_REPLY:
		handle_statfs_reply(monc, msg);
		break;

	case CEPH_MSG_MON_GET_VERSION_REPLY:
		handle_get_version_reply(monc, msg);
		break;

	case CEPH_MSG_MON_COMMAND_ACK:
		handle_command_ack(monc, msg);
		break;

	case CEPH_MSG_MON_MAP:
		ceph_monc_handle_map(monc, msg);
		break;

	case CEPH_MSG_OSD_MAP:
		ceph_osdc_handle_map(&monc->client->osdc, msg);
		break;

	default:
		/* can the chained handler handle it? */
		if (monc->client->extra_mon_dispatch &&
		    monc->client->extra_mon_dispatch(monc->client, msg) == 0)
			break;

		pr_err("received unknown message type %d %s\n", type,
		       ceph_msg_type_name(type));
	}
	ceph_msg_put(msg);
}

static void mon_complete_osd_marked_down(struct ceph_mon_client *monc)
{
	mutex_lock(&monc->mutex);
	complete_all(&monc->m_osd_marked_down_comp);
	mutex_unlock(&monc->mutex);
}

/*
 * Allocate memory for incoming message
 */
static struct ceph_msg *mon_alloc_msg(struct ceph_connection *con,
				      struct ceph_msg_header *hdr,
				      int *skip)
{
	struct ceph_mon_client *monc = con->private;
	int type = le16_to_cpu(hdr->type);
	int front_len = le32_to_cpu(hdr->front_len);
	struct ceph_msg *m = NULL;

	*skip = 0;

	switch (type) {
	case CEPH_MSG_MON_SUBSCRIBE_ACK:
		m = ceph_msg_get(monc->m_subscribe_ack);
		break;
	case CEPH_MSG_STATFS_REPLY:
	case CEPH_MSG_MON_COMMAND_ACK:
		return get_generic_reply(con, hdr, skip);
	case CEPH_MSG_OSD_MARK_ME_DOWN:
		*skip = 1;
		mon_complete_osd_marked_down(monc);
		return NULL;
	case CEPH_MSG_AUTH_REPLY:
		m = ceph_msg_get(monc->m_auth_reply);
		break;
	case CEPH_MSG_MON_GET_VERSION_REPLY:
		if (le64_to_cpu(hdr->tid) != 0)
			return get_generic_reply(con, hdr, skip);

		/*
		 * Older OSDs don't set reply tid even if the orignal
		 * request had a non-zero tid.  Work around this weirdness
		 * by allocating a new message.
		 */
		/* fall through */
	case CEPH_MSG_MON_MAP:
	case CEPH_MSG_MDS_MAP:
	case CEPH_MSG_OSD_MAP:
	case CEPH_MSG_FS_MAP_USER:
		m = ceph_msg_new(type, front_len, GFP_NOFS, false);
		if (!m)
			return NULL;	/* ENOMEM--return skip == 0 */
		break;
	}

	if (!m) {
		pr_info("alloc_msg unknown type %d\n", type);
		*skip = 1;
	} else if (front_len > m->front_alloc_len) {
		pr_warn("mon_alloc_msg front %d > prealloc %d (%u#%llu)\n",
			front_len, m->front_alloc_len,
			(unsigned int)con->peer_name.type,
			le64_to_cpu(con->peer_name.num));
		ceph_msg_put(m);
		m = ceph_msg_new(type, front_len, GFP_NOFS, false);
	}

	return m;
}

/*
 * If the monitor connection resets, pick a new monitor and resubmit
 * any pending requests.
 */
static void mon_fault(struct ceph_connection *con)
{
	struct ceph_mon_client *monc = con->private;

	mutex_lock(&monc->mutex);
	dout("%s mon%d\n", __func__, monc->cur_mon);
	if (monc->cur_mon >= 0) {
		if (!monc->hunting) {
			dout("%s hunting for new mon\n", __func__);
			reopen_session(monc);
			__schedule_delayed(monc);
		} else {
			dout("%s already hunting\n", __func__);
		}
	}
	mutex_unlock(&monc->mutex);
}

/*
 * We can ignore refcounting on the connection struct, as all references
 * will come from the messenger workqueue, which is drained prior to
 * mon_client destruction.
 */
static struct ceph_connection *con_get(struct ceph_connection *con)
{
	return con;
}

static void con_put(struct ceph_connection *con)
{
}

static const struct ceph_connection_operations mon_con_ops = {
	.get = con_get,
	.put = con_put,
	.dispatch = dispatch,
	.fault = mon_fault,
	.alloc_msg = mon_alloc_msg,
};
