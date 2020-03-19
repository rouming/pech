// SPDX-License-Identifier: GPL-2.0

#include "ceph/ceph_debug.h"

#include "module.h"
#include "err.h"
#include "slab.h"

#include "semaphore.h"

#include "ceph/ceph_features.h"
#include "ceph/libceph.h"
#include "ceph/osd_server.h"
#include "ceph/osd_client.h"
#include "ceph/messenger.h"
#include "ceph/decode.h"
#include "ceph/auth.h"
#include "ceph/osdmap.h"

static const struct ceph_connection_operations osds_con_ops;

struct ceph_osds_con {
	struct ceph_connection con;
	struct kref ref;
};

static int osds_accept_con(struct ceph_connection *con)
{
	pr_err("@@ con %p\n", con);

	return 0;
}

static struct ceph_connection *osds_alloc_con(struct ceph_messenger *msgr)
{
	struct ceph_osds_con *osds_con;

	osds_con = kzalloc(sizeof(*osds_con), GFP_KERNEL | __GFP_NOFAIL);
	if (unlikely(!osds_con))
		return NULL;

	kref_init(&osds_con->ref);

	return &osds_con->con;
}

static struct ceph_connection *osds_con_get(struct ceph_connection *con)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(con, typeof(*osds_con), con);
	kref_get(&osds_con->ref);

	return con;
}

static void osds_free_con(struct kref *ref)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(ref, typeof(*osds_con), ref);
	kfree(osds_con);
}

static void osds_con_put(struct ceph_connection *con)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(con, typeof(*osds_con), con);
	kref_put(&osds_con->ref, osds_free_con);
}


/* XXX Probably need to be unified with ceph_osd_request */
struct ceph_msg_osd_op {
	u64                    tid;    /* unique for this peer */
	u64                    features;
	u64                    snapid;
	u32                    epoch;
	struct ceph_spg        spgid;
	struct ceph_pg         pgid;
	u32                    flags;
	int                    attempts;
	struct timespec64      mtime;
	unsigned int	       num_ops;
	struct ceph_osd_req_op ops[CEPH_OSD_MAX_OPS];
	struct ceph_object_locator
			       oloc;
	struct ceph_object_id  oid;
	unsigned int           num_snaps;
	u64                    snap_seq;
	u64                    *snaps;
};

static int encode_pgid(void **p, void *end, const struct ceph_pg *pgid)
{
	ceph_encode_8_safe(p, end, 1, bad);
	ceph_encode_64_safe(p, end, pgid->pool, bad);
	ceph_encode_32_safe(p, end, pgid->seed, bad);
	ceph_encode_32_safe(p, end, -1, bad); /* preferred */

	return 0;

bad:
	return -EINVAL;
}

/* XXX Unify with the same function from osd_client */
static u32 osd_req_encode_op(struct ceph_osd_op *dst,
			     const struct ceph_osd_req_op *src)
{
	switch (src->op) {
	case CEPH_OSD_OP_STAT:
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_WRITE:
	case CEPH_OSD_OP_WRITEFULL:
	case CEPH_OSD_OP_ZERO:
	case CEPH_OSD_OP_TRUNCATE:
		dst->extent.offset = cpu_to_le64(src->extent.offset);
		dst->extent.length = cpu_to_le64(src->extent.length);
		dst->extent.truncate_size =
			cpu_to_le64(src->extent.truncate_size);
		dst->extent.truncate_seq =
			cpu_to_le32(src->extent.truncate_seq);
		break;
	case CEPH_OSD_OP_CALL:
		dst->cls.class_len = src->cls.class_len;
		dst->cls.method_len = src->cls.method_len;
		dst->cls.indata_len = cpu_to_le32(src->cls.indata_len);
		break;
	case CEPH_OSD_OP_WATCH:
		dst->watch.cookie = cpu_to_le64(src->watch.cookie);
		dst->watch.ver = cpu_to_le64(0);
		dst->watch.op = src->watch.op;
		dst->watch.gen = cpu_to_le32(src->watch.gen);
		break;
	case CEPH_OSD_OP_NOTIFY_ACK:
		break;
	case CEPH_OSD_OP_NOTIFY:
		dst->notify.cookie = cpu_to_le64(src->notify.cookie);
		break;
	case CEPH_OSD_OP_LIST_WATCHERS:
		break;
	case CEPH_OSD_OP_SETALLOCHINT:
		dst->alloc_hint.expected_object_size =
		    cpu_to_le64(src->alloc_hint.expected_object_size);
		dst->alloc_hint.expected_write_size =
		    cpu_to_le64(src->alloc_hint.expected_write_size);
		break;
	case CEPH_OSD_OP_SETXATTR:
	case CEPH_OSD_OP_CMPXATTR:
		dst->xattr.name_len = cpu_to_le32(src->xattr.name_len);
		dst->xattr.value_len = cpu_to_le32(src->xattr.value_len);
		dst->xattr.cmp_op = src->xattr.cmp_op;
		dst->xattr.cmp_mode = src->xattr.cmp_mode;
		break;
	case CEPH_OSD_OP_CREATE:
	case CEPH_OSD_OP_DELETE:
		break;
	case CEPH_OSD_OP_COPY_FROM2:
		dst->copy_from.snapid = cpu_to_le64(src->copy_from.snapid);
		dst->copy_from.src_version =
			cpu_to_le64(src->copy_from.src_version);
		dst->copy_from.flags = src->copy_from.flags;
		dst->copy_from.src_fadvise_flags =
			cpu_to_le32(src->copy_from.src_fadvise_flags);
		break;
	default:
		pr_err("unsupported osd opcode %s\n",
			ceph_osd_op_name(src->op));
		WARN_ON(1);

		return 0;
	}

	dst->op = cpu_to_le16(src->op);
	dst->flags = cpu_to_le32(src->flags);
	dst->payload_len = cpu_to_le32(src->indata_len);

	return src->indata_len;
}

static struct ceph_msg *
create_osd_op_reply(const struct ceph_msg_osd_op *req,
		    int result, u32 epoch, int acktype)
{
	struct ceph_eversion bad_replay_version;
	struct ceph_eversion replay_version;
	struct ceph_msg *msg;
	u64 user_version;
	u8 do_redirect;
	u64 flags;
	size_t msg_size;
	void *p, *end;
	int ret, i;

	/* XXX Default 0 value for some reply members */
	memset(&bad_replay_version, 0, sizeof(bad_replay_version));
	memset(&replay_version, 0, sizeof(replay_version));
	user_version = 0;
	do_redirect = 0;

	flags  = req->flags;
	flags &= ~(CEPH_OSD_FLAG_ONDISK|CEPH_OSD_FLAG_ONNVRAM|CEPH_OSD_FLAG_ACK);
	flags |= acktype;

	msg_size = 0;
	msg_size += 4 + req->oid.name_len; /* oid */
	msg_size += 1 + 8 + 4 + 4; /* pgid */
	msg_size += 8; /* flags */
	msg_size += 4; /* result */
	msg_size += sizeof(bad_replay_version);
	msg_size += 4; /* epoch */
	msg_size += 4; /* num_ops */
	msg_size += req->num_ops * sizeof(struct ceph_osd_op);
	msg_size += 4; /* attempts */
	msg_size += req->num_ops * 4; /* op.rval */
	msg_size += sizeof(replay_version);
	msg_size += 8; /* user_version */
	msg_size += 1; /* do_redirect */

	msg = ceph_msg_new2(CEPH_MSG_OSD_OPREPLY, msg_size,
			    0, GFP_KERNEL, false);
	if (!msg)
		return NULL;

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	/* Difference between 8 and 7 is in last trace member encoding */
	msg->hdr.version = cpu_to_le16(7);
	msg->hdr.tid = cpu_to_le64(req->tid);

	ceph_encode_string_safe(&p, end, req->oid.name,
				req->oid.name_len, bad);

	ret = encode_pgid(&p, end, &req->pgid);
	if (ret)
		goto bad;

	ceph_encode_64_safe(&p, end, flags, bad);
	ceph_encode_32_safe(&p, end, result, bad);

	memset(&bad_replay_version, 0, sizeof(bad_replay_version));
	ceph_encode_copy_safe(&p, end, &bad_replay_version,
			      sizeof(bad_replay_version), bad);

	ceph_encode_32_safe(&p, end, epoch, bad);

	ceph_encode_32_safe(&p, end, req->num_ops, bad);
	ceph_encode_need(&p, end, req->num_ops * sizeof(struct ceph_osd_op),
			 bad);
	for (i = 0; i < req->num_ops; i++) {
		struct ceph_osd_op *op = p;

		osd_req_encode_op(op, &req->ops[i]);
		op->payload_len = 0;
		p += sizeof(struct ceph_osd_op);
	}

	ceph_encode_32_safe(&p, end, req->attempts, bad);

	for (i = 0; i < req->num_ops; i++) {
		ceph_encode_32_safe(&p, end, req->ops[i].rval, bad);
	}

	ceph_encode_copy_safe(&p, end, &replay_version,
			      sizeof(replay_version), bad);
	ceph_encode_64_safe(&p, end, user_version, bad);

	ceph_encode_8_safe(&p, end, do_redirect, bad);

        if (do_redirect) {
		/* XXX TODO
		   ceph_redirect_encode(&p, end, redirect, bad);
		*/
		BUG();
	}

	return msg;
bad:
	ceph_msg_put(msg);
	return NULL;
}

static void init_msg_osd_op(struct ceph_msg_osd_op *req)
{
	ceph_oloc_init(&req->oloc);
	ceph_oid_init(&req->oid);
	memset(&req->ops, 0, sizeof(req->ops));
	req->snaps = NULL;
}

static void free_msg_osd_op(struct ceph_msg_osd_op *req)
{
	ceph_oloc_destroy(&req->oloc);
	ceph_oid_destroy(&req->oid);
	kfree(req->snaps);
}

static int decode_spgid(void **p, void *end, struct ceph_spg *spgid)
{
	void *beg;
	u32 struct_len = 0;
	u8 struct_v = 0;
	int ret;

	ret = ceph_start_decoding(p, end, 1, "pgid", &struct_v, &struct_len);
	beg = *p;
	if (!ret)
		ret = ceph_decode_pgid(p, end, &spgid->pgid);
	if (!ret)
		ceph_decode_8_safe(p, end, spgid->shard, bad);

	if (!ret) {
		if (beg + struct_len < *p) {
			pr_warn("%s: corrupted structure, len=%d\n",
				__func__, struct_len);
			goto bad;
		}
		*p = beg + struct_len;
	}

	return ret;
bad:
	return -EINVAL;
}

static struct ceph_string *decode_string(void **p, void *end)
{
	struct ceph_string *str;
	size_t strlen;

	ceph_decode_32_safe(p, end, strlen, bad);
	ceph_decode_need(p, end, strlen, bad);
	str = ceph_find_or_create_string(*p, strlen);
	*p += strlen;
	if (!str)
		return ERR_PTR(-ENOMEM);

	return str;
bad:
	return ERR_PTR(-EINVAL);
}

static int decode_oloc(void **p, void *end, struct ceph_object_locator *oloc)
{
	void *beg;
	u32 struct_len;
	u8 struct_v;
	int ret;

	ret = ceph_start_decoding(p, end, 4, "oloc", &struct_v, &struct_len);
	beg = *p;
	if (ret)
		return ret;
	ceph_decode_64_safe(p, end, oloc->pool, bad);
	ceph_decode_skip_n(p, end, 4, bad); /* preferred */
	ceph_decode_skip_n(p, end, 4, bad); /* key len */
	oloc->pool_ns = decode_string(p, end);
	if (IS_ERR(oloc->pool_ns))
		return PTR_ERR(oloc->pool_ns);

	if (beg + struct_len < *p) {
		pr_warn("%s: corrupted structure, len=%d\n",
			__func__, struct_len);
		goto bad;
	}
	*p = beg + struct_len;

	return 0;
bad:
	return -EINVAL;
}

static int osd_req_decode_op(void **p, void *end, struct ceph_osd_req_op *dst)
{
	const struct ceph_osd_op *src;

	if (!ceph_has_room(p, end, sizeof(*src)))
		return -EINVAL;

	src = *p;
	*p += sizeof(*src);

	dst->op = le16_to_cpu(src->op);
	dst->flags = le32_to_cpu(src->flags);
	dst->indata_len = le32_to_cpu(src->payload_len);

	switch (dst->op) {
	case CEPH_OSD_OP_STAT:
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_WRITE:
	case CEPH_OSD_OP_WRITEFULL:
	case CEPH_OSD_OP_ZERO:
	case CEPH_OSD_OP_TRUNCATE:
		dst->extent.offset = le64_to_cpu(src->extent.offset);
		dst->extent.length = le64_to_cpu(src->extent.length);
		dst->extent.truncate_size =
			le64_to_cpu(src->extent.truncate_size);
		dst->extent.truncate_seq =
			le32_to_cpu(src->extent.truncate_seq);
		break;
	case CEPH_OSD_OP_CALL:
		dst->cls.class_len = src->cls.class_len;
		dst->cls.method_len = src->cls.method_len;
		dst->cls.indata_len = le32_to_cpu(src->cls.indata_len);
		break;
	case CEPH_OSD_OP_WATCH:
		dst->watch.cookie = le64_to_cpu(src->watch.cookie);
		dst->watch.op = src->watch.op;
		dst->watch.gen = le32_to_cpu(src->watch.gen);
		break;
	case CEPH_OSD_OP_NOTIFY_ACK:
		break;
	case CEPH_OSD_OP_NOTIFY:
		dst->notify.cookie = le64_to_cpu(src->notify.cookie);
		break;
	case CEPH_OSD_OP_LIST_WATCHERS:
		break;
	case CEPH_OSD_OP_SETALLOCHINT:
		dst->alloc_hint.expected_object_size =
		    le64_to_cpu(src->alloc_hint.expected_object_size);
		dst->alloc_hint.expected_write_size =
		    le64_to_cpu(src->alloc_hint.expected_write_size);
		break;
	case CEPH_OSD_OP_SETXATTR:
	case CEPH_OSD_OP_CMPXATTR:
		dst->xattr.name_len = le32_to_cpu(src->xattr.name_len);
		dst->xattr.value_len = le32_to_cpu(src->xattr.value_len);
		dst->xattr.cmp_op = src->xattr.cmp_op;
		dst->xattr.cmp_mode = src->xattr.cmp_mode;
		break;
	case CEPH_OSD_OP_CREATE:
	case CEPH_OSD_OP_DELETE:
		break;
	case CEPH_OSD_OP_COPY_FROM2:
		dst->copy_from.snapid = le64_to_cpu(src->copy_from.snapid);
		dst->copy_from.src_version =
			le64_to_cpu(src->copy_from.src_version);
		dst->copy_from.flags = src->copy_from.flags;
		dst->copy_from.src_fadvise_flags =
			le32_to_cpu(src->copy_from.src_fadvise_flags);
		break;
	default:
		pr_err("unsupported osd opcode %s\n",
			ceph_osd_op_name(dst->op));
		WARN_ON(1);

		return -EINVAL;
	}

	return 0;
}

static int ceph_decode_msg_osd_op(const struct ceph_msg *msg,
				  struct ceph_msg_osd_op *req)
{
	struct ceph_timespec mtime;
	void *p, *end, *beg;
	u32 struct_len;
	u8 struct_v;
	int ret, i;
	size_t strlen;

	init_msg_osd_op(req);

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	req->tid = le64_to_cpu(msg->hdr.tid);

	ret = decode_spgid(&p, end, &req->spgid); /* actual spg */
	if (ret)
		goto err;
	ceph_decode_32_safe(&p, end, req->pgid.seed, bad); /* raw hash */
	ceph_decode_32_safe(&p, end, req->epoch, bad);
	ceph_decode_32_safe(&p, end, req->flags, bad);

	ret = ceph_start_decoding(&p, end, 2, "reqid",
				  &struct_v, &struct_len);
	beg = p;
	if (ret)
		goto err;

	ceph_decode_skip_n(&p, end, sizeof(struct ceph_osd_reqid), bad);
	if (beg + struct_len < p) {
		pr_warn("%s: corrupted structure osd_reqid, len=%d\n",
			__func__, struct_len);
		goto bad;
	}
	p = beg + struct_len;

	ceph_decode_skip_n(&p, end, sizeof(struct ceph_blkin_trace_info), bad);

	ceph_decode_skip_n(&p, end, 4, bad); /* client_inc, always 0 */
	ceph_decode_copy_safe(&p, end, &mtime, sizeof(mtime), bad);
	ceph_decode_timespec64(&req->mtime, &mtime);

	ret = decode_oloc(&p, end, &req->oloc);
	if (ret)
		goto err;

	ceph_decode_32_safe(&p, end, strlen, bad);
	ceph_decode_need(&p, end, strlen, bad);
	ret = ceph_oid_aprintf(&req->oid, GFP_KERNEL, "%s", p);
	p += strlen;
	if (ret)
		goto err;

	ceph_decode_16_safe(&p, end, req->num_ops, bad);
	if (req->num_ops > CEPH_OSD_MAX_OPS) {
		pr_err("%s: too big num_ops %d\n",
		       __func__, req->num_ops);
		goto err;
	}
	for (i = 0; i < req->num_ops; i++) {
		ret = osd_req_decode_op(&p, end, &req->ops[i]);
		if (ret)
			goto err;
	}

	ceph_decode_64_safe(&p, end, req->snapid, bad); /* snapid */
	ceph_decode_64_safe(&p, end, req->snap_seq, bad);
	ceph_decode_32_safe(&p, end, req->num_snaps, bad);
	if (req->num_snaps > 1024) {
		pr_err("%s: too big num_snaps %d\n",
		       __func__, req->num_snaps);
		goto err;
	}

	if (req->num_snaps) {
		req->snaps = kmalloc_array(req->num_snaps,
					   sizeof(*req->snaps),
					   GFP_KERNEL);
		if (!req->snaps) {
			ret = -ENOMEM;
			goto err;
		}

		for (i = 0; i < req->num_snaps; i++)
			ceph_decode_64_safe(&p, end, req->snaps[i], bad);
	}

	ceph_decode_32_safe(&p, end, req->attempts, bad);
	ceph_decode_64_safe(&p, end, req->features, bad);

	return 0;
err:
	free_msg_osd_op(req);
	return ret;
bad:
	ret = -EINVAL;
	goto err;
}

static void handle_osd_op(struct ceph_connection *con, struct ceph_msg *msg)
{
	struct ceph_client *client;
	struct ceph_osd_client *osdc;
	struct ceph_msg_osd_op req;
	struct ceph_msg *reply;
	int ret;

	client = container_of(con->msgr, typeof(*client), msgr);
	osdc = &client->osdc;

	ret = ceph_decode_msg_osd_op(msg, &req);
	if (unlikely(ret)) {
		pr_err("%s: con %p, failed to decode a message, ret=%d\n",
		       __func__, con, ret);
		return;
	}

	/* XXX Immediately reply with ACK */
	reply = create_osd_op_reply(&req, 0, osdc->osdmap->epoch,
				CEPH_OSD_FLAG_ACK | CEPH_OSD_FLAG_ONDISK);
	free_msg_osd_op(&req);
	if (unlikely(!reply)) {
		pr_err("%s: con %p, failed to allocate a reply\n",
		       __func__, con);
		return;
	}

	ceph_con_send(con, reply);
}

static void osds_dispatch(struct ceph_connection *con, struct ceph_msg *msg)
{
	int type = le16_to_cpu(msg->hdr.type);

	switch (type) {
	case CEPH_MSG_OSD_OP:
		handle_osd_op(con, msg);
		break;
	default:
		pr_err("@@ message type %d, \"%s\"\n", type,
		       ceph_msg_type_name(type));
		break;
	}

	ceph_msg_put(msg);
}

static struct ceph_msg *alloc_msg_with_page_vector(struct ceph_msg_header *hdr)
{
	struct ceph_msg *m;
	int type = le16_to_cpu(hdr->type);
	u32 front_len = le32_to_cpu(hdr->front_len);
	u32 data_len = le32_to_cpu(hdr->data_len);

	m = ceph_msg_new2(type, front_len, 1, GFP_KERNEL, false);
	if (!m)
		return NULL;

	if (data_len) {
		struct page **pages;

		pages = ceph_alloc_page_vector(calc_pages_for(0, data_len),
					       GFP_NOIO);
		if (IS_ERR(pages)) {
			ceph_msg_put(m);
			return NULL;
		}

		ceph_msg_data_add_pages(m, pages, data_len, 0, true);
	}

	return m;
}

static struct ceph_msg *osds_alloc_msg(struct ceph_connection *con,
				       struct ceph_msg_header *hdr,
				       int *skip)
{
	int type = le16_to_cpu(hdr->type);

	*skip = 0;
	switch (type) {
	case CEPH_MSG_OSD_MAP:
	case CEPH_MSG_OSD_BACKOFF:
	case CEPH_MSG_WATCH_NOTIFY:
	case CEPH_MSG_OSD_OP:
		return alloc_msg_with_page_vector(hdr);
	case CEPH_MSG_OSD_OPREPLY:
		/* fall through */
	default:
		pr_warn("%s unknown msg type %d, skipping\n", __func__,
			type);
		*skip = 1;
		return NULL;
	}
}

static void osds_fault(struct ceph_connection *con)
{
	ceph_con_close(con);
	osds_con_put(con);
}

struct ceph_osd_server *
ceph_create_osd_server(struct ceph_options *opt, int osd)
{
	struct ceph_osd_server *osds;
	struct ceph_client *client;
	int ret;

	osds = kzalloc(sizeof(*osds), GFP_KERNEL);
	if (unlikely(!osds))
		return ERR_PTR(-ENOMEM);

	osds->osd = osd;

	client = __ceph_create_client(opt, osds, CEPH_ENTITY_TYPE_OSD,
				      osd, CEPH_FEATURES_SUPPORTED_OSD,
				      CEPH_FEATURES_REQUIRED_OSD);
	if (unlikely(IS_ERR(client))) {
		ret = PTR_ERR(client);
		goto err;
	}
	osds->client = client;

	return osds;

err:
	kfree(osds);
	return ERR_PTR(ret);
}

static void ceph_stop_osd_server(struct ceph_osd_server *osds)
{
	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	unsigned long started;

	struct ceph_client *client = osds->client;
	bool is_down;
	int ret;

	ret = ceph_monc_osd_mark_me_down(&client->monc, osds->osd);
	if (unlikely(ret && ret != -ETIMEDOUT)) {
		pr_err("mark_me_down: failed %d\n", ret);
		return;
	}

	started = jiffies;
	is_down = false;
	while (!time_after_eq(jiffies, started + _5s)) {
		ret = ceph_wait_for_latest_osdmap(client, _300ms);
		if (unlikely(ret && ret != -ETIMEDOUT)) {
			pr_err("latest_osdmap: failed %d\n", ret);
			break;
		}
		if (!ret &&
		    ceph_osdmap_contains(client->osdc.osdmap, osds->osd,
					 ceph_client_addr(client)) &&
		    !ceph_osd_is_up(client->osdc.osdmap, osds->osd)) {
			is_down = true;
			break;
		}
	}
	if (is_down)
		pr_notice(">>>> Tear down osd.%d\n", osds->osd);
}

void ceph_destroy_osd_server(struct ceph_osd_server *osds)
{
	ceph_stop_osd_server(osds);
	ceph_destroy_client(osds->client);
	kfree(osds);
}

int ceph_start_osd_server(struct ceph_osd_server *osds)
{
	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	unsigned long started;

	struct ceph_client *client = osds->client;
	bool is_up;
	int ret;

	ret = ceph_open_session(client);
	if (unlikely(ret))
		return ret;

	pr_notice(">>>> Ceph session opened\n");

	ret = ceph_messenger_start_listen(&client->msgr, &osds_con_ops);
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Start listening\n");

	ret = ceph_monc_osd_to_crush_add(&client->monc, osds->osd, "0.0010");
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Add osd.%d to crush\n", osds->osd);

	ret = ceph_monc_osd_boot(&client->monc, osds->osd,
				 &client->options->fsid);
	if (unlikely(ret))
		goto err;

	started = jiffies;
	is_up = false;
	while (!time_after_eq(jiffies, started + _5s)) {
		ret = ceph_wait_for_latest_osdmap(client, _300ms);
		if (unlikely(ret && ret != -ETIMEDOUT))
			goto err;

		if (!ret &&
		    ceph_osdmap_contains(client->osdc.osdmap, osds->osd,
					 ceph_client_addr(client)) &&
		    ceph_osd_is_up(client->osdc.osdmap, osds->osd)) {
			is_up = true;
			break;
		}
	}
	if (!is_up) {
		ret = -ETIMEDOUT;
		goto err;
	}

	WARN_ON(!ceph_osd_is_up(client->osdc.osdmap, osds->osd));

	pr_notice(">>>> Boot osd.%d\n", osds->osd);

	return 0;

err:
	ceph_messenger_stop_listen(&client->msgr);

	return ret;
}

static const struct ceph_connection_operations osds_con_ops = {
	.alloc_con     = osds_alloc_con,
	.accept_con    = osds_accept_con,
	.get           = osds_con_get,
	.put           = osds_con_put,
	.dispatch      = osds_dispatch,
	.fault         = osds_fault,
	.alloc_msg     = osds_alloc_msg,
};
