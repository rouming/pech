// SPDX-License-Identifier: GPL-2.0

#include "ceph/ceph_debug.h"

#include "module.h"
#include "err.h"
#include "slab.h"
#include "getorder.h"

#include "ceph/ceph_features.h"
#include "ceph/libceph.h"
#include "ceph/osd_server.h"
#include "ceph/osd_client.h"
#include "ceph/messenger.h"
#include "ceph/decode.h"
#include "ceph/auth.h"
#include "ceph/osdmap.h"
#include "ceph/transaction.h"
#include "ceph/memstore.h"
#include "ceph/objclass/class_loader.h"

static const struct ceph_connection_operations osds_con_ops;

/* XXX Probably need to be unified with ceph_osd_request */
struct ceph_msg_osd_op {
	u64                    tid;    /* unique for this peer */
	u64                    features;
	u32                    epoch;
	struct ceph_spg        spg;
	u32                    flags;
	int                    attempts;
	struct timespec64      mtime;
	unsigned int	       num_ops;
	struct ceph_osd_req_op ops[CEPH_OSD_MAX_OPS];
	struct ceph_object_locator
			       oloc;
	struct ceph_hobject_id hoid;
	unsigned int           num_snaps;
	u64                    snap_seq;
	u64                    *snaps;
};

struct ceph_osds_pg {
	struct rb_node         node;     /* node of ->pgs */
	struct ceph_store_coll *coll;
	struct ceph_spg        spg;
	struct rb_root         objs_info;/* all objects info structures */
	struct rb_root         repops;   /* all repops waiting for ACKs */
	u64                    next_tid;
};

struct ceph_osds_obj_info {
	struct rb_node         node;    /* node of ->objs_info */
	struct ceph_hobject_id hoid;    /* object hoid */
	bool                   exists;  /* does object really exists */
	size_t                 size;    /* size of an object */
	struct timespec64      mtime;   /* modification time of an object */
};

struct ceph_osds_msg {
	struct ceph_msg        msg;  /* should be the first in the struct */
	struct work_struct     work;
	struct ceph_msg_osd_op req;
	struct ceph_osds_pg    *pg;
	struct ceph_osds_obj_info
			       *obj_info;

	int                    nr_acks; /* number of ACKs awaited for */
	struct ceph_transaction txn;

	struct ceph_osd_req_op *ops_arr[CEPH_OSD_MAX_OPS]; /* additional ops */
	struct ceph_osd_req_op **ops;
	int                    max_ops;
	int                    nr_ops;
};

struct ceph_osds_repop_msg {
	struct ceph_msg        msg;       /* should be the first in the struct */
	struct ceph_osds_msg   *orig_msg; /* original request */
	struct rb_node         node;      /* node of ->repops */
	u64                    tid;
};

struct ceph_osds_con {
	struct ceph_connection con;
	union {
		struct rb_node   node;  /* node of ->osds_cons */
		struct list_head entry; /* entry of ->accepted_cons */
	};
	struct kref            ref;
	struct ceph_entity_addr addr;
};

struct ceph_osd_server {
	struct ceph_options    *opt;
	struct ceph_client     *client;
	int                    osd;
	struct ceph_cls_loader class_loader;
	struct ceph_store      *store;
	struct list_head       accepted_cons; /* accepted connections */
	struct rb_root         pgs;           /* all pgs */
	struct rb_root         osds_cons;     /* connected osds */
	struct workqueue_struct
			       *dispatch_wq;
	struct kmem_cache      *msg_cache;
	struct kmem_cache      *repop_msg_cache;
};

static int ceph_entity_addr_compare(struct ceph_entity_addr *a_,
				    struct ceph_entity_addr *b_)
{
	struct sockaddr_storage a = a_->in_addr;
	struct sockaddr_storage b = b_->in_addr;
	struct sockaddr_in *a4 = (struct sockaddr_in *)&a;
	struct sockaddr_in *b4 = (struct sockaddr_in *)&b;
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&a;
	struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)&b;

	int res;

	if (a.ss_family != b.ss_family)
		return a.ss_family - b.ss_family;

	switch (a.ss_family) {
	case AF_INET:
		if ((res = memcmp(&a4->sin_addr, &b4->sin_addr,
				  sizeof(a4->sin_addr))))
			return res;
		if (a4->sin_port != b4->sin_port)
			return a4->sin_port - b4->sin_port;

		return 0;

	case AF_INET6:
		if ((res = memcmp(&a6->sin6_addr, &b6->sin6_addr,
				  sizeof(a6->sin6_addr))))
			return res;
		if (a6->sin6_port != b6->sin6_port)
			return a6->sin6_port - b6->sin6_port;

		return 0;

	default:
		WARN_ON(0);
		return memcmp(&a, &b, sizeof(a));
	}
}


/* Define RB functions for collection lookup and insert by spg */
DEFINE_RB_FUNCS2(pg, struct ceph_osds_pg, spg,
		 ceph_spg_compare, RB_BYPTR, struct ceph_spg *,
		 node);

/* Define RB functions for object infos lookup and insert by hoid */
DEFINE_RB_FUNCS2(obj_info, struct ceph_osds_obj_info, hoid,
		 ceph_hoid_compare, RB_BYPTR, struct ceph_hobject_id *,
		 node);

/* Define RB functions for osds connections lookup and insert by addr */
DEFINE_RB_FUNCS2(osds_con, struct ceph_osds_con, addr,
		 ceph_entity_addr_compare, RB_BYPTR, struct ceph_entity_addr *,
		 node);

/* Define RB functions for repops lookup and insert by tid */
DEFINE_RB_FUNCS(repop, struct ceph_osds_repop_msg, tid, node);

static int handle_osd_op(struct ceph_osds_msg *osds_msg,
			 struct ceph_osd_req_op *op);

static inline struct ceph_osd_server *con_to_osds(struct ceph_connection *con)
{
	struct ceph_client *client =
		container_of(con->msgr, typeof(*client), msgr);

	return client->private;
}

static inline struct ceph_osd_client *con_to_osdc(struct ceph_connection *con)
{
	struct ceph_client *client =
		container_of(con->msgr, typeof(*client), msgr);

	return &client->osdc;
}

static int alloc_bvec(struct ceph_bvec_iter *it, size_t data_len)
{
	struct bio_vec *bvec;
	struct page *page;
	unsigned order;

	/*
	 * Allocate the whole chunk at once.  Not acceptable for
	 * kernel side, for sure, because order can be too high,
	 * but for now is fine.
	 */
	order = get_order(data_len);
	page = alloc_pages(GFP_KERNEL, order);
	if (!page)
		return -ENOMEM;

	bvec = kmalloc(sizeof(*bvec), GFP_KERNEL);
	if (!bvec) {
		__free_pages(page, order);
		return -ENOMEM;
	}
	*bvec = (struct bio_vec) {
		.bv_page = page,
		.bv_len  = 1 << order << PAGE_SHIFT,
	};
	*it = (struct ceph_bvec_iter) {
		.bvecs = bvec,
		.iter = { .bi_size = data_len },
	};

	return 0;
}

static struct ceph_osd_req_op *alloc_osd_req_op(struct ceph_osds_msg *m)
{
	struct ceph_osd_req_op *op;

	if (unlikely(m->nr_ops == m->max_ops)) {
		struct ceph_osd_req_op **ops;
		int sz = m->max_ops << 1;
		bool fixed_arr;

		fixed_arr = (m->ops == m->ops_arr);
		ops = (fixed_arr ? NULL : m->ops);
		ops = krealloc(ops, sz * sizeof(*ops), GFP_KERNEL);
		if (!ops)
			return NULL;

		if (unlikely(fixed_arr))
			memcpy(ops, m->ops_arr, sizeof(m->ops_arr));

		m->ops = ops;
		m->max_ops = sz;
	}

	op = kmalloc(sizeof(*op), GFP_KERNEL);
	if (unlikely(!op))
		return NULL;

	ceph_msg_data_init(&op->indata);
	m->ops[m->nr_ops++] = op;

	return op;
}

static void free_osd_req_ops(struct ceph_osds_msg *m)
{
	struct ceph_osd_req_op *op;
	int i;

	for (i = 0; i < m->nr_ops; i++) {
		op = m->ops[i];
		ceph_msg_data_release(&op->indata);
		kfree(op);
	}
	if (m->ops != m->ops_arr)
		kfree(m->ops);
}

static int ceph_get_or_create_pg(struct ceph_connection *con,
				 struct ceph_osds_msg *m)
{
	struct ceph_osd_client *osdc = con_to_osdc(con);
	struct ceph_osd_server *osds = con_to_osds(con);
	unsigned long _1s = msecs_to_jiffies(1000);
	struct ceph_store_coll *coll;
	struct ceph_osds_pg *pg;

	int ret, waits = 60;

	/* Check we are up-to-date */
again:
	ret = ceph_wait_for_osdmap(osdc->client, m->req.epoch, _1s);
	if (unlikely(ret)) {
		if (ret == -ETIMEDOUT && waits--)
			goto again;
		pr_err("%s: wait for osd map failed, ret=%d\n",
		       __func__, ret);
		return -EAGAIN;
	}

	pg = lookup_pg(&osds->pgs, &m->req.spg);
	if (likely(pg))
		goto out;

	coll = ceph_store_open_collection(osds->store, &m->req.spg);
	if (unlikely(IS_ERR(coll))) {
		struct ceph_transaction txn;

		coll = ceph_store_create_collection(osds->store, &m->req.spg);
		if (unlikely(IS_ERR(coll)))
			return PTR_ERR(coll);

		ceph_transaction_init(&txn);

		ret = ceph_transaction_mkcoll(&txn, &m->req.spg);
		if (unlikely(ret))
			goto deinit_txn;

		/*
		 * Execute transaction immediately. Do not replicate it,
		 * each replica takes the same path.
		 */

		ret = ceph_store_execute_transaction(osds->store, &txn);
		if (unlikely(ret))
			goto deinit_txn;

deinit_txn:
		ceph_transaction_deinit(&txn);
		if (unlikely(ret))
			return ret;
	}

	pg = kzalloc(sizeof(*pg), GFP_KERNEL);
	if (unlikely(!pg))
		return -ENOMEM;

	/* TODO: PG structure is not bound to the store, only in cache */

	pg->objs_info = RB_ROOT;
	pg->repops = RB_ROOT;
	RB_CLEAR_NODE(&pg->node);
	pg->spg = m->req.spg;
	pg->coll = coll;
	insert_pg(&osds->pgs, pg);

out:
	m->pg = pg;

	return 0;
}

static void ceph_get_obj_info(struct ceph_osds_msg *m)
{
	struct ceph_osds_pg *pg = m->pg;

	m->obj_info = lookup_obj_info(&pg->objs_info, &m->req.hoid);
};

static int ceph_recreate_obj_info(struct ceph_osds_msg *m)
{
	struct ceph_osds_obj_info *obj_info = m->obj_info;
	struct ceph_osds_pg *pg = m->pg;

	if (likely(obj_info))
		goto mark_as_existing;

	obj_info = lookup_obj_info(&pg->objs_info, &m->req.hoid);
	if (likely(obj_info))
		goto cache_obj_info;

	obj_info = kzalloc(sizeof(*obj_info), GFP_KERNEL);
	if (unlikely(!obj_info))
		return -ENOMEM;

	/* TODO: obj_info structure is not bound to the store, only in cache */

	RB_CLEAR_NODE(&obj_info->node);
	ceph_hoid_init(&obj_info->hoid);
	ceph_hoid_copy(&obj_info->hoid, &m->req.hoid);
	insert_obj_info(&pg->objs_info, obj_info);

cache_obj_info:
	m->obj_info = obj_info;
mark_as_existing:
	if (!obj_info->exists) {
		int ret;

		ret = ceph_transaction_touch(&m->txn, &m->req.spg,
					     &m->req.hoid);
		if (unlikely(ret))
			return ret;

		obj_info->size = 0;
		memset(&obj_info->mtime, 0, sizeof(obj_info->mtime));
	}
	obj_info->exists = true;

	return 0;
}

static int osds_accept_con(struct ceph_connection *con)
{
	struct ceph_osd_server *osds = con_to_osds(con);
	struct ceph_osds_con *osds_con;

	osds_con = container_of(con, typeof(*osds_con), con);
	list_add_tail(&osds_con->entry, &osds->accepted_cons);

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
	struct ceph_osd_server *osds;

	osds_con = container_of(ref, typeof(*osds_con), ref);

	osds = con_to_osds(&osds_con->con);
	if (ceph_con_is_client(&osds_con->con))
		erase_osds_con(&osds->osds_cons, osds_con);
	else
		list_del(&osds_con->entry);
	kfree(osds_con);
}

static void osds_con_put(struct ceph_connection *con)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(con, typeof(*osds_con), con);
	kref_put(&osds_con->ref, osds_free_con);
}

static int decode_hoid(void **p, void *end, struct ceph_hobject_id *hoid)
{
	struct ceph_string *str;
	u8 struct_v;
	u32 struct_len;
	int ret, strlen;

	ret = ceph_start_decoding(p, end, 4, "hobject_t", &struct_v,
				  &struct_len);
	if (ret)
		return ret;

	if (struct_v < 4) {
		pr_err("got struct_v %d < 4 of hobject_t\n", struct_v);
		goto e_inval;
	}

	ceph_decode_32_safe(p, end, strlen, e_inval);
	if (strlen) {
		ceph_decode_need(p, end, strlen, e_inval);
		str = ceph_find_or_create_string(*p, strlen);
		*p += strlen;
		if (!str)
			goto e_inval;
	} else {
		str = NULL;
	}
	hoid->key = str;

	ceph_decode_32_safe(p, end, strlen, e_inval);
	if (strlen) {
		ceph_decode_need(p, end, strlen, e_inval);
		ret = ceph_oid_aprintf(&hoid->oid, GFP_NOIO,
				       "%.*s", strlen, *p);
		*p += strlen;
		if (ret)
			goto e_inval;
	}

	ceph_decode_64_safe(p, end, hoid->snapid, e_inval);
	ceph_decode_32_safe(p, end, hoid->hash, e_inval);
	ceph_decode_8_safe(p, end, hoid->is_max, e_inval);

	ceph_decode_32_safe(p, end, strlen, e_inval);
	if (strlen) {
		ceph_decode_need(p, end, strlen, e_inval);
		str = ceph_find_or_create_string(*p, strlen);
		*p += strlen;
		if (!str)
			goto e_inval;
	} else {
		str = NULL;
	}
	hoid->nspace = str;

	ceph_decode_64_safe(p, end, hoid->pool, e_inval);

	ceph_hoid_build_hash_cache(hoid);
	return 0;

e_inval:
	return -EINVAL;
}

static int hoid_encoding_size(const struct ceph_hobject_id *hoid)
{
	return 8 + 4 + 1 + 8 + /* snapid, hash, is_max, pool */
	       4 + ceph_string_len(hoid->key) + 4 + hoid->oid.name_len +
	       4 + ceph_string_len(hoid->nspace);
}

static void encode_hoid(void **p, void *end, const struct ceph_hobject_id *hoid)
{
	ceph_start_encoding(p, 4, 3, hoid_encoding_size(hoid));
	ceph_encode_string(p, end, ceph_string_ptr(hoid->key),
			   ceph_string_len(hoid->key));
	ceph_encode_string(p, end, hoid->oid.name, hoid->oid.name_len);
	ceph_encode_64(p, hoid->snapid);
	ceph_encode_32(p, hoid->hash);
	ceph_encode_8(p, hoid->is_max);
	ceph_encode_string(p, end, ceph_string_ptr(hoid->nspace),
			   ceph_string_len(hoid->nspace));
	ceph_encode_64(p, hoid->pool);
}

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

static int spg_encoding_size(void)
{
	return 1 + 1 + 4 +     /* encoding block */
	       1 + 8 + 4 + 4 + /* pgid */
	       1;              /* shard */
}

static void encode_spg(void **p, void *end, const struct ceph_spg *spgid)
{
	ceph_start_encoding(p, 1, 1, CEPH_PGID_ENCODING_LEN + 1);
	encode_pgid(p, end, &spgid->pgid);
	ceph_encode_8(p, spgid->shard);
}

static int decode_spg(void **p, void *end, struct ceph_spg *spg)
{
	void *beg;
	u32 struct_len = 0;
	u8 struct_v = 0;
	int ret;

	ret = ceph_start_decoding(p, end, 1, "pgid", &struct_v, &struct_len);
	beg = *p;
	if (!ret)
		ret = ceph_decode_pgid(p, end, &spg->pgid);
	if (!ret)
		ceph_decode_8_safe(p, end, spg->shard, bad);

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

/*
 * XXX Unify with the same function from osd_client, with one
 * XXX exception: here we are replying, thus using ->outdata_len
 * XXX not ->indata_len
 */
static u32 osd_req_encode_op(struct ceph_osd_op *dst,
			     struct ceph_osd_req_op *src)
{
	memset(dst, 0, sizeof(*dst));

	switch (src->op) {
	case CEPH_OSD_OP_STAT:
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_SYNC_READ:
	case CEPH_OSD_OP_SPARSE_READ:
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
	case CEPH_OSD_OP_GETXATTR:
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
	case CEPH_OSD_OP_OMAPGETVALS:
	case CEPH_OSD_OP_OMAPGETVALSBYKEYS:
	case CEPH_OSD_OP_OMAPSETVALS:
	case CEPH_OSD_OP_OMAPGETKEYS:
		break;
	default:
		pr_err("%s: unsupported osd opcode 0x%x '%s'\n", __func__,
		       src->op, ceph_osd_op_name(src->op));
		WARN_ON(1);

		return 0;
	}

	dst->op = cpu_to_le16(src->op);
	dst->flags = cpu_to_le32(src->flags);
	dst->payload_len = cpu_to_le32(src->outdata_len);

	return src->outdata_len;
}

static struct ceph_msg *
create_osd_op_reply(struct ceph_msg_osd_op *req,
		    int result, u32 epoch, int acktype)
{
	struct ceph_eversion bad_replay_version;
	struct ceph_eversion replay_version;
	struct ceph_msg *msg;
	u64 user_version;
	u8 do_redirect;
	u64 flags;
	size_t msg_size;
	u32 data_len;
	void *p, *end;
	int ret, i, n_items;

	/* XXX Default 0 value for some reply members */
	memset(&bad_replay_version, 0, sizeof(bad_replay_version));
	memset(&replay_version, 0, sizeof(replay_version));
	user_version = 0;
	do_redirect = 0;

	flags  = req->flags;
	flags &= ~(CEPH_OSD_FLAG_ONDISK|CEPH_OSD_FLAG_ONNVRAM|CEPH_OSD_FLAG_ACK);
	flags |= acktype;

	msg_size = 0;
	msg_size += 4 + req->hoid.oid.name_len; /* oid */
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

	/* Count number of items for reply */
	for (n_items = 0, i = 0; i < req->num_ops; i++) {
		struct ceph_osd_req_op *op = &req->ops[i];

		if (op->outdata_len)
			n_items++;
	}
	msg = ceph_msg_new2(CEPH_MSG_OSD_OPREPLY, msg_size,
			    n_items, GFP_KERNEL, false);
	if (!msg)
		return NULL;

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	/* Difference between 8 and 7 is in last trace member encoding */
	msg->hdr.version = cpu_to_le16(7);
	msg->hdr.tid = cpu_to_le64(req->tid);

	ceph_encode_string_safe(&p, end, req->hoid.oid.name,
				req->hoid.oid.name_len, bad);

	ret = encode_pgid(&p, end, &req->spg.pgid);
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

	data_len = 0;
	for (i = 0; i < req->num_ops; i++) {
		struct ceph_osd_req_op *op = &req->ops[i];
		struct ceph_osd_op *raw_op = p;

		data_len += osd_req_encode_op(raw_op, op);
		p += sizeof(struct ceph_osd_op);

		if (op->outdata) {
			BUG_ON(!op->outdata_len);
			ceph_msg_data_add(msg, op->outdata);
		}
	}
	msg->hdr.data_len = cpu_to_le32(data_len);

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

static struct ceph_msg *
create_osd_repopreply(struct ceph_msg_osd_op *req,
		      int result, u32 epoch, int acktype)
{
	struct ceph_msg *msg;
	u64 flags;
	size_t msg_size;
	void *p, *end;

	flags  = req->flags;
	flags &= ~(CEPH_OSD_FLAG_ONDISK|CEPH_OSD_FLAG_ONNVRAM|CEPH_OSD_FLAG_ACK);
	flags |= acktype;

	msg_size = 0;

	msg_size += spg_encoding_size();
	msg_size += 4; /* epoch */
	msg_size += 4; /* flags */
	msg_size += 4; /* result */

	/* TODO: add more reply fields */

	msg = ceph_msg_new2(CEPH_MSG_OSD_REPOPREPLY, msg_size,
			    0, GFP_KERNEL, false);
	if (!msg)
		return NULL;

	msg->hdr.version = cpu_to_le16(1);
	msg->hdr.tid = cpu_to_le64(req->tid);

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	encode_spg(&p, end, &req->spg);
	ceph_encode_32(&p, req->epoch);
	ceph_encode_32(&p, req->flags);
	ceph_encode_32(&p, result);

	return msg;
}

static void free_repop_msg(struct ceph_msg *msg)
{
	struct ceph_osds_repop_msg *osds_rep;
	struct ceph_osds_pg *pg;

	/* Message itself starts at the beginning of the struct */
	BUILD_BUG_ON(offsetof(typeof(*osds_rep), msg) != 0);
	osds_rep = container_of(msg, typeof(*osds_rep), msg);
	pg = osds_rep->orig_msg->pg;
	ceph_msg_put(&osds_rep->orig_msg->msg);
	if (!RB_EMPTY_NODE(&osds_rep->node))
		erase_repop(&pg->repops, osds_rep);
}

static void init_msg_osd_op(struct ceph_msg_osd_op *req)
{
	ceph_oloc_init(&req->oloc);
	ceph_hoid_init(&req->hoid);
	req->snaps = NULL;
}

static void deinit_msg_osd_op(struct ceph_msg_osd_op *req)
{
	ceph_oloc_destroy(&req->oloc);
	ceph_hoid_destroy(&req->hoid);
	kfree(req->snaps);
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
	dst->outdata = NULL;
	dst->outdata_len = 0;

	switch (dst->op) {
	case CEPH_OSD_OP_STAT:
		dst->raw_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_SYNC_READ:
	case CEPH_OSD_OP_SPARSE_READ:
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
		dst->extent.osd_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_CALL:
		dst->cls.class_len = src->cls.class_len;
		dst->cls.method_len = src->cls.method_len;
		dst->cls.indata_len = le32_to_cpu(src->cls.indata_len);
		dst->cls.request_info.type = CEPH_MSG_DATA_NONE;
		dst->cls.request_data.type = CEPH_MSG_DATA_NONE;
		dst->cls.response_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_WATCH:
		dst->watch.cookie = le64_to_cpu(src->watch.cookie);
		dst->watch.op = src->watch.op;
		dst->watch.gen = le32_to_cpu(src->watch.gen);
		break;
	case CEPH_OSD_OP_NOTIFY_ACK:
		dst->notify_ack.request_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_NOTIFY:
		dst->notify.cookie = le64_to_cpu(src->notify.cookie);
		dst->notify.request_data.type = CEPH_MSG_DATA_NONE;
		dst->notify.response_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_LIST_WATCHERS:
		dst->notify.response_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_SETALLOCHINT:
		dst->alloc_hint.expected_object_size =
		    le64_to_cpu(src->alloc_hint.expected_object_size);
		dst->alloc_hint.expected_write_size =
		    le64_to_cpu(src->alloc_hint.expected_write_size);
		break;
	case CEPH_OSD_OP_GETXATTR:
	case CEPH_OSD_OP_SETXATTR:
	case CEPH_OSD_OP_CMPXATTR:
		dst->xattr.name_len = le32_to_cpu(src->xattr.name_len);
		dst->xattr.value_len = le32_to_cpu(src->xattr.value_len);
		dst->xattr.cmp_op = src->xattr.cmp_op;
		dst->xattr.cmp_mode = src->xattr.cmp_mode;
		dst->xattr.osd_data.type = CEPH_MSG_DATA_NONE;
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
		dst->copy_from.osd_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_OMAPGETVALS:
	case CEPH_OSD_OP_OMAPGETVALSBYKEYS:
	case CEPH_OSD_OP_OMAPSETVALS:
	case CEPH_OSD_OP_OMAPGETKEYS:
		break;
	default:
		pr_err("%s: unsupported osd opcode 0x%x '%s'\n", __func__,
		       dst->op, ceph_osd_op_name(dst->op));
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

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	req->tid = le64_to_cpu(msg->hdr.tid);

	ret = decode_spg(&p, end, &req->spg); /* actual spg */
	if (ret)
		goto err;
	ceph_decode_32_safe(&p, end, req->hoid.hash, bad); /* raw hash */
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

	ret = ceph_oloc_decode(&p, end, &req->oloc);
	if (ret)
		goto err;

	ceph_decode_32_safe(&p, end, strlen, bad);
	ceph_decode_need(&p, end, strlen, bad);
	ret = ceph_oid_aprintf(&req->hoid.oid, GFP_KERNEL,
			       "%.*s", strlen, p);
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

	ceph_decode_64_safe(&p, end, req->hoid.snapid, bad); /* snapid */
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

	ceph_hoid_build_hash_cache(&req->hoid);
	req->hoid.pool = req->spg.pgid.pool;
	/* XXX Should be something valid? */
	req->hoid.key = NULL;
	req->hoid.nspace = ceph_get_string(req->oloc.pool_ns);

	return 0;
err:
	return ret;
bad:
	ret = -EINVAL;
	goto err;
}

static size_t transaction_encoding_size(const struct ceph_transaction *txn,
					int *nr_osd_ops)
{
	const struct ceph_transaction_op *txn_op;
	size_t size, hoid_size = 0;
	int i, osd_ops;

	osd_ops = 0;
	for (i = 0; i < txn->nr_ops; i++) {
		txn_op = txn->ops[i];
		osd_ops += (txn_op->type == TXN_OP_OSD);

		hoid_size += 1 + 1 + 4; /* encoding block */
		hoid_size += hoid_encoding_size(&txn_op->hoid);
	}

	size = 0;
	size += 4;               /* nr_ops */
	size += 4 * txn->nr_ops; /* ->type */
	size += spg_encoding_size() * txn->nr_ops;
	size += sizeof(struct ceph_osd_op) * osd_ops;
	size += hoid_size;

	*nr_osd_ops = osd_ops;

	return size;
}

static int transaction_encode(const struct ceph_transaction *txn,
			      void **p, void *end,
			      struct ceph_msg *msg)
{
	const struct ceph_transaction_op *txn_op;
	struct ceph_osd_op raw_op;
	int i;

	ceph_encode_32(p, txn->nr_ops);

	for (i = 0; i < txn->nr_ops; i++) {
		txn_op = txn->ops[i];

		ceph_encode_32(p, txn_op->type);
		encode_spg(p, end, &txn_op->spg);
		encode_hoid(p, end, &txn_op->hoid);

		if (txn_op->type == TXN_OP_OSD) {
			osd_req_encode_op(&raw_op, txn_op->op);
			ceph_encode_copy(p, &raw_op, sizeof(raw_op));
			ceph_msg_data_add_nested_cursor(msg,
					&txn_op->op->incur);
		}
	}
	msg->hdr.data_len = cpu_to_le32(msg->data_length);

	return 0;
}

static int transaction_decode(void **p, void *end,
			      const struct ceph_msg *msg,
			      struct ceph_msg_osd_op *req,
			      struct ceph_transaction *txn)
{
	struct ceph_msg_data_cursor in_cur;
	int ret, i, nr_ops;

	ceph_decode_32_safe(p, end, nr_ops, bad);

	/* Expect empty request */
	BUG_ON(req->num_ops);

	if (WARN_ON(nr_ops > ARRAY_SIZE(req->ops)))
		/* Do not want to allocate anything, reuse ops from req */
		return -EINVAL;

	/* Init iterator for input data */
	ceph_msg_data_cursor_init(&in_cur, msg->data, WRITE,
				  msg->data_length);

	for (i = 0; i < nr_ops; i++) {
		struct ceph_hobject_id hoid;
		struct ceph_spg spg;
		int type;

		ceph_hoid_init(&hoid);

		ceph_decode_32_safe(p, end, type, bad);
		ret = decode_spg(p, end, &spg);
		if (unlikely(ret))
			goto err;

		ret = decode_hoid(p, end, &hoid);
		if (unlikely(ret))
			goto err;

		if (type == TXN_OP_OSD) {
			struct ceph_osd_req_op *op;

			op = &req->ops[req->num_ops++];

			ret = osd_req_decode_op(p, end, op);
			if (unlikely(ret))
				goto err;

			/* Cache cursor and advance on indata_len */
			op->incur = in_cur;

			ret = ceph_transaction_add_osd_op(txn, &spg,
							  &hoid, op);

			if (op->indata_len)
				ceph_msg_data_cursor_advance(&in_cur,
							op->indata_len);
		} else if (type == TXN_OP_TOUCH) {
			ret = ceph_transaction_touch(txn, &spg,
						     &hoid);
		} else if (type == TXN_OP_MKCOLL) {
			ret = ceph_transaction_mkcoll(txn, &spg);
		} else {
			pr_err("%s: unknown transaction type %d\n",
			       __func__, type);
			ret = -EINVAL;
		}
		if (unlikely(ret))
			goto err;
	}

	return 0;

bad:
	ret = -EINVAL;
err:
	return ret;
}

static struct ceph_osds_repop_msg *
create_osd_repop(struct ceph_osds_msg *m, u64 tid, u32 epoch, int acktype)
{
	struct ceph_osd_server *osds = con_to_osds(m->msg.con);
	struct ceph_msg_osd_op *req = &m->req;

	struct ceph_osds_repop_msg *osds_rep;
	struct ceph_msg *msg;
	int ret, nr_osd_ops;
	size_t msg_size;
	void *p, *end;

	msg_size = 0;

	msg_size += spg_encoding_size();
	msg_size += 4; /* epoch */
	msg_size += 4; /* flags */
	msg_size += transaction_encoding_size(&m->txn, &nr_osd_ops);

	msg = ceph_msg_new3(osds->repop_msg_cache, CEPH_MSG_OSD_REPOP,
			    msg_size, nr_osd_ops, GFP_KERNEL, false);
	if (unlikely(!msg))
		return NULL;

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	encode_spg(&p, end, &req->spg);
	ceph_encode_32(&p, req->epoch);
	ceph_encode_32(&p, req->flags);

	ret = transaction_encode(&m->txn, &p, end, msg);
	if (unlikely(ret)) {
		pr_err("%s: failed to encode transaction, ret=%d\n",
		       __func__, ret);
		return NULL;
	}

	/* Message itself starts at the beginning of the struct */
	BUILD_BUG_ON(offsetof(typeof(*osds_rep), msg) != 0);
	osds_rep = container_of(msg, typeof(*osds_rep), msg);

	ceph_msg_get(&m->msg);
	osds_rep->orig_msg = m;
	osds_rep->tid = tid;
	RB_CLEAR_NODE(&osds_rep->node);

	msg->free_msg = free_repop_msg;
	msg->hdr.tid = cpu_to_le64(tid);

	return osds_rep;
}

static int ceph_decode_msg_repop(const struct ceph_msg *msg,
				 struct ceph_msg_osd_op *req,
				 struct ceph_transaction *txn)
{
	void *p, *end;
	int ret;

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	req->tid = le64_to_cpu(msg->hdr.tid);

	ret = decode_spg(&p, end, &req->spg); /* actual spg */
	if (ret)
		goto bad;

	ceph_decode_32_safe(&p, end, req->epoch, bad);
	ceph_decode_32_safe(&p, end, req->flags, bad);

	return transaction_decode(&p, end, msg, req, txn);
bad:
	return -EINVAL;
}

static int ceph_decode_msg_repopreply(const struct ceph_msg *msg,
				      struct ceph_msg_osd_op *req)
{
	void *p, *end;
	int ret, result;

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	req->tid = le64_to_cpu(msg->hdr.tid);

	ret = decode_spg(&p, end, &req->spg); /* actual spg */
	if (ret)
		goto err;

	ceph_decode_32_safe(&p, end, req->epoch, bad);
	ceph_decode_32_safe(&p, end, req->flags, bad);
	ceph_decode_32_safe(&p, end, result, bad);

	/* TODO: use repop result */
	(void)result;

	return 0;
err:
	return ret;
bad:
	ret = -EINVAL;
	goto err;
}

static int handle_osd_op_write(struct ceph_osds_msg *m,
			       struct ceph_osd_req_op *op)
{
	int ret;

	ret = ceph_recreate_obj_info(m);
	if (unlikely(ret))
		return ret;

	m->obj_info->mtime = m->req.mtime;

	if (op->op == CEPH_OSD_OP_WRITEFULL)
		m->obj_info->size = op->extent.length;
	else
		m->obj_info->size =
			max_t(size_t, op->extent.offset + op->extent.length,
			      m->obj_info->size);

	return ceph_transaction_add_osd_op(&m->txn, &m->req.spg,
					   &m->req.hoid, op);
}

static int handle_osd_op_stat(struct ceph_osds_msg *m,
			      struct ceph_osd_req_op *op)
{
	struct ceph_osds_obj_info *obj_info;
	struct ceph_bvec_iter it;
	struct ceph_timespec ts;
	size_t outdata_len;
	void *p;
	int ret;

	/* Find an object */
	obj_info = lookup_obj_info(&m->pg->objs_info, &m->req.hoid);
	if (!obj_info)
		return -ENOENT;

	outdata_len = 8 + sizeof(ts);

	/* Allocate bvec for the read chunk */
	ret = alloc_bvec(&it, outdata_len);
	if (ret)
		return ret;

	/* Setup output length */
	op->outdata_len = outdata_len;
	op->outdata = &op->raw_data;

	/* Give ownership to msg */
	ceph_msg_data_bvecs_init(&op->raw_data, &it, 1, true);

	p = page_address(mp_bvec_iter_page(it.bvecs, it.iter));
	ceph_encode_timespec64(&ts, &obj_info->mtime);
	ceph_encode_64(&p, obj_info->size);
	ceph_encode_copy(&p, &ts, sizeof(ts));

	return 0;
}

struct osds_cls_call_ctx {
	struct ceph_cls_call_ctx ctx;
	struct ceph_osds_msg     *m;
};

/**
 * osds_cls_request_desc() - back call for OSD class, which fills in the
 *                           request description.
 */
static int osds_cls_request_desc(struct ceph_cls_call_ctx *ctx,
				 struct ceph_cls_req_desc *desc)
{
	struct osds_cls_call_ctx *osds_ctx;
	struct ceph_connection *con;
	struct ceph_msg *msg;

	osds_ctx = container_of(ctx, typeof(*osds_ctx), ctx);

	msg = &osds_ctx->m->msg;
	con = msg->con;

	desc->source.name = msg->hdr.src;
	desc->source.addr = con->peer_addr;
	desc->peer_features = con->peer_features;

	return 0;
}

/**
 * From OSD classes we get ceph_osd_op structure, since the archutecture
 * is the same we just copy all members directly.
 */
static int osd_op_to_req_op(const struct ceph_osd_op *src,
			    struct ceph_osd_req_op *dst)
{
	dst->op = src->op;
	dst->flags = src->flags;
	dst->indata_len = src->payload_len;
	dst->outdata = NULL;
	dst->outdata_len = 0;

	switch (dst->op) {
	case CEPH_OSD_OP_STAT:
		dst->raw_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_SYNC_READ:
	case CEPH_OSD_OP_SPARSE_READ:
	case CEPH_OSD_OP_WRITE:
	case CEPH_OSD_OP_WRITEFULL:
	case CEPH_OSD_OP_ZERO:
	case CEPH_OSD_OP_TRUNCATE:
		dst->extent.offset = src->extent.offset;
		dst->extent.length = src->extent.length;
		dst->extent.truncate_size = src->extent.truncate_size;
		dst->extent.truncate_seq = src->extent.truncate_seq;
		dst->extent.osd_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_CALL:
		dst->cls.class_len = src->cls.class_len;
		dst->cls.method_len = src->cls.method_len;
		dst->cls.indata_len = src->cls.indata_len;
		dst->cls.request_info.type = CEPH_MSG_DATA_NONE;
		dst->cls.request_data.type = CEPH_MSG_DATA_NONE;
		dst->cls.response_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_WATCH:
		dst->watch.cookie = src->watch.cookie;
		dst->watch.op = src->watch.op;
		dst->watch.gen = src->watch.gen;
		break;
	case CEPH_OSD_OP_NOTIFY_ACK:
		dst->notify_ack.request_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_NOTIFY:
		dst->notify.cookie = src->notify.cookie;
		dst->notify.request_data.type = CEPH_MSG_DATA_NONE;
		dst->notify.response_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_LIST_WATCHERS:
		dst->notify.response_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_SETALLOCHINT:
		dst->alloc_hint.expected_object_size =
			src->alloc_hint.expected_object_size;
		dst->alloc_hint.expected_write_size =
			src->alloc_hint.expected_write_size;
		break;
	case CEPH_OSD_OP_GETXATTR:
	case CEPH_OSD_OP_SETXATTR:
	case CEPH_OSD_OP_CMPXATTR:
		dst->xattr.name_len = src->xattr.name_len;
		dst->xattr.value_len = src->xattr.value_len;
		dst->xattr.cmp_op = src->xattr.cmp_op;
		dst->xattr.cmp_mode = src->xattr.cmp_mode;
		dst->xattr.osd_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_CREATE:
	case CEPH_OSD_OP_DELETE:
		break;
	case CEPH_OSD_OP_COPY_FROM2:
		dst->copy_from.snapid = src->copy_from.snapid;
		dst->copy_from.src_version =
			src->copy_from.src_version;
		dst->copy_from.flags = src->copy_from.flags;
		dst->copy_from.src_fadvise_flags =
			src->copy_from.src_fadvise_flags;
		dst->copy_from.osd_data.type = CEPH_MSG_DATA_NONE;
		break;
	case CEPH_OSD_OP_OMAPGETVALS:
	case CEPH_OSD_OP_OMAPGETVALSBYKEYS:
	case CEPH_OSD_OP_OMAPSETVALS:
	case CEPH_OSD_OP_OMAPGETKEYS:
		break;
	default:
		pr_err("%s: unsupported osd opcode 0x%x: %s\n", __func__,
		       dst->op, ceph_osd_op_name(dst->op));
		WARN_ON(1);

		return -EINVAL;
	}

	return 0;
}

struct ceph_msg_data_kvec {
	struct ceph_msg_data data;
	struct ceph_kvec     vec;
	struct kvec          kvec[];
};

static void ceph_msg_data_kvec_release(struct ceph_kvec *kvec)
{
	struct ceph_msg_data_kvec *vec_data;

	vec_data = container_of(kvec, typeof(*vec_data), vec);
	ceph_msg_data_release(&vec_data->data);
	kfree(vec_data);
}

/**
 * Convert ceph_msg_data to kvec, because ceph_pech_proxy expects
 * ceph_kvec to be filled in.
 */
static struct ceph_msg_data_kvec *
alloc_msg_data_kvec(struct ceph_msg_data *data)
{
	struct ceph_msg_data_kvec *vec_data;
	unsigned int nr_segs, size, i;

	if (data->type == CEPH_MSG_DATA_BVECS)
		nr_segs = data->num_bvecs;
	else if (data->type == CEPH_MSG_DATA_PAGELIST)
		nr_segs = PAGE_ALIGN(data->pagelist->length) >> PAGE_SHIFT;
	else
		BUG();

	size  = sizeof(*vec_data);
	size += sizeof(*vec_data->kvec) * nr_segs;
	vec_data = kmalloc(size, GFP_KERNEL);
	if (!vec_data)
		return NULL;

	/* Take ownership */
	vec_data->data = *data;
	vec_data->vec.kvec    = vec_data->kvec;
	vec_data->vec.release = ceph_msg_data_kvec_release;
	vec_data->vec.length  = ceph_msg_data_length(data);
	vec_data->vec.nr_segs = nr_segs;
	vec_data->vec.refs    = 1;

	if (data->type == CEPH_MSG_DATA_BVECS) {
		for (i = 0; i < nr_segs; i++) {
			struct bio_vec *bvec = &data->bvec_pos.bvecs[i];
			struct kvec *kvec = &vec_data->kvec[i];

			kvec->iov_base = page_address(bvec->bv_page) +
				bvec->bv_offset;
			kvec->iov_len = bvec->bv_len;
		}
	} else if (data->type == CEPH_MSG_DATA_PAGELIST) {
		struct ceph_pagelist *pl = data->pagelist;
		struct page *page;

		i = 0;
		list_for_each_entry(page, &pl->head, lru) {
			struct kvec *kvec;

			BUG_ON(i == nr_segs);

			kvec = &vec_data->kvec[i++];
			kvec->iov_base = page_address(page);
			kvec->iov_len = PAGE_SIZE;
		}
	} else {
		BUG();
	}

	return vec_data;
}

/**
 * osds_cls_execute_op() - back call for OSD class, which execute another
 *                         operation.
 */
static int osds_cls_execute_op(struct ceph_cls_call_ctx *ctx,
			       struct ceph_osd_op *raw_op,
			       struct ceph_kvec *in,
			       struct ceph_kvec **out)
{
	struct osds_cls_call_ctx *osds_ctx;
	struct ceph_osd_req_op *op;
	int ret;

	osds_ctx = container_of(ctx, typeof(*osds_ctx), ctx);

	op = alloc_osd_req_op(osds_ctx->m);
	if (!op)
		return -ENOMEM;

	/* Fill in osd request op */
	ret = osd_op_to_req_op(raw_op, op);
	if (ret)
		return ret;

	if (WARN_ON(op->op == CEPH_OSD_OP_CALL))
		/* Avoid recursion */
		return -EINVAL;

	/* Take ownership, kvec will be put when message is destroyed */
	ceph_kvec_get(in);

	/* Init msg data with input kvec */
	ceph_msg_data_kvec_init(&op->indata, in);

	/* Init iterator for input data */
	ceph_msg_data_cursor_init(&op->incur, &op->indata,
				  WRITE, in->length);

	ret = handle_osd_op(osds_ctx->m, op);
	if (ret)
		return ret;

	if (op->outdata) {
		struct ceph_msg_data_kvec *vec_data;

		vec_data = alloc_msg_data_kvec(op->outdata);
		if (!vec_data) {
			ceph_msg_data_release(op->outdata);
			return -ENOMEM;
		}
		*out = &vec_data->vec;
	}

	return 0;
}

static struct ceph_cls_callback_ops cls_callback_ops = {
	.execute_op   = osds_cls_execute_op,
	.describe_req = osds_cls_request_desc,
};

static int handle_osd_op_call(struct ceph_osds_msg *m,
			      struct ceph_osd_req_op *op)
{
	struct ceph_osd_server *osds = con_to_osds(m->msg.con);
	struct ceph_msg_data_cursor *in_cur = &op->incur;
	struct osds_cls_call_ctx osds_ctx;
	struct ceph_kvec *out = NULL;
	char cname[16], mname[128];
	void *ptr, *indata;
	int ret;

	if (!op->cls.class_len || !op->cls.method_len)
		return -EINVAL;

	if (op->cls.class_len > sizeof(cname) - 1) {
		pr_warn("class name is long: %d\n", op->cls.class_len);
		return -EINVAL;
	}
	if (op->cls.method_len > sizeof(mname) - 1) {
		pr_warn("method name is long: %d\n", op->cls.method_len);
		return -EINVAL;
	}

	if (op->cls.class_len + op->cls.method_len +
	    op->cls.indata_len > m->msg.data_length)
		return -EINVAL;

	BUG_ON(in_cur->iter.nr_segs != 1);

	if (iter_is_iovec(&in_cur->iter))
		ptr = in_cur->iter.iov->iov_base;
	else if (iov_iter_is_kvec(&in_cur->iter))
		ptr = in_cur->iter.kvec->iov_base;
	else if (iov_iter_is_bvec(&in_cur->iter))
		ptr = page_address(in_cur->iter.bvec->bv_page);
	else
		BUG();

	ptr += in_cur->iter.iov_offset;

	memcpy(cname, ptr, op->cls.class_len);
	memcpy(mname, ptr + op->cls.class_len, op->cls.method_len);
	cname[op->cls.class_len] = '\0';
	mname[op->cls.method_len] = '\0';
	indata = ptr + op->cls.class_len + op->cls.method_len;

	ceph_msg_data_cursor_advance(in_cur, op->cls.class_len +
				     op->cls.method_len + op->cls.indata_len);

	osds_ctx = (struct osds_cls_call_ctx) {
		.ctx = {
			.ops    = &cls_callback_ops,
			.in     = indata,
			.in_len = op->cls.indata_len,
			.out    = &out
		},
		.m = m,
	};
	ret = ceph_cls_method_call(&osds->class_loader, cname, mname,
				   &osds_ctx.ctx);
	if (ret)
		return ret;

	if (out) {
		BUG_ON(!out->length);

		/* Setup output length */
		op->outdata_len = out->length;
		op->outdata = &op->raw_data;

		/* Give ownership to msg */
		ceph_msg_data_kvec_init(&op->raw_data, out);
	}

	return 0;
}

static int handle_osd_op_omapsetvals(struct ceph_osds_msg *m,
				     struct ceph_osd_req_op *op)
{
	int ret;

	ret = ceph_recreate_obj_info(m);
	if (unlikely(ret))
		return ret;

	return ceph_transaction_add_osd_op(&m->txn, &m->req.spg,
					   &m->req.hoid, op);
}

static int handle_osd_op_setxattr(struct ceph_osds_msg *m,
				  struct ceph_osd_req_op *op)
{
	int ret;

	ret = ceph_recreate_obj_info(m);
	if (unlikely(ret))
		return ret;

	return ceph_transaction_add_osd_op(&m->txn, &m->req.spg,
					   &m->req.hoid, op);
}

static int handle_osd_op_create(struct ceph_osds_msg *m,
				struct ceph_osd_req_op *op)
{
	if (m->obj_info && m->obj_info->exists &&
	    (op->flags & CEPH_OSD_OP_FLAG_EXCL))
		return -EEXIST;

	return ceph_recreate_obj_info(m);
}

static int handle_osd_op(struct ceph_osds_msg *m,
			 struct ceph_osd_req_op *op)
{
	struct ceph_osd_server *osds = con_to_osds(m->msg.con);
	int ret;

	switch (op->op) {

	/* Mutation ops, through transaction */

	case CEPH_OSD_OP_WRITE:
	case CEPH_OSD_OP_WRITEFULL:
		ret = handle_osd_op_write(m, op);
		break;
	case CEPH_OSD_OP_OMAPSETVALS:
		ret = handle_osd_op_omapsetvals(m, op);
		break;
	case CEPH_OSD_OP_SETXATTR:
		ret = handle_osd_op_setxattr(m, op);
		break;
	case CEPH_OSD_OP_CREATE:
		ret = handle_osd_op_create(m, op);
		break;

	/* Read ops, immediate execution */

	case CEPH_OSD_OP_STAT:
		ret = handle_osd_op_stat(m, op);
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_SYNC_READ:
	case CEPH_OSD_OP_SPARSE_READ:
	case CEPH_OSD_OP_OMAPGETVALS:
	case CEPH_OSD_OP_OMAPGETVALSBYKEYS:
	case CEPH_OSD_OP_OMAPGETKEYS:
	case CEPH_OSD_OP_GETXATTR:
		ret = ceph_store_execute_ro_osd_op(osds->store, m->pg->coll,
						   &m->req.hoid, op);
		break;

	/* Other ops */

	case CEPH_OSD_OP_CALL:
		ret = handle_osd_op_call(m, op);
		break;
	case CEPH_OSD_OP_WATCH:
	case CEPH_OSD_OP_LIST_WATCHERS:
	case CEPH_OSD_OP_SETALLOCHINT:
		/* FIXME: pretend we support these commands */
		ret = 0;
		break;
	case CEPH_OSD_OP_NOTIFY:
		/* Without that `fio examples/rbd.fio` hangs on exit */
		ret = -EOPNOTSUPP;
		break;
	default:
		pr_err("%s: unknown op type 0x%x '%s'\n", __func__,
		       op->op, ceph_osd_op_name(op->op));
		ret = -EOPNOTSUPP;
		break;
	}
	op->rval = ret;

	return ret;
}

static void create_and_send_reply(struct ceph_connection *con,
				  struct ceph_osds_msg *m, int ret)
{
	struct ceph_osd_client *osdc = con_to_osdc(con);
	struct ceph_msg *reply;

	int type;

	type = le16_to_cpu(m->msg.hdr.type);

	switch (type) {
	case CEPH_MSG_OSD_OP:
		reply = create_osd_op_reply(&m->req, ret, osdc->osdmap->epoch,
			  /* TODO: Not actually clear to me when to set those */
			  CEPH_OSD_FLAG_ACK | CEPH_OSD_FLAG_ONDISK);
		break;
	case CEPH_MSG_OSD_REPOP:
		reply = create_osd_repopreply(&m->req, ret, osdc->osdmap->epoch,
			  /* TODO: Not actually clear to me when to set those */
			  CEPH_OSD_FLAG_ACK | CEPH_OSD_FLAG_ONDISK);
		break;
	default:
		BUG();
	}

	if (unlikely(!reply)) {
		pr_err("%s: con %p, failed to allocate a reply\n",
		       __func__, con);
		return;
	}

	ceph_con_send(con, reply);
}

static struct ceph_osds_con *
lookup_create_osds_con(struct ceph_osd_server *osds, int osd)
{
	struct ceph_osds_con *osds_con;
	struct ceph_entity_addr *addr;

	addr = ceph_osd_addr(osds->client->osdc.osdmap, osd);
	if (!addr) {
		pr_err("%s: incorrect osd %d\n", __func__, osd);
		return NULL;
	}

	osds_con = lookup_osds_con(&osds->osds_cons, addr);
	if (!osds_con) {
		osds_con = kmalloc(sizeof(*osds_con),
				   GFP_KERNEL | __GFP_NOFAIL);
		if (unlikely(!osds_con)) {
			pr_err("%s: no memory\n", __func__);

			return NULL;
		}
		RB_CLEAR_NODE(&osds_con->node);
		kref_init(&osds_con->ref);
		osds_con->addr = *addr;

		ceph_con_init(&osds_con->con, osds_con, &osds_con_ops,
			      &osds->client->msgr);
		insert_osds_con(&osds->osds_cons, osds_con);
		ceph_con_open(&osds_con->con, CEPH_ENTITY_TYPE_OSD, osd, addr);
	}

	return osds_con;
}

static bool i_am_primary(struct ceph_osd_server *osds,
			 struct ceph_osds *acting)
{
	return (osds->osd == acting->primary);
}

static bool i_am_last_in_chain(struct ceph_osd_server *osds,
			       struct ceph_osds *acting)
{
	BUG_ON(!acting->size);
	return (osds->osd == acting->osds[acting->size-1]);
}

static void create_and_send_reply_to(struct ceph_osd_server *osds, int osd,
				     struct ceph_osds_msg *m, int ret)
{
	struct ceph_osds_con *osds_con;

	osds_con = lookup_create_osds_con(osds, osd);
	if (likely(osds_con))
		create_and_send_reply(&osds_con->con, m, ret);
}

static void forward_req_to_all_secondaries(struct ceph_osd_server *osds,
					   struct ceph_osds *acting,
					   struct ceph_osds_msg *m)
{
	struct ceph_osd_client *osdc = con_to_osdc(m->msg.con);
	struct ceph_osds_con *osds_con;
	struct ceph_osds_repop_msg *rep;
	int i, nr, ret;
	u64 tid;

	struct {
		struct ceph_osds_repop_msg *rep;
		struct ceph_connection     *con;
	} msg_arr[16];

	BUG_ON(!i_am_primary(osds, acting));

	/* Array size seems should be big enough for all the cases */
	if (WARN_ON(acting->size > ARRAY_SIZE(msg_arr))) {
		ret = -EINVAL;
		goto reply_with_error;
	}

	for (i = 0, nr = 0; i < acting->size; i++) {
		int osd;

		osd = acting->osds[i];
		if (osd == acting->primary)
			/* Skip ourselves */
			continue;

		osds_con = lookup_create_osds_con(osds, osd);
		if (unlikely(!osds_con)) {
			pr_err("%s: can't create osds_con\n", __func__);
			ret = -ENOMEM;
			goto reply_with_error;
		}

		/* Bump tid up */
		tid = ++m->pg->next_tid;

		rep = create_osd_repop(m, tid, osdc->osdmap->epoch,
			  /* TODO: Not actually clear to me when to set those */
			  CEPH_OSD_FLAG_ACK | CEPH_OSD_FLAG_ONDISK);

		if (unlikely(!rep)) {
			pr_err("%s: failed to allocate a replication msg\n",
			       __func__);
			ret = -ENOMEM;
			goto reply_with_error;
		}

		msg_arr[nr].rep = rep;
		msg_arr[nr].con = &osds_con->con;
		nr++;
	}

	/* All replicated messages are created, ready to fan them out */

	BUG_ON(!nr);
	m->nr_acks = nr;
	ceph_msg_get(&m->msg);

	for (i = 0; i < nr; i++) {
		struct ceph_osds_repop_msg *rep = msg_arr[i].rep;
		struct ceph_connection *con = msg_arr[i].con;

		ceph_msg_get(&rep->msg);
		insert_repop(&m->pg->repops, rep);
		ceph_con_send(con, &rep->msg);
	}

	return;

reply_with_error:
	create_and_send_reply(m->msg.con, m, ret);
}

static void forward_req_to_next(struct ceph_osd_server *osds,
				struct ceph_osds *acting,
				struct ceph_osds_msg *m)
{
	struct ceph_osd_client *osdc = con_to_osdc(m->msg.con);
	struct ceph_osds_con *osds_con = NULL;
	struct ceph_osds_repop_msg *rep;
	bool primary;
	int i, ret;
	u64 tid;

	for (i = 0; i < acting->size; i++) {
		int osd;

		osd = acting->osds[i];
		if (osd != osds->osd)
			continue;

		/* Get the next OSD in round-robin */
		osd = acting->osds[++i % acting->size];
		osds_con = lookup_create_osds_con(osds, osd);
		if (unlikely(!osds_con)) {
			pr_err("%s: can't create osds_con\n", __func__);
			ret = -ENOMEM;
			goto reply_with_error;
		}
		break;
	}
	BUG_ON(!osds_con);

	primary = i_am_primary(osds, acting);
	if (primary) {
		/* Bump tid up */
		tid = ++m->pg->next_tid;
	} else {
		BUG_ON(le16_to_cpu(m->msg.hdr.type) != CEPH_MSG_OSD_REPOP);
		tid = m->req.tid;
	}

	rep = create_osd_repop(m, tid, osdc->osdmap->epoch,
			  /* TODO: Not actually clear to me when to set those */
			  CEPH_OSD_FLAG_ACK | CEPH_OSD_FLAG_ONDISK);

	if (unlikely(!rep)) {
		pr_err("%s: failed to allocate a replication msg\n",
		       __func__);
		ret = -ENOMEM;
		goto reply_with_error;
	}

	if (primary) {
		/* Wait for a single ACK */
		m->nr_acks = 1;
		ceph_msg_get(&m->msg);
		ceph_msg_get(&rep->msg);
		insert_repop(&m->pg->repops, rep);
	}
	ceph_con_send(&osds_con->con, &rep->msg);

	return;

reply_with_error:
	create_and_send_reply(m->msg.con, m, ret);
}

static bool osdmap_acting_osds(struct ceph_connection *con,
			       struct ceph_pg *pgid,
			       struct ceph_osds *acting)
{
	struct ceph_osd_client *osdc = con_to_osdc(con);
	struct ceph_pg_pool_info *pi;
	struct ceph_osds up;

	pi = ceph_pg_pool_by_id(osdc->osdmap, pgid->pool);
	if (!pi)
		return false;

	ceph_pg_to_up_acting_osds(osdc->osdmap, pi, pgid, &up, acting);

	return true;
}

static void replicate_osd_ops(struct ceph_connection *con,
			      struct ceph_osds_msg *m, int ret)
{
	struct ceph_osd_server *osds = con_to_osds(con);
	struct ceph_osds acting;

	int repl_model = osds->client->options->replication;

	if (!m->txn.nr_ops) {
		/* No transaction ops, no replication */
		create_and_send_reply(con, m, ret);
		return;
	}

	if (!osdmap_acting_osds(con, &m->req.spg.pgid, &acting)) {
		pr_err("%s: failed to get acting OSDs\n", __func__);
		create_and_send_reply(con, m, -ENOENT);
		return;
	}

	/* Simply exclude all corner cases when we have < 2 osd in pg */
	if (acting.size < 2)
		repl_model = CEPH_REP_NONE;

	/* Sweet, client does everything on his own */
	if (m->req.flags & CEPH_OSD_FLAG_DONT_REPLICATE)
		repl_model = CEPH_REP_NONE;

	if (unlikely(ret)) {
		/* Error path */

		switch (repl_model) {
		case CEPH_REP_CHAIN:
			if (i_am_primary(osds, &acting))
				create_and_send_reply(con, m, ret);
			else
				/* Chain is broken, reply to primary */
				create_and_send_reply_to(osds, acting.primary,
							 m, ret);
			break;
		case CEPH_REP_PRIMARY_COPY:
		case CEPH_REP_NONE:
			create_and_send_reply(con, m, ret);
			break;
		default:
			BUG();
		}
	} else {
		/* Success path */

		switch (repl_model) {
		case CEPH_REP_NONE:
			create_and_send_reply(con, m, ret);
			break;
		case CEPH_REP_PRIMARY_COPY:
			if (i_am_primary(osds, &acting))
				forward_req_to_all_secondaries(osds,
							&acting, m);
			else
				create_and_send_reply(con, m, ret);
			break;
		case CEPH_REP_CHAIN:
			if (i_am_last_in_chain(osds, &acting))
				create_and_send_reply_to(osds, acting.primary,
							 m, ret);
			else
				forward_req_to_next(osds, &acting, m);
			break;
		default:
			BUG();
		}
	}
}

static void handle_osd_ops(struct ceph_connection *con,
			   struct ceph_osds_msg *m)
{
	struct ceph_osd_server *osds = con_to_osds(con);
	struct ceph_msg_data_cursor in_cur;
	int ret, i;

	/* See osds_alloc_msg(), we gather input in a single data */
	BUG_ON(m->msg.num_data_items > 1);

	ret = ceph_decode_msg_osd_op(&m->msg, &m->req);
	if (unlikely(ret)) {
		pr_err("%s: con %p, failed to decode a message, ret=%d\n",
		       __func__, con, ret);
		return;
	}

	/* Get and cache PG for the current message */
	ret = ceph_get_or_create_pg(con, m);
	if (unlikely(ret))
		goto replicate;

	/* Get and cache object info for the current message */
	ceph_get_obj_info(m);

	/* Init iterator for input data, ->data_length can be 0 */
	ceph_msg_data_cursor_init(&in_cur, m->msg.data, WRITE,
				  m->msg.data_length);

	/* Iterate over all operations */
	for (i = 0; i < m->req.num_ops; i++) {
		struct ceph_osd_req_op *op = &m->req.ops[i];

		/* Cache cursor and advance on indata_len */
		op->incur = in_cur;

		/* Make things happen */
		ret = handle_osd_op(m, op);
		if (ret && (op->flags & CEPH_OSD_OP_FLAG_FAILOK) &&
		    ret != -EAGAIN && ret != -EINPROGRESS)
			/* Ignore op error and continue executing */
			ret = 0;

		if (ret)
			break;

		if (op->indata_len)
			ceph_msg_data_cursor_advance(&in_cur, op->indata_len);
	}

	/* Execute accumulated ops in one transaction */
	ceph_store_execute_transaction(osds->store, &m->txn);

replicate:
	replicate_osd_ops(con, m, ret);
}

static void handle_osd_repop(struct ceph_connection *con,
			     struct ceph_osds_msg *m)
{
	struct ceph_osd_server *osds = con_to_osds(con);
	int ret;

	/* See osds_alloc_msg(), we gather input in a single data */
	BUG_ON(m->msg.num_data_items > 1);

	ret = ceph_decode_msg_repop(&m->msg, &m->req, &m->txn);
	if (unlikely(ret)) {
		pr_err("%s: con %p, failed to decode a message, ret=%d\n",
		       __func__, con, ret);
		return;
	}

	/* Get and cache PG for the current message */
	ret = ceph_get_or_create_pg(con, m);
	if (unlikely(ret))
		goto replicate;

	/* Execute accumulated ops in one transaction */
	ceph_store_execute_transaction(osds->store, &m->txn);

replicate:
	replicate_osd_ops(con, m, ret);
}

static void handle_osd_repopreply(struct ceph_connection *con,
				  struct ceph_osds_msg *m)
{
	struct ceph_osds_repop_msg *rep;
	struct ceph_osds_msg *orig_msg;
	u64 tid;
	int ret;

	ret = ceph_decode_msg_repopreply(&m->msg, &m->req);
	if (unlikely(ret)) {
		pr_err("%s: con %p, failed to decode a message, ret=%d\n",
		       __func__, con, ret);
		return;
	}

	/* Get and cache PG for the current message */
	ret = ceph_get_or_create_pg(con, m);
	if (unlikely(ret))
		return;

	tid = le64_to_cpu(m->msg.hdr.tid);
	rep = lookup_repop(&m->pg->repops, tid);
	if (unlikely(!rep)) {
		pr_err("%s: failed to lookup for repop, tid %lld\n",
		       __func__, tid);
		return;
	}

	orig_msg = rep->orig_msg;

	/* Put repop message */
	ceph_msg_put(&rep->msg);

	if (WARN_ON(!orig_msg->nr_acks))
		return;

	if (!--orig_msg->nr_acks) {
		/* Got all ACKs, ready to reply back to the originator */

		/* TODO: accumulate return code from each replica */

		create_and_send_reply(orig_msg->msg.con, orig_msg, 0);
		ceph_msg_put(&orig_msg->msg);
	}
}

static void osds_dispatch(struct ceph_connection *con, struct ceph_msg *msg)
{
	struct ceph_osd_server *osds = con_to_osds(con);
	struct ceph_osds_msg *osds_msg;

	osds_msg = container_of(msg, typeof(*osds_msg), msg);
	queue_work(osds->dispatch_wq, &osds_msg->work);
}

static void osds_dispatch_workfn(struct work_struct *work)
{
	struct ceph_osds_msg *osds_msg;
	struct ceph_msg *msg;
	int type;

	osds_msg = container_of(work, typeof(*osds_msg), work);
	msg = &osds_msg->msg;

	type = le16_to_cpu(msg->hdr.type);

	switch (type) {
	case CEPH_MSG_OSD_OP:
		handle_osd_ops(msg->con, osds_msg);
		break;
	case CEPH_MSG_OSD_REPOP:
		handle_osd_repop(msg->con, osds_msg);
		break;
	case CEPH_MSG_OSD_REPOPREPLY:
		handle_osd_repopreply(msg->con, osds_msg);
		break;
	default:
		pr_err("@@ message type %d, \"%s\"\n", type,
		       ceph_msg_type_name(type));
		break;
	}

	ceph_msg_put(msg);
}

static void init_osds_msg(struct ceph_osds_msg *m)
{
	INIT_WORK(&m->work, osds_dispatch_workfn);
	init_msg_osd_op(&m->req);
	ceph_transaction_init(&m->txn);
	m->ops = m->ops_arr;
	m->max_ops = ARRAY_SIZE(m->ops_arr);
	m->nr_ops = 0;
}

static struct ceph_msg *alloc_msg_with_bvec(struct ceph_osd_server *osds,
					    struct ceph_msg_header *hdr)
{
	int type = le16_to_cpu(hdr->type);
	u32 front_len = le32_to_cpu(hdr->front_len);
	u32 data_len = le32_to_cpu(hdr->data_len);
	struct ceph_osds_msg *osds_msg;
	struct ceph_msg *m;

	m = ceph_msg_new3(osds->msg_cache, type, front_len, 1,
			  GFP_KERNEL, false);
	if (!m)
		return NULL;

	/* Message itself starts at the beginning of the struct */
	BUILD_BUG_ON(offsetof(typeof(*osds_msg), msg) != 0);
	osds_msg = container_of(m, typeof(*osds_msg), msg);
	init_osds_msg(osds_msg);

	if (data_len) {
		struct ceph_bvec_iter it;
		int ret;

		ret = alloc_bvec(&it, data_len);
		if (ret) {
			ceph_msg_put(m);
			return NULL;
		}

		/* Give ownership to msg */
		ceph_msg_data_add_bvecs(m, &it, 1, true);
	}

	return m;
}

static struct ceph_msg *osds_alloc_msg(struct ceph_connection *con,
				       struct ceph_msg_header *hdr,
				       int *skip)
{
	struct ceph_osd_server *osds = con_to_osds(con);
	int type = le16_to_cpu(hdr->type);

	*skip = 0;
	switch (type) {
	case CEPH_MSG_OSD_MAP:
	case CEPH_MSG_OSD_BACKOFF:
	case CEPH_MSG_WATCH_NOTIFY:
	case CEPH_MSG_OSD_OP:
	case CEPH_MSG_OSD_REPOP:
	case CEPH_MSG_OSD_REPOPREPLY:
		return alloc_msg_with_bvec(osds, hdr);
	case CEPH_MSG_PING:
		/* TODO: */
		*skip = 1;
		return NULL;
	case CEPH_MSG_OSD_OPREPLY:
		/* fall through */
	default:
		pr_warn("%s unknown msg type %d '%s', skipping\n", __func__,
			type, ceph_msg_type_name(type));
		*skip = 1;
		return NULL;
	}
}

static void osds_free_msg(struct ceph_msg *msg)

{
	struct ceph_osds_msg *osds_msg;

	/* Message itself starts at the beginning of the struct */
	BUILD_BUG_ON(offsetof(typeof(*osds_msg), msg) != 0);
	osds_msg = container_of(msg, typeof(*osds_msg), msg);

	ceph_transaction_deinit(&osds_msg->txn);
	deinit_msg_osd_op(&osds_msg->req);
	free_osd_req_ops(osds_msg);
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

	osds = kzalloc(sizeof(*osds), GFP_KERNEL);
	if (unlikely(!osds))
		return ERR_PTR(-ENOMEM);

	osds->opt = opt;
	osds->osd = osd;
	osds->pgs = RB_ROOT;
	osds->osds_cons = RB_ROOT;
	INIT_LIST_HEAD(&osds->accepted_cons);
	ceph_cls_init(&osds->class_loader, opt);

	return osds;
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
		    !ceph_osd_is_up(client->osdc.osdmap, osds->osd)) {
			is_down = true;
			break;
		}
		/* Don't flood, relax */
		msleep(100);
	}
	if (is_down)
		pr_notice(">>>> Tear down osd.%d\n", osds->osd);
}

static void destroy_objs_info(struct rb_root *root)
{
	struct ceph_osds_obj_info *obj;

	while ((obj = rb_entry_safe(rb_first(root),
				    typeof(*obj), node))) {
		erase_obj_info(root, obj);
		kfree(obj);
	}
}

static void destroy_pgs(struct ceph_osd_server *osds)
{
	struct ceph_osds_pg *pg;

	while ((pg = rb_entry_safe(rb_first(&osds->pgs),
				   typeof(*pg), node))) {
		destroy_objs_info(&pg->objs_info);
		erase_pg(&osds->pgs, pg);
		kfree(pg);
	}
}

static void destroy_osds_cons(struct ceph_osd_server *osds)
{
	struct ceph_osds_con *osds_con;

	while ((osds_con = rb_entry_safe(rb_first(&osds->osds_cons),
					 typeof(*osds_con), node))) {
		ceph_con_close(&osds_con->con);
		erase_osds_con(&osds->osds_cons, osds_con);
		kfree(osds_con);
	}
}

static void destroy_accepted_cons(struct ceph_osd_server *osds)
{
	struct ceph_osds_con *osds_con, *tmp;

	list_for_each_entry_safe(osds_con, tmp, &osds->accepted_cons, entry) {
		ceph_con_close(&osds_con->con);
		list_del(&osds_con->entry);
		kfree(osds_con);
	}
}

void ceph_destroy_osd_server(struct ceph_osd_server *osds)
{
	if (osds->client) {
		ceph_stop_osd_server(osds);
		destroy_accepted_cons(osds);
		destroy_osds_cons(osds);
		flush_workqueue(osds->dispatch_wq);
		ceph_destroy_client(osds->client);
		ceph_store_destroy(osds->store);
		destroy_pgs(osds);
		ceph_cls_deinit(&osds->class_loader);
		destroy_workqueue(osds->dispatch_wq);
		kmem_cache_destroy(osds->msg_cache);
		kmem_cache_destroy(osds->repop_msg_cache);
	}
	kfree(osds);
}

int ceph_start_osd_server(struct ceph_osd_server *osds)
{
	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	struct ceph_client *client;
	unsigned long started;

	bool is_up;
	int ret;

	client = __ceph_create_client(osds->opt, osds, CEPH_ENTITY_TYPE_OSD,
				      osds->osd, CEPH_FEATURES_SUPPORTED_OSD,
				      CEPH_FEATURES_REQUIRED_OSD);
	if (unlikely(IS_ERR(client)))
		return PTR_ERR(client);

	osds->client = client;

	osds->msg_cache = KMEM_CACHE(ceph_osds_msg, 0);
	osds->repop_msg_cache = KMEM_CACHE(ceph_osds_repop_msg, 0);
	if (unlikely(!osds->msg_cache || !osds->repop_msg_cache)) {
		ret = -ENOMEM;
		goto destroy_client;
	}

	/*
	 * In order to schedule dispatch workfn immediately WQ_HIGHPRI
	 * flag is used, that significantly reduces latency.
	 */
	osds->dispatch_wq = alloc_workqueue("ceph-osds-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (unlikely(!osds->dispatch_wq)) {
		ret = -ENOMEM;
		goto free_cache;
	}

	/* Allocate store */
	osds->store = ceph_memstore_create(client->options);
	if (unlikely(IS_ERR(osds->store))) {
		ret = PTR_ERR(osds->store);
		goto destroy_wq;
	}

	ret = ceph_messenger_start_listen(&client->msgr, &osds_con_ops);
	if (unlikely(ret))
		goto destroy_store;

	pr_notice(">>>> Start listening\n");

	ret = ceph_open_session(client);
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Ceph session opened\n");

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
		/* Don't flood, relax */
		msleep(100);
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
destroy_wq:
	destroy_workqueue(osds->dispatch_wq);
destroy_store:
	ceph_store_destroy(osds->store);
free_cache:
	kmem_cache_destroy(osds->msg_cache);
	kmem_cache_destroy(osds->repop_msg_cache);
destroy_client:
	ceph_destroy_client(osds->client);
	osds->client = NULL;

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
	.free_msg      = osds_free_msg,
};
