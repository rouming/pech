// SPDX-License-Identifier: GPL-2.0

#include "ceph/ceph_debug.h"

#include "module.h"
#include "err.h"
#include "slab.h"
#include "getorder.h"

#include "semaphore.h"

#include "ceph/ceph_features.h"
#include "ceph/libceph.h"
#include "ceph/osd_server.h"
#include "ceph/osd_client.h"
#include "ceph/messenger.h"
#include "ceph/decode.h"
#include "ceph/auth.h"
#include "ceph/osdmap.h"
#include "ceph/objclass/class_loader.h"

enum {
	OSDS_BLOCK_SHIFT    = 16, /* 64k, must be ^2 */
	OSDS_BLOCK_SIZE     = (1UL << OSDS_BLOCK_SHIFT),
	OSDS_BLOCK_MASK     = (~(OSDS_BLOCK_SIZE-1))
};

static const struct ceph_connection_operations osds_con_ops;

/* XXX Probably need to be unified with ceph_osd_request */
struct ceph_msg_osd_op {
	u64                    tid;    /* unique for this peer */
	u64                    features;
	u32                    epoch;
	struct ceph_spg        spgid;
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
	struct ceph_osds_object
			       *object; /* cached object for OP_CALL */
};

struct ceph_osds_con {
	struct ceph_connection con;
	struct kref ref;
};

struct ceph_osd_server {
	struct ceph_client     *client;
	int                    osd;
	struct ceph_cls_loader class_loader;
	struct rb_root         s_objects;  /* all objects */
};

struct ceph_osds_object {
	struct rb_node         o_node;    /* node of ->s_objects */
	struct ceph_hobject_id o_hoid;
	struct rb_root         o_blocks;  /* all blocks of the object */
	struct rb_root         o_omap;    /* omap of the object */
	struct rb_root         o_xattrs;  /* xattr of the object */
	size_t                 o_size;    /* size of an object */
	struct timespec64      o_mtime;   /* modification time of an object */
};

struct ceph_osds_block {
	struct rb_node         b_node;    /* node of ->o_blocks */
	struct page            *b_page;
	off_t                  b_off;     /* offset inside a whole object */
};

struct ceph_osds_omap_entry {
	struct rb_node         e_node;   /* node of ->o_omap or ->o_xattrs */
	char                   *e_key;
	unsigned int           e_key_len;
	struct ceph_pagelist   *e_val_pl;
};

/**
 * Define RB functions for object lookup and insert by hoid
 */
DEFINE_RB_FUNCS2(object_by_hoid, struct ceph_osds_object, o_hoid,
		 ceph_hoid_compare, RB_BYPTR, struct ceph_hobject_id *,
		 o_node);

/**
 * Define RB functions for object block lookup by offset
 */
DEFINE_RB_FUNCS(object_block_by_off, struct ceph_osds_block, b_off, b_node);

/**
 * Define RB functions for omap lookup by string
 */
DEFINE_RB_FUNCS2(omap_entry, struct ceph_osds_omap_entry, e_key,
		 strcmp, RB_BYVAL, char *, e_node);

static int handle_osd_op(struct ceph_msg *msg, struct ceph_msg_osd_op *req,
			 struct ceph_osd_req_op *op,
			 struct ceph_msg_data_cursor *in_cur);

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

static struct ceph_osds_object *
ceph_lookup_object(struct ceph_osd_server *osds,
		   struct ceph_msg_osd_op *req)
{
	if (!req->object)
		req->object = lookup_object_by_hoid(&osds->s_objects,
						    &req->hoid);
	return req->object;
}

static struct ceph_osds_object *
ceph_create_and_insert_object(struct ceph_osd_server *osds,
			      struct ceph_msg_osd_op *req)
{
	struct ceph_osds_object *obj;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;

	obj->o_size = 0;
	obj->o_blocks = RB_ROOT;
	obj->o_omap = RB_ROOT;
	obj->o_xattrs = RB_ROOT;
	RB_CLEAR_NODE(&obj->o_node);
	ceph_hoid_init(&obj->o_hoid);
	ceph_hoid_copy(&obj->o_hoid, &req->hoid);
	insert_object_by_hoid(&osds->s_objects, obj);

	/* Cache an object */
	req->object = obj;

	return obj;
}

static struct ceph_osds_omap_entry *
ceph_create_and_insert_omap(struct rb_root *root, const char *key)
{
	struct ceph_osds_omap_entry *ome;
	size_t key_len = strlen(key);

	ome = kmalloc(sizeof(*ome), GFP_KERNEL);
	if (!ome)
		return NULL;

	ome->e_key = kstrndup(key, key_len, GFP_KERNEL);
	if (!ome->e_key) {
		kfree(ome);
		return NULL;
	}
	ome->e_key_len = key_len;
	RB_CLEAR_NODE(&ome->e_node);

	ome->e_val_pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!ome->e_val_pl) {
		kfree(ome->e_key);
		kfree(ome);
		return NULL;
	}
	insert_omap_entry(root, ome);

	return ome;
}

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

/*
 * XXX Unify with the same function from osd_client, with one
 * XXX exception: here we are replying, thus using ->outdata_len
 * XXX not ->indata_len
 */
static u32 osd_req_encode_op(struct ceph_osd_op *dst,
			     struct ceph_osd_req_op *src)
{
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

	ret = encode_pgid(&p, end, &req->spgid.pgid);
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

static void init_msg_osd_op(struct ceph_msg_osd_op *req)
{
	ceph_oloc_init(&req->oloc);
	ceph_hoid_init(&req->hoid);
	req->snaps = NULL;
	req->object = NULL;
}

static void deinit_msg_osd_op(struct ceph_msg_osd_op *req)
{
	ceph_oloc_destroy(&req->oloc);
	ceph_hoid_destroy(&req->hoid);
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

	init_msg_osd_op(req);

	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	req->tid = le64_to_cpu(msg->hdr.tid);

	ret = decode_spgid(&p, end, &req->spgid); /* actual spg */
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
	req->hoid.pool = req->spgid.pgid.pool;
	/* XXX Should be something valid? */
	req->hoid.key = NULL;
	req->hoid.nspace = ceph_get_string(req->oloc.pool_ns);

	return 0;
err:
	deinit_msg_osd_op(req);
	return ret;
bad:
	ret = -EINVAL;
	goto err;
}

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

static inline int next_dst(struct ceph_osd_req_op *op,
			   struct ceph_osds_object *obj,
			   struct ceph_osds_block **pblk,
			   off_t dst_off,
			   size_t *dst_len)
{
	struct ceph_osds_block *blk;
	off_t blk_off;

	blk_off = ALIGN_DOWN(dst_off, OSDS_BLOCK_SIZE);
	blk = lookup_object_block_by_off(&obj->o_blocks, blk_off);
	if (!blk) {
		unsigned int order;

		blk = kmalloc(sizeof(*blk), GFP_KERNEL);
		if (!blk)
			return -ENOMEM;

		RB_CLEAR_NODE(&blk->b_node);
		order = OSDS_BLOCK_SHIFT - PAGE_SHIFT;
		blk->b_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
		blk->b_off = blk_off;

		if (!blk->b_page) {
			kfree(blk);
			return -ENOMEM;
		}

		insert_object_block_by_off(&obj->o_blocks, blk);
	}

	*dst_len = OSDS_BLOCK_SIZE - (dst_off & ~OSDS_BLOCK_MASK);
	*pblk = blk;


	return 0;
}

static int handle_osd_op_write(struct ceph_msg *msg,
			       struct ceph_msg_osd_op *req,
			       struct ceph_osd_req_op *op,
			       struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_object *obj;
	struct ceph_osds_block *blk;

	size_t len_write, dst_len;
	off_t dst_off;

	bool modified = false;
	int ret;

	if (!op->extent.length)
		/* Nothing to do */
		return 0;

	if (ceph_test_opt(msg->con->msgr->options, NOOP_WRITE) &&
	    op->extent.length >= 4096)
		/* Write is noop */
		return 0;

	/*
	 * Find or create an object
	 */
	obj = ceph_lookup_object(osds, req);
	if (!obj) {
		obj = ceph_create_and_insert_object(osds, req);
		if (!obj)
			return -ENOMEM;
	}

	/*
	 * Fill in blocks with data of found/created object
	 */
	len_write = op->extent.length;
	dst_off = op->extent.offset;
	blk = NULL;
	dst_len = 0;
	ret = 0;

	while (len_write) {
		size_t len, len2;
		void *dst;

		if (!dst_len) {
			ret = next_dst(op, obj, &blk, dst_off, &dst_len);
			if (ret)
				goto out;
		}

		ceph_msg_data_cursor_next(in_cur);

		len = iov_iter_count(&in_cur->iter);
		len = min(len, dst_len);
		len = min(len, len_write);

		dst = page_address(blk->b_page);
		len2 = copy_from_iter(dst + (dst_off & ~OSDS_BLOCK_MASK),
				      len, &in_cur->iter);
		WARN_ON(len2 != len);

		ceph_msg_data_cursor_advance(in_cur, len);
		len_write -= len;
		dst_len -= len;
		dst_off += len;
		modified = true;
	}
out:
	if (modified) {
		bool truncate = (op->op == CEPH_OSD_OP_WRITEFULL);

		obj->o_mtime = req->mtime;

		/* Extend object size if needed or truncate */
		if (dst_off > obj->o_size || truncate)
			obj->o_size = dst_off;

		/* FIXME: need to free the rest in case of truncate */
	}

	return ret;
}

/**
 * lookup_block_ge() - returns block which offset equal or greater than @off
 */
static struct ceph_osds_block *lookup_block_ge(struct ceph_osds_object *obj,
					       off_t off)
{
	struct rb_node *n = obj->o_blocks.rb_node;
	struct ceph_osds_block *right = NULL;
	int cmp = 0;

	while (n) {
		struct ceph_osds_block *blk;

		blk = rb_entry(n, typeof(*blk), b_node);
		cmp = RB_CMP3WAY(off, blk->b_off);
		if (cmp < 0) {
			right = blk;
			n = n->rb_left;
		}
		else if (cmp > 0) {
			n = n->rb_right;
		} else {
			return blk;
		}
	}

	return right;
}

static int handle_osd_op_read(struct ceph_msg *msg,
			      struct ceph_msg_osd_op *req,
			      struct ceph_osd_req_op *op)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_object *obj;
	struct ceph_osds_block *blk;
	size_t len_read, map_size;
	off_t off, blk_off;
	unsigned off_inpg;
	bool is_sparse;
	void *p;
	int ret;

	struct ceph_bvec_iter it;

	/* Find an object */
	obj = ceph_lookup_object(osds, req);
	if (!obj)
		return -ENOENT;

	if (!op->extent.length)
		/* Nothing to do */
		return 0;

	if (op->extent.offset >= obj->o_size)
		/* Offset is beyond the object, nothing to do */
		return 0;

	is_sparse = (op->op == CEPH_OSD_OP_SPARSE_READ);
	map_size = is_sparse ? 4 + 8 + 8 + 4: 0;

	len_read = min(op->extent.length, obj->o_size - op->extent.offset);

	/* Allocate bvec for the read chunk */
	ret = alloc_bvec(&it, map_size + len_read);
	if (ret)
		return ret;

	/* Setup output length and data */
	op->outdata_len = map_size + len_read;
	op->outdata = &op->extent.osd_data;

	/* Give ownership to msg */
	ceph_msg_data_bvecs_init(&op->extent.osd_data, &it, 1, true);

	/* Here we always have 1 segment bvec, with mpages though */
	p = page_address(it.bvecs->bv_page);

	if (is_sparse) {
		/* Encode extent map, for now we have only 1 entry */
		ceph_encode_32(&p, 1); /* map size */
		ceph_encode_64(&p, op->extent.offset); /* offset as a key */
		ceph_encode_64(&p, len_read); /* len as a value */
		ceph_encode_32(&p, len_read); /* len of the following extent */
	}

	off_inpg = 0;
	off = op->extent.offset;
	blk_off = ALIGN_DOWN(off, OSDS_BLOCK_SIZE);
	blk = lookup_block_ge(obj, blk_off);
	while (blk && len_read) {
		/* Found block is exactly we were looking for or the next one */
		BUG_ON(blk->b_off < blk_off);

		/* Zero out a possible hole before block */
		if (blk->b_off > off) {
			size_t len_zero = blk->b_off - off;

			len_zero = min(len_zero, len_read);
			memset(p + off_inpg, 0, len_zero);

			len_read -= len_zero;
			off_inpg += len_zero;
			off += len_zero;
		}

		/* Copy block */
		if (len_read) {
			void *src = page_address(blk->b_page);
			off_t off_inblk = off & ~OSDS_BLOCK_MASK;
			size_t len_copy;

			len_copy = min((size_t)OSDS_BLOCK_SIZE - off_inblk,
				       len_read);

			memcpy(p + off_inpg, src + off_inblk, len_copy);

			len_read -= len_copy;
			off_inpg += len_copy;
			off += len_copy;
		}

		/* Get the next block */
		if (len_read) {
			blk = rb_entry_safe(rb_next(&blk->b_node),
					    typeof(*blk), b_node);
		}
	}

	if (len_read)
		/* Zero out the rest */
		memset(p + off_inpg, 0, len_read);

	return 0;
}

static int handle_osd_op_stat(struct ceph_msg *msg,
			      struct ceph_msg_osd_op *req,
			      struct ceph_osd_req_op *op)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_object *obj;
	struct ceph_bvec_iter it;
	struct ceph_timespec ts;
	size_t outdata_len;
	void *p;
	int ret;

	/* Find an object */
	obj = ceph_lookup_object(osds, req);
	if (!obj)
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
	ceph_encode_timespec64(&ts, &obj->o_mtime);
	ceph_encode_64(&p, obj->o_size);
	ceph_encode_copy(&p, &ts, sizeof(ts));

	return 0;
}

struct osds_cls_call_ctx {
	struct ceph_cls_call_ctx ctx;
	struct ceph_msg          *msg;
	struct ceph_msg_osd_op   *req;
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

	msg = osds_ctx->msg;
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
	struct ceph_msg_data_cursor in_cur;
	struct ceph_msg_data in_data;
	struct ceph_osd_req_op op;
	int ret;

	osds_ctx = container_of(ctx, typeof(*osds_ctx), ctx);

	/* Fill in osd request op */
	ret = osd_op_to_req_op(raw_op, &op);
	if (ret)
		return ret;

	if (WARN_ON(op.op == CEPH_OSD_OP_CALL))
		/* Avoid recursion */
		return -EINVAL;

	/* Init msg data with input kvec */
	ceph_msg_data_kvec_init(&in_data, in);

	/* Init iterator for input data */
	ceph_msg_data_cursor_init(&in_cur, &in_data, WRITE, in->length);

	ret = handle_osd_op(osds_ctx->msg, osds_ctx->req, &op, &in_cur);
	if (ret)
		return ret;

	if (op.outdata) {
		struct ceph_msg_data_kvec *vec_data;

		vec_data = alloc_msg_data_kvec(op.outdata);
		if (!vec_data) {
			ceph_msg_data_release(op.outdata);
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

static int handle_osd_op_call(struct ceph_msg *msg,
			      struct ceph_msg_osd_op *req,
			      struct ceph_osd_req_op *op,
			      struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
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
	    op->cls.indata_len > msg->data_length)
		return -EINVAL;

	ceph_msg_data_cursor_next(in_cur);
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
		.msg = msg,
		.req = req,
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

static struct ceph_osds_omap_entry *
lookup_omap_entry_ge_gt(struct rb_root *root, const char *key, bool equal)
{
	struct rb_node *n = root->rb_node;
	struct ceph_osds_omap_entry *right = NULL;
	int cmp = 0;

	while (n) {
		struct ceph_osds_omap_entry *ome;

		ome = rb_entry(n, typeof(*ome), e_node);
		cmp = strcmp(key, ome->e_key);
		if (cmp < 0) {
			right = ome;
			n = n->rb_left;
		}
		else if (cmp > 0) {
			n = n->rb_right;
		} else {
			if (equal)
				/* Exact match */
				return ome;

			/*
			 * We were asked to lookup for the next node,
			 * i.e. greater than the key. Two options exist:
			 * a) return right node from the current one,
			 * b) if right node does not exist - return the
			 *    cached right, when we turned left.
			 */
			n = n->rb_right;
			if (n)
				return rb_entry(n, typeof(*ome), e_node);

			return right;
		}
	}

	return right;
}

static struct ceph_osds_omap_entry *
lookup_omap_entry_ge(struct rb_root *root, const char *key)
{
	return lookup_omap_entry_ge_gt(root, key, true);
}

static struct ceph_osds_omap_entry *
lookup_omap_entry_gt(struct rb_root *root, const char *key)
{
	return lookup_omap_entry_ge_gt(root, key, false);
}

static int ceph_encode_omap_entry(struct ceph_pagelist *pl,
				  struct ceph_osds_omap_entry *ome)
{
	int ret;

	/* Encode key */
	ret = ceph_pagelist_encode_string(pl, ome->e_key,
					  ome->e_key_len);
	/* Encode value with prefixed length  */
	if (!ret)
		ret = ceph_pagelist_encode_pagelist(pl, ome->e_val_pl, true);

	return ret;
}

static int handle_osd_op_omapgetvals(struct ceph_msg *msg,
				     struct ceph_msg_osd_op *req,
				     struct ceph_osd_req_op *op,
				     struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_omap_entry *ome;
	struct ceph_osds_object *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	char *after_str = NULL, *prefix_str = NULL;
	const char *after;
	const char *prefix;

	uint64_t max, cnt;
	u8 more = false;

	after_str = cursor_decode_safe_str(in_cur, GFP_KERNEL, einval, enomem);
	max = cursor_decode_safe(64, in_cur, einval);
	prefix_str = cursor_decode_safe_str(in_cur, GFP_KERNEL, einval, enomem);

	after = after_str ?: "";
	prefix = prefix_str ?: "";

	if (!max)
		goto einval;

	pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!pl)
		goto enomem;

	/*
	 * Write zero size of the map, if omap values are found -
	 * will update the value later.
	 */
	ret = ceph_pagelist_encode_32(pl, 0);
	if (ret)
		goto err;

	obj = ceph_lookup_object(osds, req);
	if (!obj)
		/* Last bits and we are done */
		goto finish;

	if (strcmp(after, prefix) < 0) {
		/*
		 * 'prefix' is to the right from 'after', so do not waste
		 * time and do lookup *starting* from 'prefix', thus GE.
		 */
		ome = lookup_omap_entry_ge(&obj->o_omap, prefix);
	} else {
		/*
		 * Lookup for omaps greater than 'after', thus GT.
		 */
		ome = lookup_omap_entry_gt(&obj->o_omap, after);
	}

	for (cnt = 0; ome && cnt < max; cnt++) {
		/* Key should start with the prefix */
		if (strncmp(ome->e_key, prefix, strlen(prefix)))
		    break;

		/* Encode key and value */
		ret = ceph_encode_omap_entry(pl, ome);
		if (ret)
			goto err;

		/* Get the next node */
		ome = rb_entry_safe(rb_next(&ome->e_node),
				    typeof(*ome), e_node);
	}

	/* Do we have more? */
	more = (ome && cnt == max);

	if (cnt) {
		/* Write down map size at 0 offset */
		ret = ceph_pagelist_encode_32_at_offset(pl, cnt, 0);
		if (ret)
			goto err;
	}

finish:
	ret = ceph_pagelist_encode_8(pl, more);
	if (ret)
		goto err;

	/* Setup output length */
	op->outdata_len = pl->length;
	op->outdata = &op->raw_data;

	/* Give ownership to msg */
	ceph_msg_data_pagelist_init(&op->raw_data, pl);

	kfree(after_str);
	kfree(prefix_str);

	return 0;

err:
	kfree(after_str);
	kfree(prefix_str);
	if (pl)
		ceph_pagelist_release(pl);
	return ret;

einval:
	ret = -EINVAL;
	goto err;

enomem:
	ret = -ENOMEM;
	goto err;
}

static int handle_osd_op_omapgetvalsbykeys(struct ceph_msg *msg,
					   struct ceph_msg_osd_op *req,
					   struct ceph_osd_req_op *op,
					   struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_object *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	unsigned int i, cnt, max;

	/* How many values we should return */
	max = cursor_decode_safe(32, in_cur, einval);

	pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!pl)
		return -ENOMEM;

	/*
	 * Write zero size of the map, if omap values are found -
	 * will update the value later.
	 */
	ret = ceph_pagelist_encode_32(pl, 0);
	if (ret)
		goto err;

	obj = ceph_lookup_object(osds, req);
	if (!obj)
		/* Last bits and we are done */
		goto finish;

	for (i = 0, cnt = 0; i < max; i++) {
		struct ceph_osds_omap_entry *ome;
		char *key;

		/* Extract a key and lookup for an entry */
		key = cursor_decode_safe_str(in_cur, GFP_KERNEL,
					     einval, enomem);
		ome = lookup_omap_entry(&obj->o_omap, key);
		kfree(key);

		if (!ome)
			continue;

		/* Encode key and value */
		ret = ceph_encode_omap_entry(pl, ome);
		if (ret)
			goto err;
		cnt++;
	}

	if (cnt) {
		/* Write down map size at 0 offset */
		ret = ceph_pagelist_encode_32_at_offset(pl, cnt, 0);
		if (ret)
			goto err;
	}

finish:
	/* Setup output length */
	op->outdata_len = pl->length;
	op->outdata = &op->raw_data;

	/* Give ownership to msg */
	ceph_msg_data_pagelist_init(&op->raw_data, pl);

	return 0;

err:
	if (pl)
		ceph_pagelist_release(pl);
	return ret;

einval:
	ret = -EINVAL;
	goto err;

enomem:
	ret = -ENOMEM;
	goto err;
}

static int handle_osd_op_omapsetvals(struct ceph_msg *msg,
				     struct ceph_msg_osd_op *req,
				     struct ceph_osd_req_op *op,
				     struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_object *obj;
	int ret;

	unsigned int i, cnt;

	/* How many values we should set */
	cnt = cursor_decode_safe(32, in_cur, einval);

	/* Find or create an object */
	obj = ceph_lookup_object(osds, req);
	if (!obj) {
		obj = ceph_create_and_insert_object(osds, req);
		if (!obj)
			goto enomem;
	}

	for (i = 0; i < cnt; i++) {
		struct ceph_osds_omap_entry *ome;
		size_t val_len;
		char *key;

		/* Extract key and look omap entry */
		key = cursor_decode_safe_str(in_cur, GFP_KERNEL,
					     einval, enomem);
		ome = lookup_omap_entry(&obj->o_omap, key);
		if (!ome)
			ome = ceph_create_and_insert_omap(&obj->o_omap, key);
		kfree(key);
		if (!ome)
			goto enomem;

		/* Get value size */
		val_len = cursor_decode_safe(32, in_cur, einval);

		/* Reserve enough to keep new value */
		if (val_len > ome->e_val_pl->length) {
			ret = ceph_pagelist_reserve(ome->e_val_pl,
					val_len - ome->e_val_pl->length);
			if (ret)
				goto err;
		}

		/* Copy value */
		ret = ceph_pagelist_copy_from_cursor(ome->e_val_pl, in_cur,
						     val_len);
		/* Should be preallocated, thus no error expected */
		WARN_ON(ret);

		/* In case old value was bigger than the new one */
		ret = ceph_pagelist_truncate(ome->e_val_pl, val_len);
		WARN_ON(ret);
	}

	return 0;

err:
	return ret;

einval:
	ret = -EINVAL;
	goto err;

enomem:
	ret = -ENOMEM;
	goto err;
}

static int handle_osd_op_omapgetkeys(struct ceph_msg *msg,
				     struct ceph_msg_osd_op *req,
				     struct ceph_osd_req_op *op,
				     struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_omap_entry *ome;
	struct ceph_osds_object *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	char *after_str = NULL;
	const char *after;

	uint64_t max, cnt;
	u8 more = false;

	after_str = cursor_decode_safe_str(in_cur, GFP_KERNEL, einval, enomem);
	max = cursor_decode_safe(64, in_cur, einval);

	after = after_str ?: "";

	if (!max)
		goto einval;

	pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!pl)
		goto enomem;

	/*
	 * Write zero size of the map, if omap values are found -
	 * will update the value later.
	 */
	ret = ceph_pagelist_encode_32(pl, 0);
	if (ret)
		goto err;

	obj = ceph_lookup_object(osds, req);
	if (!obj)
		/* Last bits and we are done */
		goto finish;

	/*
	 * Lookup for omaps greater than 'after', thus GT.
	 */
	ome = lookup_omap_entry_gt(&obj->o_omap, after);

	for (cnt = 0; ome && cnt < max; cnt++) {
		/* Encode key */
		ret = ceph_pagelist_encode_string(pl, ome->e_key,
						  ome->e_key_len);
		if (ret)
			goto err;

		/* Get the next node */
		ome = rb_entry_safe(rb_next(&ome->e_node),
				    typeof(*ome), e_node);
	}

	/* Do we have more? */
	more = (ome && cnt == max);

	if (cnt) {
		/* Write down map size at 0 offset */
		ret = ceph_pagelist_encode_32_at_offset(pl, cnt, 0);
		if (ret)
			goto err;
	}

finish:
	ret = ceph_pagelist_encode_8(pl, more);
	if (ret)
		goto err;

	/* Setup output length */
	op->outdata_len = pl->length;
	op->outdata = &op->raw_data;

	/* Give ownership to msg */
	ceph_msg_data_pagelist_init(&op->raw_data, pl);

	kfree(after_str);

	return 0;

err:
	kfree(after_str);
	if (pl)
		ceph_pagelist_release(pl);
	return ret;

einval:
	ret = -EINVAL;
	goto err;

enomem:
	ret = -ENOMEM;
	goto err;
}

static int handle_osd_op_getxattr(struct ceph_msg *msg,
				  struct ceph_msg_osd_op *req,
				  struct ceph_osd_req_op *op,
				  struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_omap_entry *ome;
	struct ceph_osds_object *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	char *key = NULL;

	key = cursor_decode_safe_strn(in_cur, GFP_KERNEL, op->xattr.name_len,
				      einval, enomem);
	if (!key)
		goto einval;

	pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!pl)
		goto enomem;

	obj = ceph_lookup_object(osds, req);
	if (!obj)
		goto einval;

	ome = lookup_omap_entry(&obj->o_xattrs, key);
	if (!ome)
		goto enodata;

	/* Encode value */
	ret = ceph_pagelist_encode_pagelist(pl, ome->e_val_pl, false);
	if (ret)
		goto err;

	/* Setup output length */
	op->outdata_len = pl->length;
	op->outdata = &op->raw_data;

	/* Give ownership to msg */
	ceph_msg_data_pagelist_init(&op->raw_data, pl);

	kfree(key);

	return 0;

err:
	kfree(key);
	if (pl)
		ceph_pagelist_release(pl);
	return ret;

einval:
	ret = -EINVAL;
	goto err;

enomem:
	ret = -ENOMEM;
	goto err;

enodata:
	ret = -ENODATA;
	goto err;
}

static int handle_osd_op_setxattr(struct ceph_msg *msg,
				  struct ceph_msg_osd_op *req,
				  struct ceph_osd_req_op *op,
				  struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_omap_entry *ome;
	struct ceph_osds_object *obj;
	size_t val_len;
	int ret;

	char *key = NULL;

	key = cursor_decode_safe_strn(in_cur, GFP_KERNEL, op->xattr.name_len,
				      einval, enomem);
	if (!key)
		goto einval;

	/* Find or create an object */
	obj = ceph_lookup_object(osds, req);
	if (!obj) {
		obj = ceph_create_and_insert_object(osds, req);
		if (!obj)
			goto enomem;
	}

	/* Find or create new xattr */
	ome = lookup_omap_entry(&obj->o_xattrs, key);
	if (!ome) {
		ome = ceph_create_and_insert_omap(&obj->o_xattrs, key);
		if (!ome)
			goto enomem;
	}

	/* Get value size */
	val_len = op->xattr.value_len;

	/* Reserve enough to keep new value */
	if (val_len > ome->e_val_pl->length) {
		ret = ceph_pagelist_reserve(ome->e_val_pl,
					    val_len - ome->e_val_pl->length);
		if (ret)
			goto err;
	}

	/* Copy value */
	ret = ceph_pagelist_copy_from_cursor(ome->e_val_pl, in_cur,
					     val_len);
	/* Should be preallocated, thus no error expected */
	WARN_ON(ret);

	/* In case old value was bigger than the new one */
	ret = ceph_pagelist_truncate(ome->e_val_pl, val_len);
	WARN_ON(ret);

	kfree(key);

	return 0;

err:
	kfree(key);
	return ret;

einval:
	ret = -EINVAL;
	goto err;

enomem:
	ret = -ENOMEM;
	goto err;
}

static int handle_osd_op_create(struct ceph_msg *msg,
				struct ceph_msg_osd_op *req,
				struct ceph_osd_req_op *op)
{
	struct ceph_osd_server *osds = con_to_osds(msg->con);
	struct ceph_osds_object *obj;

	obj = ceph_lookup_object(osds, req);
	if (obj)
		return op->flags & CEPH_OSD_OP_FLAG_EXCL ? -EEXIST : 0;

	obj = ceph_create_and_insert_object(osds, req);
	if (!obj)
		return -ENOMEM;

	return 0;
}

static int handle_osd_op(struct ceph_msg *msg, struct ceph_msg_osd_op *req,
			 struct ceph_osd_req_op *op,
			 struct ceph_msg_data_cursor *in_cur)
{
	int ret;

	switch (op->op) {
	case CEPH_OSD_OP_WRITE:
	case CEPH_OSD_OP_WRITEFULL:
		ret = handle_osd_op_write(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_SYNC_READ:
	case CEPH_OSD_OP_SPARSE_READ:
		ret = handle_osd_op_read(msg, req, op);
		break;
	case CEPH_OSD_OP_STAT:
		ret = handle_osd_op_stat(msg, req, op);
		break;
	case CEPH_OSD_OP_CALL:
		ret = handle_osd_op_call(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPGETVALS:
		ret = handle_osd_op_omapgetvals(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPGETVALSBYKEYS:
		ret = handle_osd_op_omapgetvalsbykeys(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPSETVALS:
		ret = handle_osd_op_omapsetvals(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPGETKEYS:
		ret = handle_osd_op_omapgetkeys(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_GETXATTR:
		ret = handle_osd_op_getxattr(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_SETXATTR:
		ret = handle_osd_op_setxattr(msg, req, op, in_cur);
		break;
	case CEPH_OSD_OP_CREATE:
		ret = handle_osd_op_create(msg, req, op);
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

static void handle_osd_ops(struct ceph_connection *con, struct ceph_msg *msg)
{
	struct ceph_osd_client *osdc = con_to_osdc(con);
	struct ceph_msg_data_cursor in_cur;
	struct ceph_msg_osd_op req;
	struct ceph_msg *reply;
	int ret, i;

	/* See osds_alloc_msg(), we gather input in a single data */
	BUG_ON(msg->num_data_items > 1);

	ret = ceph_decode_msg_osd_op(msg, &req);
	if (unlikely(ret)) {
		pr_err("%s: con %p, failed to decode a message, ret=%d\n",
		       __func__, con, ret);
		return;
	}

	/* Init iterator for input data, ->data_length can be 0 */
	ceph_msg_data_cursor_init(&in_cur, msg->data, WRITE,
				  msg->data_length);

	/* Iterate over all operations */
	for (i = 0; i < req.num_ops; i++) {
		struct ceph_osd_req_op *op = &req.ops[i];

		/* Make things happen */
		ret = handle_osd_op(msg, &req, op, &in_cur);
		if (ret && (op->flags & CEPH_OSD_OP_FLAG_FAILOK) &&
		    ret != -EAGAIN && ret != -EINPROGRESS)
			/* Ignore op error and continue executing */
			ret = 0;

		if (ret)
			break;
	}

	/* Create reply message */
	reply = create_osd_op_reply(&req, ret, osdc->osdmap->epoch,
			/* TODO: Not actually clear to me when to set those */
			CEPH_OSD_FLAG_ACK | CEPH_OSD_FLAG_ONDISK);

	deinit_msg_osd_op(&req);

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
		handle_osd_ops(con, msg);
		break;
	default:
		pr_err("@@ message type %d, \"%s\"\n", type,
		       ceph_msg_type_name(type));
		break;
	}

	ceph_msg_put(msg);
}

static struct ceph_msg *alloc_msg_with_bvec(struct ceph_msg_header *hdr)
{
	struct ceph_msg *m;
	int type = le16_to_cpu(hdr->type);
	u32 front_len = le32_to_cpu(hdr->front_len);
	u32 data_len = le32_to_cpu(hdr->data_len);

	m = ceph_msg_new2(type, front_len, 1, GFP_KERNEL, false);
	if (!m)
		return NULL;

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
	int type = le16_to_cpu(hdr->type);

	*skip = 0;
	switch (type) {
	case CEPH_MSG_OSD_MAP:
	case CEPH_MSG_OSD_BACKOFF:
	case CEPH_MSG_WATCH_NOTIFY:
	case CEPH_MSG_OSD_OP:
		return alloc_msg_with_bvec(hdr);
	case CEPH_MSG_OSD_OPREPLY:
		/* fall through */
	default:
		pr_warn("%s unknown msg type %d '%s', skipping\n", __func__,
			type, ceph_msg_type_name(type));
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
	osds->s_objects = RB_ROOT;
	ceph_cls_init(&osds->class_loader, opt);

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

static void destroy_blocks(struct ceph_osds_object *obj)
{
	struct ceph_osds_block *blk;

	while ((blk = rb_entry_safe(rb_first(&obj->o_blocks),
				    typeof(*blk), b_node))) {
		erase_object_block_by_off(&obj->o_blocks, blk);
		__free_pages(blk->b_page, OSDS_BLOCK_SHIFT - PAGE_SHIFT);
		kfree(blk);
	}
}

static void __destroy_omap(struct rb_root *root)
{
	struct ceph_osds_omap_entry *ome;

	while ((ome = rb_entry_safe(rb_first(root),
				    typeof(*ome), e_node))) {
		erase_omap_entry(root, ome);
		ceph_pagelist_release(ome->e_val_pl);
		kfree(ome->e_key);
		kfree(ome);
	}
}

static void destroy_omap(struct ceph_osds_object *obj)
{
	__destroy_omap(&obj->o_omap);
}

static void destroy_xattrs(struct ceph_osds_object *obj)
{
	__destroy_omap(&obj->o_xattrs);
}

static void destroy_objects(struct ceph_osd_server *osds)
{
	struct ceph_osds_object *obj;

	while ((obj = rb_entry_safe(rb_first(&osds->s_objects),
				    typeof(*obj), o_node))) {
		destroy_blocks(obj);
		destroy_omap(obj);
		destroy_xattrs(obj);
		erase_object_by_hoid(&osds->s_objects, obj);
		kfree(obj);
	}
}

void ceph_destroy_osd_server(struct ceph_osd_server *osds)
{
	ceph_stop_osd_server(osds);
	ceph_destroy_client(osds->client);
	destroy_objects(osds);
	ceph_cls_deinit(&osds->class_loader);
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
