// SPDX-License-Identifier: GPL-2.0
#include "types.h"
#include "rbtree.h"
#include "slab.h"
#include "getorder.h"

#include "ceph/memstore.h"
#include "ceph/transaction.h"

enum {
	MEMSTORE_BLOCK_SHIFT    = 16, /* 64k, must be ^2 */
	MEMSTORE_BLOCK_SIZE     = (1UL << MEMSTORE_BLOCK_SHIFT),
	MEMSTORE_BLOCK_MASK     = (~(MEMSTORE_BLOCK_SIZE-1))
};

struct ceph_store_coll {
};

struct ceph_memstore {
	struct ceph_store      s;
	struct rb_root         colls;  /* collections */
};

struct ceph_memstore_coll {
	struct rb_node         node;    /* node of ->colls */
	struct ceph_store_coll c;
	struct ceph_spg        spg;
	struct rb_root         objects; /* objects of the collection */
	struct ceph_memstore   *store;
	bool                   persistent; /* transaction commited */
};

struct ceph_memstore_obj {
	struct rb_node         node;    /* node of ->objects */
	struct ceph_hobject_id hoid;
	struct rb_root         blocks;  /* all blocks of the object */
	struct rb_root         omap;    /* omap of the object */
	struct rb_root         xattrs;  /* xattr of the object */
	size_t                 size;    /* size of an object */
	struct timespec64      mtime;   /* modification time of an object */
};

struct ceph_memstore_blk {
	struct rb_node         node;    /* node of ->blocks */
	struct page            *page;
	off_t                  off;     /* offset inside a whole object */
};

struct ceph_memstore_omap_ent {
	struct rb_node         node;    /* node of ->omap or ->xattrs */
	char                   *key;
	unsigned int           key_len;
	struct ceph_pagelist   *val_pl;
};

/* Define RB functions for collection lookup and insert by spg */
DEFINE_RB_FUNCS2(collection, struct ceph_memstore_coll, spg,
		 ceph_spg_compare, RB_BYPTR, struct ceph_spg *,
		 node);

/* Define RB functions for object lookup and insert by hoid */
DEFINE_RB_FUNCS2(object, struct ceph_memstore_obj, hoid,
		 ceph_hoid_compare, RB_BYPTR, struct ceph_hobject_id *,
		 node);

/* Define RB functions for object block lookup by offset */
DEFINE_RB_FUNCS(object_block, struct ceph_memstore_blk, off, node);

/* Define RB functions for omap lookup by string */
DEFINE_RB_FUNCS2(omap_entry, struct ceph_memstore_omap_ent, key,
		 strcmp, RB_BYVAL, char *, node);

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

static struct ceph_memstore_obj *
create_and_insert_object(struct ceph_memstore_coll *coll,
			 struct ceph_hobject_id *hoid)
{
	struct ceph_memstore_obj *obj;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;

	obj->size = 0;
	obj->blocks = RB_ROOT;
	obj->omap = RB_ROOT;
	obj->xattrs = RB_ROOT;
	RB_CLEAR_NODE(&obj->node);
	ceph_hoid_init(&obj->hoid);
	ceph_hoid_copy(&obj->hoid, hoid);
	insert_object(&coll->objects, obj);

	return obj;
}

static struct ceph_memstore_coll *
create_and_insert_collection(struct ceph_memstore *store,
			     struct ceph_spg *spg)
{
	struct ceph_memstore_coll *coll;

	coll = kmalloc(sizeof(*coll), GFP_KERNEL);
	if (!coll)
		return NULL;

	RB_CLEAR_NODE(&coll->node);
	coll->spg = *spg;
	coll->objects = RB_ROOT;
	coll->store = store;
	coll->persistent = false;
	insert_collection(&store->colls, coll);

	return coll;
}

static struct ceph_store_coll *open_collection(struct ceph_store *s,
					       struct ceph_spg *spg)
{
	struct ceph_memstore *store;
	struct ceph_memstore_coll *coll;

	store = container_of(s, typeof(*store), s);
	coll = lookup_collection(&store->colls, spg);
	if (!coll || !coll->persistent)
		return ERR_PTR(-ENOENT);

	return &coll->c;
}

static struct ceph_store_coll *create_collection(struct ceph_store *s,
						 struct ceph_spg *spg)
{
	struct ceph_memstore *store;
	struct ceph_memstore_coll *coll;

	store = container_of(s, typeof(*store), s);
	coll = lookup_collection(&store->colls, spg);
	if (!coll) {
		coll = create_and_insert_collection(store, spg);
		if (!coll)
			return ERR_PTR(-ENOMEM);
	} else if (coll->persistent) {
		return ERR_PTR(-EEXIST);
	}

	return &coll->c;
}

static struct ceph_memstore_omap_ent *
create_and_insert_omap(struct rb_root *root, const char *key)
{
	struct ceph_memstore_omap_ent *ome;
	size_t key_len = strlen(key);

	ome = kmalloc(sizeof(*ome), GFP_KERNEL);
	if (!ome)
		return NULL;

	ome->key = kstrndup(key, key_len, GFP_KERNEL);
	if (!ome->key) {
		kfree(ome);
		return NULL;
	}
	ome->key_len = key_len;
	RB_CLEAR_NODE(&ome->node);

	ome->val_pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!ome->val_pl) {
		kfree(ome->key);
		kfree(ome);
		return NULL;
	}
	insert_omap_entry(root, ome);

	return ome;
}

static inline int next_dst(struct ceph_osd_req_op *op,
			   struct ceph_memstore_obj *obj,
			   struct ceph_memstore_blk **pblk,
			   off_t dst_off,
			   size_t *dst_len)
{
	struct ceph_memstore_blk *blk;
	off_t blk_off;

	blk_off = ALIGN_DOWN(dst_off, MEMSTORE_BLOCK_SIZE);
	blk = lookup_object_block(&obj->blocks, blk_off);
	if (!blk) {
		unsigned int order;

		blk = kmalloc(sizeof(*blk), GFP_KERNEL);
		if (!blk)
			return -ENOMEM;

		RB_CLEAR_NODE(&blk->node);
		order = MEMSTORE_BLOCK_SHIFT - PAGE_SHIFT;
		blk->page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
		blk->off = blk_off;

		if (!blk->page) {
			kfree(blk);
			return -ENOMEM;
		}

		insert_object_block(&obj->blocks, blk);
	}

	*dst_len = MEMSTORE_BLOCK_SIZE - (dst_off & ~MEMSTORE_BLOCK_MASK);
	*pblk = blk;


	return 0;
}

static int handle_osd_op_write(struct ceph_memstore_coll *coll,
			       struct ceph_hobject_id *hoid,
			       struct timespec64 *mtime,
			       struct ceph_osd_req_op *op,
			       const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore* store = coll->store;
	struct ceph_memstore_obj *obj;
	struct ceph_memstore_blk *blk;

	size_t len_write, dst_len;
	off_t dst_off;

	bool modified = false;
	int ret;

	if (!op->extent.length)
		/* Nothing to do */
		return 0;

	if (ceph_test_opt(store->s.opt, NOOP_WRITE) &&
	    op->extent.length >= 4096)
		/* Write is noop */
		return 0;

	/*
	 * Find or create an object
	 */
	obj = lookup_object(&coll->objects, hoid);
	if (!obj) {
		obj = create_and_insert_object(coll, hoid);
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

		len = iov_iter_count(&incur.iter);
		len = min(len, dst_len);
		len = min(len, len_write);

		dst = page_address(blk->page);
		len2 = copy_from_iter(dst + (dst_off & ~MEMSTORE_BLOCK_MASK),
				      len, &incur.iter);
		WARN_ON(len2 != len);

		ceph_msg_data_cursor_advance(&incur, len);
		len_write -= len;
		dst_len -= len;
		dst_off += len;
		modified = true;
	}
out:
	if (modified) {
		bool truncate = (op->op == CEPH_OSD_OP_WRITEFULL);

		obj->mtime = *mtime;

		/* Extend object size if needed or truncate */
		if (dst_off > obj->size || truncate)
			obj->size = dst_off;

		/* FIXME: need to free the rest in case of truncate */
	}

	return ret;
}


/**
 * lookup_block_ge() - returns block which offset equal or greater than @off
 */
static struct ceph_memstore_blk *
lookup_block_ge(struct ceph_memstore_obj *obj, off_t off)
{
	struct rb_node *n = obj->blocks.rb_node;
	struct ceph_memstore_blk *right = NULL;
	int cmp = 0;

	while (n) {
		struct ceph_memstore_blk *blk;

		blk = rb_entry(n, typeof(*blk), node);
		cmp = RB_CMP3WAY(off, blk->off);
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

static int handle_osd_op_read(struct ceph_memstore_coll *coll,
			      struct ceph_hobject_id *hoid,
			      struct ceph_osd_req_op *op)
{
	struct ceph_memstore_obj *obj;
	struct ceph_memstore_blk *blk;
	size_t len_read, map_size;
	off_t off, blk_off;
	unsigned off_inpg;
	bool is_sparse;
	void *p;
	int ret;

	struct ceph_bvec_iter it;

	/* Find an object */
	obj = lookup_object(&coll->objects, hoid);
	if (!obj)
		return -ENOENT;

	if (!op->extent.length)
		/* Nothing to do */
		return 0;

	if (op->extent.offset >= obj->size)
		/* Offset is beyond the object, nothing to do */
		return 0;

	is_sparse = (op->op == CEPH_OSD_OP_SPARSE_READ);
	map_size = is_sparse ? 4 + 8 + 8 + 4: 0;

	len_read = min(op->extent.length, obj->size - op->extent.offset);

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
	blk_off = ALIGN_DOWN(off, MEMSTORE_BLOCK_SIZE);
	blk = lookup_block_ge(obj, blk_off);
	while (blk && len_read) {
		/* Found block is exactly we were looking for or the next one */
		BUG_ON(blk->off < blk_off);

		/* Zero out a possible hole before block */
		if (blk->off > off) {
			size_t len_zero = blk->off - off;

			len_zero = min(len_zero, len_read);
			memset(p + off_inpg, 0, len_zero);

			len_read -= len_zero;
			off_inpg += len_zero;
			off += len_zero;
		}

		/* Copy block */
		if (len_read) {
			void *src = page_address(blk->page);
			off_t off_inblk = off & ~MEMSTORE_BLOCK_MASK;
			size_t len_copy;

			len_copy = min((size_t)MEMSTORE_BLOCK_SIZE - off_inblk,
				       len_read);

			memcpy(p + off_inpg, src + off_inblk, len_copy);

			len_read -= len_copy;
			off_inpg += len_copy;
			off += len_copy;
		}

		/* Get the next block */
		if (len_read) {
			blk = rb_entry_safe(rb_next(&blk->node),
					    typeof(*blk), node);
		}
	}

	if (len_read)
		/* Zero out the rest */
		memset(p + off_inpg, 0, len_read);

	return 0;
}

static int handle_osd_op_stat(struct ceph_memstore_coll *coll,
			      struct ceph_hobject_id *hoid,
			      struct ceph_osd_req_op *op)
{
	struct ceph_memstore_obj *obj;
	struct ceph_bvec_iter it;
	struct ceph_timespec ts;
	size_t outdata_len;
	void *p;
	int ret;

	/* Find an object */
	obj = lookup_object(&coll->objects, hoid);
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
	ceph_encode_timespec64(&ts, &obj->mtime);
	ceph_encode_64(&p, obj->size);
	ceph_encode_copy(&p, &ts, sizeof(ts));

	return 0;
}

static struct ceph_memstore_omap_ent *
lookup_omap_entry_ge_gt(struct rb_root *root, const char *key, bool equal)
{
	struct rb_node *n = root->rb_node;
	struct ceph_memstore_omap_ent *right = NULL;
	int cmp = 0;

	while (n) {
		struct ceph_memstore_omap_ent *ome;

		ome = rb_entry(n, typeof(*ome), node);
		cmp = strcmp(key, ome->key);
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
				return rb_entry(n, typeof(*ome), node);

			return right;
		}
	}

	return right;
}

static struct ceph_memstore_omap_ent *
lookup_omap_entry_ge(struct rb_root *root, const char *key)
{
	return lookup_omap_entry_ge_gt(root, key, true);
}

static struct ceph_memstore_omap_ent *
lookup_omap_entry_gt(struct rb_root *root, const char *key)
{
	return lookup_omap_entry_ge_gt(root, key, false);
}

static int encode_omap_entry(struct ceph_pagelist *pl,
			     struct ceph_memstore_omap_ent *ome)
{
	int ret;

	/* Encode key */
	ret = ceph_pagelist_encode_string(pl, ome->key,
					  ome->key_len);
	/* Encode value with prefixed length  */
	if (!ret)
		ret = ceph_pagelist_encode_pagelist(pl, ome->val_pl, true);

	return ret;
}

static int handle_osd_op_omapgetvals(struct ceph_memstore_coll *coll,
				     struct ceph_hobject_id *hoid,
				     struct ceph_osd_req_op *op,
				     const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore_omap_ent *ome;
	struct ceph_memstore_obj *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	char *after_str = NULL, *prefix_str = NULL;
	const char *after;
	const char *prefix;

	uint64_t max, cnt;
	u8 more = false;

	after_str = cursor_decode_safe_str(&incur, GFP_KERNEL, einval, enomem);
	max = cursor_decode_safe(64, &incur, einval);
	prefix_str = cursor_decode_safe_str(&incur, GFP_KERNEL, einval, enomem);

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

	obj = lookup_object(&coll->objects, hoid);
	if (!obj)
		/* Last bits and we are done */
		goto finish;

	if (strcmp(after, prefix) < 0) {
		/*
		 * 'prefix' is to the right from 'after', so do not waste
		 * time and do lookup *starting* from 'prefix', thus GE.
		 */
		ome = lookup_omap_entry_ge(&obj->omap, prefix);
	} else {
		/*
		 * Lookup for omaps greater than 'after', thus GT.
		 */
		ome = lookup_omap_entry_gt(&obj->omap, after);
	}

	for (cnt = 0; ome && cnt < max; cnt++) {
		/* Key should start with the prefix */
		if (strncmp(ome->key, prefix, strlen(prefix)))
		    break;

		/* Encode key and value */
		ret = encode_omap_entry(pl, ome);
		if (ret)
			goto err;

		/* Get the next node */
		ome = rb_entry_safe(rb_next(&ome->node),
				    typeof(*ome), node);
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

static int handle_osd_op_omapgetvalsbykeys(struct ceph_memstore_coll *coll,
					   struct ceph_hobject_id *hoid,
					   struct ceph_osd_req_op *op,
					   const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore_obj *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	unsigned int i, cnt, max;

	/* How many values we should return */
	max = cursor_decode_safe(32, &incur, einval);

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

	obj = lookup_object(&coll->objects, hoid);
	if (!obj)
		/* Last bits and we are done */
		goto finish;

	for (i = 0, cnt = 0; i < max; i++) {
		struct ceph_memstore_omap_ent *ome;
		char *key;

		/* Extract a key and lookup for an entry */
		key = cursor_decode_safe_str(&incur, GFP_KERNEL,
					     einval, enomem);
		ome = lookup_omap_entry(&obj->omap, key);
		kfree(key);

		if (!ome)
			continue;

		/* Encode key and value */
		ret = encode_omap_entry(pl, ome);
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

static int handle_osd_op_omapsetvals(struct ceph_memstore_coll *coll,
				     struct ceph_hobject_id *hoid,
				     struct ceph_osd_req_op *op,
				     const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore_obj *obj;
	int ret;

	unsigned int i, cnt;

	/* How many values we should set */
	cnt = cursor_decode_safe(32, &incur, einval);

	/* Find or create an object */
	obj = lookup_object(&coll->objects, hoid);
	if (!obj) {
		obj = create_and_insert_object(coll, hoid);
		if (!obj)
			goto enomem;
	}

	for (i = 0; i < cnt; i++) {
		struct ceph_memstore_omap_ent *ome;
		size_t val_len;
		char *key;

		/* Extract key and look omap entry */
		key = cursor_decode_safe_str(&incur, GFP_KERNEL,
					     einval, enomem);
		ome = lookup_omap_entry(&obj->omap, key);
		if (!ome)
			ome = create_and_insert_omap(&obj->omap, key);
		kfree(key);
		if (!ome)
			goto enomem;

		/* Get value size */
		val_len = cursor_decode_safe(32, &incur, einval);

		/* Reserve enough to keep new value */
		if (val_len > ome->val_pl->length) {
			ret = ceph_pagelist_reserve(ome->val_pl,
					val_len - ome->val_pl->length);
			if (ret)
				goto err;
		}

		/* Copy value */
		ret = ceph_pagelist_copy_from_cursor(ome->val_pl, &incur,
						     val_len);
		/* Should be preallocated, thus no error expected */
		WARN_ON(ret);

		/* In case old value was bigger than the new one */
		ret = ceph_pagelist_truncate(ome->val_pl, val_len);
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

static int handle_osd_op_omapgetkeys(struct ceph_memstore_coll *coll,
				     struct ceph_hobject_id *hoid,
				     struct ceph_osd_req_op *op,
				     const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore_omap_ent *ome;
	struct ceph_memstore_obj *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	char *after_str = NULL;
	const char *after;

	uint64_t max, cnt;
	u8 more = false;

	after_str = cursor_decode_safe_str(&incur, GFP_KERNEL, einval, enomem);
	max = cursor_decode_safe(64, &incur, einval);

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

	obj = lookup_object(&coll->objects, hoid);
	if (!obj)
		/* Last bits and we are done */
		goto finish;

	/*
	 * Lookup for omaps greater than 'after', thus GT.
	 */
	ome = lookup_omap_entry_gt(&obj->omap, after);

	for (cnt = 0; ome && cnt < max; cnt++) {
		/* Encode key */
		ret = ceph_pagelist_encode_string(pl, ome->key,
						  ome->key_len);
		if (ret)
			goto err;

		/* Get the next node */
		ome = rb_entry_safe(rb_next(&ome->node),
				    typeof(*ome), node);
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

static int handle_osd_op_getxattr(struct ceph_memstore_coll *coll,
				  struct ceph_hobject_id *hoid,
				  struct ceph_osd_req_op *op,
				  const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore_omap_ent *ome;
	struct ceph_memstore_obj *obj;
	struct ceph_pagelist *pl = NULL;
	int ret;

	char *key = NULL;

	key = cursor_decode_safe_strn(&incur, GFP_KERNEL, op->xattr.name_len,
				      einval, enomem);
	if (!key)
		goto einval;

	pl = ceph_pagelist_alloc(GFP_KERNEL);
	if (!pl)
		goto enomem;

	obj = lookup_object(&coll->objects, hoid);
	if (!obj)
		goto einval;

	ome = lookup_omap_entry(&obj->xattrs, key);
	if (!ome)
		goto enodata;

	/* Encode value */
	ret = ceph_pagelist_encode_pagelist(pl, ome->val_pl, false);
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

static int handle_osd_op_setxattr(struct ceph_memstore_coll *coll,
				  struct ceph_hobject_id *hoid,
				  struct ceph_osd_req_op *op,
				  const struct ceph_msg_data_cursor *in_cur)
{
	struct ceph_msg_data_cursor incur = *in_cur;
	struct ceph_memstore_omap_ent *ome;
	struct ceph_memstore_obj *obj;
	size_t val_len;
	int ret;

	char *key = NULL;

	key = cursor_decode_safe_strn(&incur, GFP_KERNEL, op->xattr.name_len,
				      einval, enomem);
	if (!key)
		goto einval;

	/* Find or create an object */
	obj = lookup_object(&coll->objects, hoid);
	if (!obj) {
		obj = create_and_insert_object(coll, hoid);
		if (!obj)
			goto enomem;
	}

	/* Find or create new xattr */
	ome = lookup_omap_entry(&obj->xattrs, key);
	if (!ome) {
		ome = create_and_insert_omap(&obj->xattrs, key);
		if (!ome)
			goto enomem;
	}

	/* Get value size */
	val_len = op->xattr.value_len;

	/* Reserve enough to keep new value */
	if (val_len > ome->val_pl->length) {
		ret = ceph_pagelist_reserve(ome->val_pl,
					    val_len - ome->val_pl->length);
		if (ret)
			goto err;
	}

	/* Copy value */
	ret = ceph_pagelist_copy_from_cursor(ome->val_pl, &incur,
					     val_len);
	/* Should be preallocated, thus no error expected */
	WARN_ON(ret);

	/* In case old value was bigger than the new one */
	ret = ceph_pagelist_truncate(ome->val_pl, val_len);
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

static int execute_ro_osd_op(struct ceph_store_coll *c,
			     struct ceph_hobject_id *hoid,
			     struct ceph_osd_req_op *op)
{
	const struct ceph_msg_data_cursor *in_cur = &op->incur;
	struct ceph_memstore_coll *coll;
	int ret;

	coll = container_of(c, typeof(*coll), c);

	switch (op->op) {
	case CEPH_OSD_OP_READ:
	case CEPH_OSD_OP_SYNC_READ:
	case CEPH_OSD_OP_SPARSE_READ:
		ret = handle_osd_op_read(coll, hoid, op);
		break;
	case CEPH_OSD_OP_STAT:
		ret = handle_osd_op_stat(coll, hoid, op);
		break;
	case CEPH_OSD_OP_OMAPGETVALS:
		ret = handle_osd_op_omapgetvals(coll, hoid, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPGETVALSBYKEYS:
		ret = handle_osd_op_omapgetvalsbykeys(coll, hoid, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPGETKEYS:
		ret = handle_osd_op_omapgetkeys(coll, hoid, op, in_cur);
		break;
	case CEPH_OSD_OP_GETXATTR:
		ret = handle_osd_op_getxattr(coll, hoid, op, in_cur);
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

static int execute_wr_osd_op(struct ceph_memstore *store,
			     struct ceph_transaction_op *txn_op)
{
	const struct ceph_msg_data_cursor *in_cur = &txn_op->op->incur;
	struct ceph_hobject_id *hoid = &txn_op->hoid;
	struct timespec64 *mtime = &txn_op->mtime;
	struct ceph_osd_req_op *op = txn_op->op;
	struct ceph_memstore_coll *coll;
	int ret;

	coll = lookup_collection(&store->colls, &txn_op->spg);
	if (!coll)
		return -ENOENT;

	switch (op->op) {
	case CEPH_OSD_OP_WRITE:
	case CEPH_OSD_OP_WRITEFULL:
		ret = handle_osd_op_write(coll, hoid, mtime, op, in_cur);
		break;
	case CEPH_OSD_OP_OMAPSETVALS:
		ret = handle_osd_op_omapsetvals(coll, hoid, op, in_cur);
		break;
	case CEPH_OSD_OP_SETXATTR:
		ret = handle_osd_op_setxattr(coll, hoid, op, in_cur);
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

static int handle_trans_op_mkcoll(struct ceph_memstore *store,
				  struct ceph_transaction_op *txn_op)
{
	struct ceph_memstore_coll *coll;

	coll = lookup_collection(&store->colls, &txn_op->spg);
	if (coll && coll->persistent)
		return -EEXIST;

	if (!coll) {
		/* Path is taken when ->create_collection() was not called */
		coll = create_and_insert_collection(store, &txn_op->spg);
		if (!coll)
			return -ENOMEM;
	}
	coll->persistent = true;

	return 0;
}

static int handle_trans_op_touch(struct ceph_memstore *store,
				 struct ceph_transaction_op *txn_op)
{
	struct ceph_memstore_coll *coll;
	struct ceph_memstore_obj *obj;


	coll = lookup_collection(&store->colls, &txn_op->spg);
	if (!coll || !coll->persistent)
		return -ENOENT;

	obj = lookup_object(&coll->objects, &txn_op->hoid);
	if (obj)
		return 0;

	obj = create_and_insert_object(coll, &txn_op->hoid);
	if (!obj)
		return -ENOMEM;

	return 0;
}

static int execute_trans_op(struct ceph_memstore *store,
			    struct ceph_transaction_op *txn_op)
{
	int ret;

	switch (txn_op->type) {
	case TXN_OP_MKCOLL:
		ret = handle_trans_op_mkcoll(store, txn_op);
		break;
	case TXN_OP_TOUCH:
		ret = handle_trans_op_touch(store, txn_op);
		break;
	default:
		pr_err("%s: unknown txn type 0x%x\n", __func__,
		       txn_op->type);
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static int execute_transaction(struct ceph_store *s,
			       struct ceph_transaction *txn)
{
	struct ceph_memstore *store;
	int i, ret = 0;

	store = container_of(s, typeof(*store), s);

	for (i = 0; i < txn->nr_ops; i++) {
		struct ceph_transaction_op *txn_op = txn->ops[i];

		if (txn_op->type == TXN_OP_OSD)
			ret = execute_wr_osd_op(store, txn_op);
		else
			ret = execute_trans_op(store, txn_op);
		if (ret)
			break;
	}

	return ret;
}

static void destroy_blocks(struct ceph_memstore_obj *obj)
{
	struct ceph_memstore_blk *blk;

	while ((blk = rb_entry_safe(rb_first(&obj->blocks),
				    typeof(*blk), node))) {
		erase_object_block(&obj->blocks, blk);
		__free_pages(blk->page, MEMSTORE_BLOCK_SHIFT - PAGE_SHIFT);
		kfree(blk);
	}
}

static void __destroy_omap(struct rb_root *root)
{
	struct ceph_memstore_omap_ent *ome;

	while ((ome = rb_entry_safe(rb_first(root),
				    typeof(*ome), node))) {
		erase_omap_entry(root, ome);
		ceph_pagelist_release(ome->val_pl);
		kfree(ome->key);
		kfree(ome);
	}
}

static void destroy_omap(struct ceph_memstore_obj *obj)
{
	__destroy_omap(&obj->omap);
}

static void destroy_xattrs(struct ceph_memstore_obj *obj)
{
	__destroy_omap(&obj->xattrs);
}

static void destroy_objects(struct ceph_memstore_coll *coll)
{
	struct ceph_memstore_obj *obj;

	while ((obj = rb_entry_safe(rb_first(&coll->objects),
				    typeof(*obj), node))) {
		destroy_blocks(obj);
		destroy_omap(obj);
		destroy_xattrs(obj);
		erase_object(&coll->objects, obj);
		kfree(obj);
	}
}

static void destroy_collections(struct ceph_memstore *store)
{
	struct ceph_memstore_coll *coll;

	while ((coll = rb_entry_safe(rb_first(&store->colls),
				     typeof(*coll), node))) {
		destroy_objects(coll);
		erase_collection(&store->colls, coll);
		kfree(coll);
	}
}

static void destroy_store(struct ceph_store *s)
{
	struct ceph_memstore *store;

	store = container_of(s, typeof(*store), s);
	destroy_collections(store);
	kfree(store);
}

static struct ceph_store_ops memstore_ops = {
	.open_collection     = open_collection,
	.create_collection   = create_collection,
	.execute_ro_osd_op   = execute_ro_osd_op,
	.execute_transaction = execute_transaction,
	.destroy             = destroy_store,
};

struct ceph_store *ceph_memstore_create(struct ceph_options *opt)
{
	struct ceph_memstore *store;

	store = kmalloc(sizeof(*store), GFP_KERNEL);
	if (!store)
		return ERR_PTR(-ENOMEM);

	store->s.ops = &memstore_ops;
	store->s.opt = opt;
	store->colls = RB_ROOT;

	return &store->s;
}
