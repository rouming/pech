/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __FS_CEPH_PAGELIST_H
#define __FS_CEPH_PAGELIST_H

//#include <asm/byteorder.h>
#include "refcount.h"
#include "list.h"
#include "types.h"
#include "messenger.h"

struct ceph_pagelist {
	struct list_head head;
	void *mapped_tail;
	size_t length;
	size_t room;
	struct list_head free_list;
	size_t num_pages_free;
	refcount_t refcnt;
};

struct ceph_pagelist *ceph_pagelist_alloc(gfp_t gfp_flags);

extern void ceph_pagelist_release(struct ceph_pagelist *pl);

extern int ceph_pagelist_append(struct ceph_pagelist *pl, const void *d, size_t l);

extern int ceph_pagelist_copy_from_page(struct ceph_pagelist *pl,
					struct page *page, size_t len);

extern int ceph_pagelist_reserve(struct ceph_pagelist *pl, size_t space);

extern int ceph_pagelist_truncate(struct ceph_pagelist *pl, size_t length);

extern int ceph_pagelist_free_reserve(struct ceph_pagelist *pl);

extern int ceph_pagelist_copy_from_buffer(struct ceph_pagelist *pl,
					  const void *buf, size_t length,
					  off_t off);
extern int ceph_pagelist_copy_from_cursor(struct ceph_pagelist *pl,
					  struct ceph_msg_data_cursor *cur,
					  size_t len);

static inline int ceph_pagelist_encode_64(struct ceph_pagelist *pl, u64 v)
{
	__le64 ev = cpu_to_le64(v);
	return ceph_pagelist_append(pl, &ev, sizeof(ev));
}
static inline int ceph_pagelist_encode_32(struct ceph_pagelist *pl, u32 v)
{
	__le32 ev = cpu_to_le32(v);
	return ceph_pagelist_append(pl, &ev, sizeof(ev));
}
static inline int ceph_pagelist_encode_16(struct ceph_pagelist *pl, u16 v)
{
	__le16 ev = cpu_to_le16(v);
	return ceph_pagelist_append(pl, &ev, sizeof(ev));
}
static inline int ceph_pagelist_encode_8(struct ceph_pagelist *pl, u8 v)
{
	return ceph_pagelist_append(pl, &v, 1);
}
static inline int ceph_pagelist_encode_32_at_offset(struct ceph_pagelist *pl,
						    u32 v, off_t off)
{
	__le32 ev = cpu_to_le32(v);
	return ceph_pagelist_copy_from_buffer(pl, &ev, sizeof(ev), off);
}
static inline int ceph_pagelist_encode_string(struct ceph_pagelist *pl,
					      char *s, u32 len)
{
	int ret = ceph_pagelist_encode_32(pl, len);
	if (ret)
		return ret;
	if (len)
		return ceph_pagelist_append(pl, s, len);
	return 0;
}
static inline int ceph_pagelist_encode_pagelist(struct ceph_pagelist *pl,
						const struct ceph_pagelist *src,
						bool encode_length)
{
	size_t length = src->length;
	struct page *page;
	int ret;

	if (encode_length) {
		ret = ceph_pagelist_encode_32(pl, length);
		if (ret)
			return ret;
	}
	list_for_each_entry(page, &src->head, lru) {
		ret = ceph_pagelist_copy_from_page(pl, page,
					length & ~PAGE_MASK);
		if (ret)
			return ret;
		length -= length & ~PAGE_MASK;
	}
	return 0;
}

#endif
