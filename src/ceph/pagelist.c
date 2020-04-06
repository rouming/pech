// SPDX-License-Identifier: GPL-2.0
#include "module.h"
#include "gfp.h"
#include "slab.h"
//#include <linux/pagemap.h>
//#include <linux/highmem.h>
#include "ceph/pagelist.h"

struct ceph_pagelist *ceph_pagelist_alloc(gfp_t gfp_flags)
{
	struct ceph_pagelist *pl;

	pl = kmalloc(sizeof(*pl), gfp_flags);
	if (!pl)
		return NULL;

	INIT_LIST_HEAD(&pl->head);
	pl->mapped_tail = NULL;
	pl->length = 0;
	pl->room = 0;
	INIT_LIST_HEAD(&pl->free_list);
	pl->num_pages_free = 0;
	refcount_set(&pl->refcnt, 1);

	return pl;
}
EXPORT_SYMBOL(ceph_pagelist_alloc);

static void ceph_pagelist_unmap_tail(struct ceph_pagelist *pl)
{
	if (pl->mapped_tail) {
		struct page *page = list_entry(pl->head.prev, struct page, lru);
		kunmap(page);
		pl->mapped_tail = NULL;
	}
}

void ceph_pagelist_release(struct ceph_pagelist *pl)
{
	if (!refcount_dec_and_test(&pl->refcnt))
		return;
	ceph_pagelist_unmap_tail(pl);
	while (!list_empty(&pl->head)) {
		struct page *page = list_first_entry(&pl->head, struct page,
						     lru);
		list_del(&page->lru);
		__free_page(page);
	}
	ceph_pagelist_free_reserve(pl);
	kfree(pl);
}
EXPORT_SYMBOL(ceph_pagelist_release);

static int ceph_pagelist_addpage(struct ceph_pagelist *pl)
{
	struct page *page;

	if (!pl->num_pages_free) {
		page = __page_cache_alloc(GFP_NOFS);
	} else {
		page = list_first_entry(&pl->free_list, struct page, lru);
		list_del(&page->lru);
		--pl->num_pages_free;
	}
	if (!page)
		return -ENOMEM;
	pl->room += PAGE_SIZE;
	ceph_pagelist_unmap_tail(pl);
	list_add_tail(&page->lru, &pl->head);
	pl->mapped_tail = kmap(page);
	return 0;
}

int ceph_pagelist_append(struct ceph_pagelist *pl, const void *buf, size_t len)
{
	while (pl->room < len) {
		size_t bit = pl->room;
		int ret;

		memcpy(pl->mapped_tail + (pl->length & ~PAGE_MASK),
		       buf, bit);
		pl->length += bit;
		pl->room -= bit;
		buf += bit;
		len -= bit;
		ret = ceph_pagelist_addpage(pl);
		if (ret)
			return ret;
	}

	memcpy(pl->mapped_tail + (pl->length & ~PAGE_MASK), buf, len);
	pl->length += len;
	pl->room -= len;
	return 0;
}
EXPORT_SYMBOL(ceph_pagelist_append);

int ceph_pagelist_copy_from_page(struct ceph_pagelist *pl, struct page *page,
				 size_t len)
{
	void *addr;
	int ret;

	addr = kmap_atomic(page);
	ret = ceph_pagelist_append(pl, addr, len);
	kunmap_atomic(addr);

	return ret;
}
EXPORT_SYMBOL(ceph_pagelist_copy_from_page);

/* Allocate enough pages for a pagelist to append the given amount
 * of data without without allocating.
 * Returns: 0 on success, -ENOMEM on error.
 */
int ceph_pagelist_reserve(struct ceph_pagelist *pl, size_t space)
{
	if (space <= pl->room)
		return 0;
	space -= pl->room;
	space = (space + PAGE_SIZE - 1) >> PAGE_SHIFT;   /* conv to num pages */

	while (space > pl->num_pages_free) {
		struct page *page = __page_cache_alloc(GFP_NOFS);
		if (!page)
			return -ENOMEM;
		list_add_tail(&page->lru, &pl->free_list);
		++pl->num_pages_free;
	}
	return 0;
}
EXPORT_SYMBOL(ceph_pagelist_reserve);

int ceph_pagelist_truncate(struct ceph_pagelist *pl, size_t length)
{
	struct page *page, *tmp;
	unsigned int n_page, last_page;

	if (length > pl->length)
		/* Do not expand, only truncate */
		return -EINVAL;

	if (length == pl->length)
		/* Nothing to do */
		return 0;

	if (PAGE_ALIGN(length) == PAGE_ALIGN(pl->length)) {
		/* Same page */
		goto end;
	}

	ceph_pagelist_unmap_tail(pl);

	n_page = 0;
	last_page = ALIGN_DOWN(length, PAGE_SIZE) >> PAGE_SHIFT;
	list_for_each_entry_safe(page, tmp, &pl->head, lru) {
		if (n_page++ < last_page)
			continue;

		if (!pl->mapped_tail) {
			/* Last page */
			pl->mapped_tail = kmap(page);
		} else {
			/* Move everything to free list next after last page */
			list_move(&page->lru, &pl->free_list);
			++pl->num_pages_free;
		}
	}
end:
	pl->length = length;
	pl->room = PAGE_SIZE - (pl->length & ~PAGE_MASK);

	return 0;
}
EXPORT_SYMBOL(ceph_pagelist_truncate);

/* Free any pages that have been preallocated. */
int ceph_pagelist_free_reserve(struct ceph_pagelist *pl)
{
	while (!list_empty(&pl->free_list)) {
		struct page *page = list_first_entry(&pl->free_list,
						     struct page, lru);
		list_del(&page->lru);
		__free_page(page);
		--pl->num_pages_free;
	}
	BUG_ON(pl->num_pages_free);
	return 0;
}
EXPORT_SYMBOL(ceph_pagelist_free_reserve);

int ceph_pagelist_copy_from_buffer(struct ceph_pagelist *pl, const void *buf,
				   size_t length, off_t off_inpg)
{
	struct page *page;
	size_t to_append;
	off_t off_inbuf;
	void *addr;
	int ret;

	if (pl->length < off_inpg)
		/* Do not handle gaps */
		return -EINVAL;

	to_append = 0;
	if (pl->length < off_inpg + length) {
		to_append = (off_inpg + length) - pl->length;
		ret = ceph_pagelist_reserve(pl, to_append);
		if (ret)
			return ret;
	}

	/* Limit to what we need to copy */
	length = min(length, pl->length - off_inpg);

	off_inbuf = 0;
	list_for_each_entry(page, &pl->head, lru) {
		size_t len;

		if (!length)
			break;

		if (off_inpg >= PAGE_SIZE) {
			off_inpg -= PAGE_SIZE;
			continue;
		}

		len = min(length, PAGE_SIZE - off_inpg);
		addr = kmap_atomic(page);
		memcpy(addr + off_inpg, buf + off_inbuf, len);
		kunmap_atomic(addr);

		length -= len;
		off_inbuf += len;
		off_inpg = 0;
	}

	if (to_append) {
		ret = ceph_pagelist_append(pl, buf + off_inbuf, to_append);
		/* Memory should be reserved already, no errors expected */
		WARN_ON(ret);
	}

	return 0;
}
EXPORT_SYMBOL(ceph_pagelist_copy_from_buffer);

int ceph_pagelist_copy_from_cursor(struct ceph_pagelist *pl,
				   struct ceph_msg_data_cursor *cursor,
				   size_t length)
{
	struct page *page;
	size_t to_copy;
	void *addr;
	int ret;

	if (pl->length < length) {
		size_t to_append = length - pl->length;
		ret = ceph_pagelist_reserve(pl, to_append);
		if (ret)
			return ret;
	}

	to_copy = length;
	list_for_each_entry(page, &pl->head, lru) {
		size_t len;

		if (!to_copy)
			break;

		len = min(to_copy, PAGE_SIZE);
		addr = kmap_atomic(page);
		ret = ceph_msg_data_cursor_copy(cursor, addr, len);
		kunmap_atomic(addr);
		if (ret)
			goto end;

		to_copy -= len;
	}

	if (to_copy) {
		size_t len;

		ret = ceph_pagelist_addpage(pl);
		/* Memory should be reserved already, no errors expected */
		WARN_ON(ret);

		len = min(to_copy, PAGE_SIZE);
		ret = ceph_msg_data_cursor_copy(cursor, pl->mapped_tail, len);
		if (ret)
			goto end;

		to_copy -= len;
	}

end:
	pl->length = max(pl->length, length - to_copy);
	pl->room = PAGE_SIZE - (pl->length & ~PAGE_MASK);

	return ret;

}
EXPORT_SYMBOL(ceph_pagelist_copy_from_cursor);
