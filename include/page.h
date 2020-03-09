/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PAGE_H
#define _PAGE_H

#include "list.h"

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

struct page {
	struct list_head lru;
	void *ptr;
};

extern unsigned char zeroes[PAGE_SIZE];
extern struct page empty_zero_page;

#define ZERO_PAGE(vaddr) &empty_zero_page

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

#define page_address(p) ((p)->ptr)

#define kmap(p) ((p)->ptr)
#define kunmap(p) ((void)p)

#define kmap_atomic(p) ((p)->ptr)
#define kunmap_atomic(addr)

static inline int page_count(struct page *page)
{
	return 0;
}

#define PageSlab(p) (1)

#define get_page(p)
#define put_page(p)

extern struct page *alloc_pages(gfp_t gfp_mask, unsigned int order);

static inline struct page *__page_cache_alloc(gfp_t gfp)
{
	return alloc_pages(gfp, 0);
}

extern void __free_pages(struct page *page, unsigned int order);

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr), 0)

#define set_page_dirty_lock(p)

#endif
