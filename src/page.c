#include "types.h"
#include "page.h"
#include "gfp.h"

#define MAX_ORDER          11
#define MAX_SZ_IN_ORDER    32<<20 /* 32mb, should be ^2 */

unsigned char zeroes[PAGE_SIZE];

struct page empty_zero_page = {
	.lru = LIST_HEAD_INIT(empty_zero_page.lru),
	.ptr = zeroes
};

struct free_pages {
	struct list_head lru_pages;
	int              nr_lru_pages;
};

#define DECLARE_ORDER(n)						\
	[n] = {								\
		.lru_pages = LIST_HEAD_INIT(orders[n].lru_pages),	\
	}

/* XXX Not thread safe */
static struct free_pages orders[] = {
	DECLARE_ORDER(0),
	DECLARE_ORDER(1),
	DECLARE_ORDER(2),
	DECLARE_ORDER(3),
	DECLARE_ORDER(4),
	DECLARE_ORDER(5),
	DECLARE_ORDER(6),
	DECLARE_ORDER(7),
	DECLARE_ORDER(8),
	DECLARE_ORDER(9),
	DECLARE_ORDER(10),
	DECLARE_ORDER(11),
};

void init_pages(void)
{
}

void deinit_pages(void)
{
	int order;

	for (order = 0; order < ARRAY_SIZE(orders); order++) {
		struct free_pages *free_pages = &orders[order];

		while (!list_empty(&free_pages->lru_pages)) {
			struct page *page;

			page = list_first_entry(&free_pages->lru_pages,
						typeof(*page), lru);
			list_del(&page->lru);
			__free_pages(page, order);
		}
	}
}

/**
 * alloc_pages() - allocates 1<<order of pages.
 *
 * In order to minimize allocations the layout is the following:
 *
 *    PAGE_SIZE PAGE_SIZE ...|page#0 page#1 ...
 *    ^         ^_____________|______|
 *    |_______________________|
 *
 */
struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	unsigned int i, num = 1 << order;
	unsigned int footer_sz;
	struct page *first_page, *page;
	struct free_pages *free_pages;
	void *ptr;

	BUILD_BUG_ON(ARRAY_SIZE(orders) != MAX_ORDER + 1);

       if (order > MAX_ORDER)
               goto alloc;

	free_pages = &orders[order];
	if (!list_empty(&free_pages->lru_pages)) {
		/* Fast path */

		if (WARN_ON(!free_pages->nr_lru_pages))
			goto alloc;

		free_pages->nr_lru_pages--;
		page = list_first_entry(&free_pages->lru_pages,
					typeof(*page), lru);
		list_del_init(&page->lru);

		if (gfp_mask & __GFP_ZERO)
			memset(page_address(page), 0, num * PAGE_SIZE);

		return page;
	}
alloc:
	footer_sz = num * sizeof(*page);
	ptr = malloc(footer_sz + num * PAGE_SIZE);
	if (!ptr)
		return NULL;

	if (gfp_mask & __GFP_ZERO)
		memset(ptr, 0, num * PAGE_SIZE);

	first_page = ptr + num * PAGE_SIZE;

	/* Fill in header */
	for (i = 0; i < num; i++) {
		page = first_page + i;
		INIT_LIST_HEAD(&page->lru);
		page->ptr = ptr + i * PAGE_SIZE;
	}

	return first_page;
}

void __free_pages(struct page *page, unsigned int order)
{
	struct free_pages *free_pages;
	unsigned int num = 1 << order;
	unsigned int max_nr;

       if (order > MAX_ORDER)
	       /* Directly to free */
               goto free;

	free_pages = &orders[order];

	max_nr = MAX_SZ_IN_ORDER >> PAGE_SHIFT >> order;
	if (free_pages->nr_lru_pages < max_nr) {
		/* Fast path */

		free_pages->nr_lru_pages++;
		list_add(&page->lru, &free_pages->lru_pages);
		return;
	}
free:
	free((void *)page - num * PAGE_SIZE);
}
