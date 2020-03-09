#include "types.h"
#include "page.h"
#include "gfp.h"

unsigned char zeroes[PAGE_SIZE];

struct page empty_zero_page = {
	.lru = LIST_HEAD_INIT(empty_zero_page.lru),
	.ptr = zeroes
};

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
	void *ptr;

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
	unsigned int num = 1 << order;

	free((void *)page - num * PAGE_SIZE);
}
