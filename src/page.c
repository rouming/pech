#include "types.h"
#include "page.h"

unsigned char zeroes[PAGE_SIZE];

struct page empty_zero_page = {
	.lru = LIST_HEAD_INIT(empty_zero_page.lru),
	.ptr = zeroes
};

struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	//XXX
	return NULL;
}

void __free_pages(struct page *page, unsigned int order)
{
	//XXX
}
