#include "mempool.h"

mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			  mempool_free_t *free_fn, void *pool_data)
{
	//XXX
	return NULL;
}

void mempool_destroy(mempool_t *pool)
{
	//XXX
}

void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	//XXX
	return NULL;
}

void mempool_free(void *element, mempool_t *pool)
{
	//XXX
}
