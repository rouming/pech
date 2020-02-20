#include "mempool.h"

/*
 * Keep it simple for now.
 */

mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			  mempool_free_t *free_fn, void *pool_data)
{
	mempool_t *pool;

	pool = calloc(1, sizeof(*pool));
	if (unlikely(!pool))
		return NULL;

	pool->nr        = 0;
	pool->alloc     = alloc_fn;
	pool->free      = free_fn;
	pool->pool_data = pool_data;

	return pool;
}

void mempool_destroy(mempool_t *pool)
{
	WARN_ON(pool->nr);
	free(pool);
}

void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	pool->nr++;
	return pool->alloc(gfp_mask, pool->pool_data);
}

void mempool_free(void *element, mempool_t *pool)
{
	pool->free(element, pool->pool_data);
	pool->nr--;
}

/*
 * A commonly used alloc and free fn.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	return kmem_cache_alloc(mem, gfp_mask);
}

void mempool_free_slab(void *element, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	kmem_cache_free(mem, element);
}
