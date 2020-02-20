/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MEMPOOL_H
#define _MEMPOOL_H

#include "types.h"
#include "slab.h"

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

struct mempool {
	mempool_alloc_t *alloc;
	mempool_free_t  *free;
	void            *pool_data;
	int             nr;
};
typedef struct mempool mempool_t;

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);
extern void mempool_destroy(mempool_t *pool);
extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab cache that is passed in through pool_data.
 * Note: the slab cache may not have a ctor function.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);

static inline mempool_t *
mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
{
	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
			      (void *) kc);
}

#endif
