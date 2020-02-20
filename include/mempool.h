/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MEMPOOL_H
#define _MEMPOOL_H

#include "types.h"

struct mempool {};
typedef struct mempool mempool_t;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);

extern void mempool_destroy(mempool_t *pool);
extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
extern void mempool_free(void *element, mempool_t *pool);

#define mempool_create_slab_pool(min, kc)		\
	mempool_create(min, NULL, NULL, kc)

#endif
