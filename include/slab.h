/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SLAB_H
#define _SLAB_H

#include <stdlib.h>

#include "types.h"
#include "page.h"
#include "gfp.h"

#define kmalloc(size, gfp) malloc(size)
#define kzalloc(size, gfp) calloc(1, size)
#define kmalloc_array(n, size, flags) malloc(n * size)
#define kcalloc(n, size, flags) calloc(n, size)
#define krealloc(ptr, size, flags) realloc(ptr, size)
#define kfree(ptr) free(ptr)

#define kstrndup(s, len, flags) strndup(s, len)

#define kvmalloc(size, flags) malloc(size)
#define kvfree(ptr) free(ptr)

#define kfree_rcu(p, rcu) kfree(p)

static inline void *kmemdup(const void *buf, size_t len, unsigned long flags)
{
	void *copy;

	(void)flags;
	copy = malloc(len);
	if (!copy)
		return NULL;

	memcpy(copy, buf, len);
	return copy;
}

#define memalloc_noio_save() (0)
#define memalloc_noio_restore(v) ((void)v)

#define memalloc_nofs_save() (0)
#define memalloc_nofs_restore(v) ((void)v)

struct kmem_cache {
	const char * name;
	unsigned int size;
	int          alloced;
};

static inline
struct kmem_cache *kmem_cache_create(const char *name, unsigned int size,
				     unsigned int align, slab_flags_t flags,
				     void (*ctor)(void *))
{
	struct kmem_cache *cache;

	(void)flags;
	(void)ctor;

	cache = calloc(1, sizeof(*cache));
	if (unlikely(!cache))
		return NULL;

	cache->name = name;
	cache->size = size;

	return cache;
}


static inline
void kmem_cache_destroy(struct kmem_cache *c)
{
	if (unlikely(!c))
		return;

	WARN_ON(c->alloced);
	free(c);
}

static inline __malloc
void *kmem_cache_alloc(struct kmem_cache *c, gfp_t flags)
{
	void *mem;

	mem = malloc(c->size);
	if (unlikely(!mem))
		return NULL;

	c->alloced++;

	if (flags & __GFP_ZERO)
		memset(mem, 0, c->size);

	return mem;
}

static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
{
	return kmem_cache_alloc(k, flags | __GFP_ZERO);
}

static inline
void kmem_cache_free(struct kmem_cache *c, void *p)
{
	c->alloced--;
	free(p);
}

#define KMEM_CACHE(__struct, __flags)					\
		kmem_cache_create(#__struct, sizeof(struct __struct),	\
			__alignof__(struct __struct), (__flags), NULL)

#endif
