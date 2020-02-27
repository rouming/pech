/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RWSEM_H
#define _RWSEM_H

#include "types.h"
#include "bug.h"

/*
 * Actually does absolutely nothing, but validates correctness
 */

struct rw_semaphore {
	int locked;
};

static inline void init_rwsem(struct rw_semaphore *rwsem)
{
	rwsem->locked = 0;
}

static inline void up_read(struct rw_semaphore *rwsem)
{
	WARN_ON(!rwsem->locked);
	rwsem->locked--;
}

static inline void down_read(struct rw_semaphore *rwsem)
{
	rwsem->locked++;
}

static inline void up_write(struct rw_semaphore *rwsem)
{
	WARN_ON(rwsem->locked != 1);
	rwsem->locked = 0;
}

static inline void down_write(struct rw_semaphore *rwsem)
{
	/* In our UP non-preemtible environment locked should not be observed */
	WARN_ON(rwsem->locked);
	rwsem->locked = 1;
}

static inline bool rwsem_is_locked(struct rw_semaphore *rwsem)
{
	return rwsem->locked;
}

static inline void downgrade_write(struct rw_semaphore *rwsem)
{
	WARN_ON(rwsem->locked != 1);
}

static inline bool down_read_trylock(struct rw_semaphore *rwsem)
{
	down_read(rwsem);
	/* In our UP non-preemtible environment always succeed */
	return true;
}

#endif
