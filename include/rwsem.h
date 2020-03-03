/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RWSEM_H
#define _RWSEM_H

#include "types.h"
#include "bug.h"

struct rw_semaphore {
	struct wait_queue_head wq;
	struct task_struct *wr_owner;
	int rd_locked;
};

static inline void init_rwsem(struct rw_semaphore *rwsem)
{
	init_waitqueue_head(&rwsem->wq);
	rwsem->wr_owner = NULL;
	rwsem->rd_locked = 0;
}

static inline void up_read(struct rw_semaphore *rwsem)
{
	if (WARN_ON(!rwsem->rd_locked))
		return;
	if (WARN_ON(rwsem->wr_owner))
		return;

	if (!--rwsem->rd_locked)
		wake_up(&rwsem->wq);
}

static inline void down_read(struct rw_semaphore *rwsem)
{
	wait_event(rwsem->wq, !rwsem->wr_owner);
	rwsem->rd_locked++;
}

static inline void up_write(struct rw_semaphore *rwsem)
{
	if (WARN_ON(!rwsem->wr_owner))
		return;

	rwsem->wr_owner = NULL;
	wake_up(&rwsem->wq);
}

static inline void down_write(struct rw_semaphore *rwsem)
{
	if (rwsem->wr_owner) {
		/* Wait for writer */
		wait_event(rwsem->wq, !rwsem->wr_owner);
		WARN_ON(rwsem->rd_locked);
		rwsem->wr_owner = current;
		return;
	}
	/* Wait for readers */
	wait_event(rwsem->wq, !rwsem->rd_locked);
	WARN_ON(rwsem->wr_owner);
	rwsem->wr_owner = current;
}

static inline void downgrade_write(struct rw_semaphore *rwsem)
{
	WARN_ON(!rwsem->wr_owner);
	WARN_ON(rwsem->rd_locked);

	rwsem->wr_owner = NULL;
	rwsem->rd_locked = 1;
}

static inline bool down_read_trylock(struct rw_semaphore *rwsem)
{
	if (rwsem->wr_owner)
		return false;

	down_read(rwsem);
	return true;
}

static inline bool rwsem_is_locked(struct rw_semaphore *rwsem)
{
	return rwsem->rd_locked || rwsem->wr_owner;
}

#endif
