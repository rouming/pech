/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MUTEX_H
#define _MUTEX_H

#include "wait.h"

struct mutex {
	struct wait_queue_head wq;
	struct task_struct *owner;
};

static inline void mutex_init(struct mutex *mutex)
{
	init_waitqueue_head(&mutex->wq);
	mutex->owner = NULL;
}

static inline void mutex_lock(struct mutex *mutex)
{
	if (WARN(mutex->owner == current,
		 "mutex: recursive lock %p\n", mutex))
		return;

	wait_event(mutex->wq, !mutex->owner);
	mutex->owner = current;
}

static inline void mutex_unlock(struct mutex *mutex)
{
	if (WARN(mutex->owner != current,
		 "mutex: task %p is not not owner %p, owner is %p\n",
		 current, mutex, mutex->owner))
		return;

	mutex->owner = NULL;
	wake_up(&mutex->wq);
}

static inline bool mutex_is_locked(struct mutex *mutex)
{
	return !!mutex->owner;
}

#endif
