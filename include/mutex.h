/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MUTEX_H
#define _MUTEX_H

/*
 * Actually does absolutely nothing, but validates correctness
 */

struct mutex {
	int locked;
};

static inline void mutex_init(struct mutex *mutex)
{
	mutex->locked = 0;
}

static inline void mutex_lock(struct mutex *mutex)
{
	/* In our UP non-preemtible environment locked should not be observed */
	WARN_ON(mutex->locked);
	mutex->locked = 1;
}

static inline void mutex_unlock(struct mutex *mutex)
{
	WARN_ON(mutex->locked != 1);
	mutex->locked = 0;
}

static inline bool mutex_is_locked(struct mutex *mutex)
{
	return mutex->locked;
}

#endif
