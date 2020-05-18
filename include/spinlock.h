/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SPINLOCK_H
#define _SPINLOCK_H

#include "sched.h"

struct spinlock {};
typedef struct spinlock spinlock_t;

#define DEFINE_SPINLOCK(x)	__attribute__((__unused__)) spinlock_t x

#define spin_lock_init(s) ((void)s)
#define spin_lock(s)				\
	({ (void)s; preempt_disable(); })
#define spin_unlock(s)				\
	({ (void)s; preempt_enable(); })

#define spin_lock_irqsave(s, f)			\
	({ (void)s; preempt_disable(); })
#define spin_unlock_irqrestore(s, f)		\
	({ (void)s; preempt_enable(); })

#endif
