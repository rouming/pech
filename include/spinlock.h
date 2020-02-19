/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SPINLOCK_H
#define _SPINLOCK_H

struct spinlock {};
typedef struct spinlock spinlock_t;

#define DEFINE_SPINLOCK(x)	spinlock_t x

#define spin_lock_init(s);
#define spin_lock(s)
#define spin_unlock(s)

#define spin_lock_irqsave(s, f)
#define spin_unlock_irqrestore(s, f)

#endif
