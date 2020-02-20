/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

struct semaphore {};

#define DEFINE_SEMAPHORE(name)

#define sema_init(...)

#define down(sem)
#define down_interruptible(sem)
#define down_killable(sem)
#define down_trylock(sem)
#define down_timeout(sem, jiffies)
#define up(sem)

#endif
