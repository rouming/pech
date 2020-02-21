/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

struct semaphore {};

#define DEFINE_SEMAPHORE(name)

#define sema_init(...)

#define down(sem) ((void)sem)
#define down_interruptible(sem) ((void)sem)
#define down_killable(sem) ((void)sem)
#define down_trylock(sem) ((void)sem)
#define down_timeout(sem, jiffies) ((void)sem)
#define up(sem) ((void)sem)

#endif
