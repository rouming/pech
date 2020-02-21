/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RWSEM_H
#define _RWSEM_H

struct rw_semaphore {};

#define init_rwsem(sem) ((void)sem)
#define up_read(sem) ((void)sem)
#define down_read(sem) ((void)sem)
#define down_write(sem) ((void)sem)
#define up_write(sem) ((void)sem)
#define rwsem_is_locked(sem) (0)
#define downgrade_write(sem) ((void)sem)
#define down_read_trylock(...) (1)

#endif
