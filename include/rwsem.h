/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RWSEM_H
#define _RWSEM_H

struct rw_semaphore {};

#define init_rwsem(sem)
#define up_read(sem)
#define down_read(sem)
#define down_write(sem)
#define up_write(sem)
#define rwsem_is_locked(sem) (0)
#define downgrade_write(sem)
#define down_read_trylock(...) (1)

#endif
