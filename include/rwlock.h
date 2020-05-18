/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RWLOCK_H
#define _RWLOCK_H

#include "sched.h"

#define write_lock_bh(...)			\
	({ preempt_disable(); })
#define write_unlock_bh(...)			\
	({ preempt_enable(); })

#define read_lock_bh(...)			\
	({ preempt_disable(); })
#define read_unlock_bh(...)			\
	({ preempt_enable(); })

#endif
