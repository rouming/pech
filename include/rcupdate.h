/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RCUPDATE_H
#define _RCUPDATE_H

#include "types.h"

struct rcu_head {};

#define rcu_read_lock()
#define rcu_read_unlock()

#define rcu_dereference(p)				\
({							\
	/* Dependency order vs. p above. */		\
	typeof(p) ________p1 = READ_ONCE(p);		\
	((typeof(*p) __force __kernel *)(________p1));	\
})

#endif
