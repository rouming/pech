#ifndef _TIMER_H
#define _TIMER_H

#include "types.h"
#include "list.h"
#include "rbtree.h"

struct timer;

typedef void (*timer_func_t)(struct timer *);

struct timer {
	timer_func_t     func;
	struct list_head list;
	struct rb_node   node;
	unsigned long    expire;
};

#define __TIMER_INITIALIZER(t) {				\
	.list = LIST_HEAD_INIT((t).list),			\
	.node = __RB_NODE_INITIALIZER((t).node),		\
	.func = NULL,						\
	}

#define INIT_TIMER(t) do {					\
	INIT_LIST_HEAD(&(t)->list);				\
	RB_CLEAR_NODE(&(t)->node);				\
	} while (0)

extern unsigned long timer_calc_msecs_timeout(void);
extern void timer_run(void);

extern void timer_add(struct timer *timer, unsigned long jexpire,
					  timer_func_t func);
extern bool timer_mod(struct timer *timer, unsigned long jexpire);
extern bool timer_del(struct timer *timer);

#endif
