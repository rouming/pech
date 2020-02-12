/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

#include "list.h"
#include "timer.h"

enum {
	WQ_UNBOUND		= 1 << 1, /* not bound to any cpu */
	WQ_MEM_RECLAIM		= 1 << 3, /* may be used for memory reclaim */
};

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);

struct workqueue_struct;

struct work_struct {
	struct list_head        entry;  /* Entry in pool->workl_ist */
	struct workqueue_struct *wq;
	work_func_t             func;
	unsigned int            flags;
	int                     color;
};

struct delayed_work {
	struct work_struct work;
	struct timer       timer;
};

/* System WQ per uCPU */
extern __thread struct workqueue_struct *system_wq;

#define __WORK_INITIALIZER(n, f) {					\
	.entry	= { &(n).entry, &(n).entry },				\
	.wq = NULL,							\
	.func = (f),							\
	.flags = 0,							\
	.color = 0,							\
	}

#define __DELAYED_WORK_INITIALIZER(n, f) {				\
	.work = __WORK_INITIALIZER((n).work, (f)),			\
	.timer = __TIMER_INITIALIZER((n).timer)				\
	}

#define DECLARE_WORK(n, f)						\
	struct work_struct n = __WORK_INITIALIZER(n, f)

#define DECLARE_DELAYED_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f)

#define DECLARE_DEFERRABLE_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f)

#define INIT_WORK(_work, _func)						\
	do {								\
		(_work)->wq = NULL;					\
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
		(_work)->flags = 0;					\
		(_work)->color = 0;					\
	} while (0)

#define INIT_WORK_ONSTACK(_work, _func)					\
	INIT_WORK((_work), (_func))

#define INIT_DELAYED_WORK(_work, _func)					\
	do {								\
		INIT_WORK(&(_work)->work, (_func));			\
		INIT_TIMER(&(_work)->timer);				\
	} while (0)

#define INIT_DELAYED_WORK_ONSTACK(_work, _func)				\
	INIT_DELAYED_WORK(_work, _func)

extern void init_workqueue(void);
extern void deinit_workqueue(void);

extern struct workqueue_struct *alloc_workqueue(const char *fmt,
						unsigned int flags,
						int max_active, ...);
extern void destroy_workqueue(struct workqueue_struct *wq);
extern void flush_workqueue(struct workqueue_struct *wq);

extern bool queue_work(struct workqueue_struct *wq,
		       struct work_struct *work);
extern bool flush_work(struct work_struct *work);
extern bool cancel_work_sync(struct work_struct *work);

extern bool queue_delayed_work(struct workqueue_struct *wq,
			       struct delayed_work *dwork,
			       unsigned long delay);
extern bool flush_delayed_work(struct delayed_work *dwork);
extern bool cancel_delayed_work(struct delayed_work *dwork);
extern bool cancel_delayed_work_sync(struct delayed_work *gdwork);
extern bool mod_delayed_work(struct workqueue_struct *wq,
			     struct delayed_work *dwork,
			     unsigned long delay);

#endif
