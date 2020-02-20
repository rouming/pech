/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _WORKQUEUE_H
#define _WORKQUEUE_H

#include "list.h"
#include "timer.h"

enum {
	WQ_UNBOUND		= 1 << 1, /* not bound to any cpu */
	WQ_MEM_RECLAIM		= 1 << 3, /* may be used for memory reclaim */

	__WQ_ORDERED		= 1 << 17, /* internal: workqueue is ordered */
	__WQ_LEGACY		= 1 << 18, /* internal: create*_workqueue() */
	__WQ_ORDERED_EXPLICIT	= 1 << 19, /* internal: alloc_ordered_workqueue() */
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

/**
 * alloc_ordered_workqueue - allocate an ordered workqueue
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags (only WQ_FREEZABLE and WQ_MEM_RECLAIM are meaningful)
 * @args...: args for @fmt
 *
 * Allocate an ordered workqueue.  An ordered workqueue executes at
 * most one work item at any given time in the queued order.  They are
 * implemented as unbound workqueues with @max_active of one.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
#define alloc_ordered_workqueue(fmt, flags, args...)			\
	alloc_workqueue(fmt, WQ_UNBOUND | __WQ_ORDERED |		\
			__WQ_ORDERED_EXPLICIT | (flags), 1, ##args)

#define create_workqueue(name)						\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, 1, (name))
#define create_freezable_workqueue(name)				\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_FREEZABLE | WQ_UNBOUND |	\
			WQ_MEM_RECLAIM, 1, (name))
#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, name)

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

/**
 * schedule_delayed_work - put work task in global workqueue after delay
 * @dwork: job to be done
 * @delay: number of jiffies to wait or 0 for immediate execution
 *
 * After waiting for a given time this puts a job in the kernel-global
 * workqueue.
 */
static inline bool schedule_delayed_work(struct delayed_work *dwork,
					 unsigned long delay)
{
	return queue_delayed_work(system_wq, dwork, delay);
}

#endif
