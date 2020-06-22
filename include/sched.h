/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SCHED_H
#define _SCHED_H

#include "types.h"

/*
 * wake flags
 */
#define WF_SYNC			0x01		/* Waker goes to sleep after wakeup */
#define WF_HIGHPRI		0x02		/* Put the task to the head */


/* Used in tsk->state: */
#define TASK_RUNNING			0x0000
#define TASK_INTERRUPTIBLE		0x0001
#define TASK_UNINTERRUPTIBLE		0x0002
#define __TASK_STOPPED			0x0004
#define __TASK_TRACED			0x0008
/* Used in tsk->exit_state: */
#define EXIT_DEAD			0x0010
#define EXIT_ZOMBIE			0x0020
#define EXIT_TRACE			(EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->state again: */
#define TASK_PARKED			0x0040
#define TASK_DEAD			0x0080
#define TASK_WAKEKILL			0x0100
#define TASK_WAKING			0x0200
#define TASK_NOLOAD			0x0400
#define TASK_NEW			0x0800
#define TASK_STATE_MAX			0x1000

/* Convenience macros for the sake of set_current_state: */
#define TASK_KILLABLE			(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED			(TASK_WAKEKILL | __TASK_TRACED)

#define TASK_IDLE			(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

/* Convenience macros for the sake of wake_up(): */
#define TASK_NORMAL			(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)

/* get_task_state(): */
#define TASK_REPORT			(TASK_RUNNING | TASK_INTERRUPTIBLE | \
					 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
					 __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
					 TASK_PARKED)

/*
 * Per process flags
 */
#define PF_WQ_WORKER        0x00000020	/* I'm a workqueue worker */
#define PF_KTHREAD          0x00200000	/* I am a kernel thread */

typedef int (task_func_t)(void *arg);

struct task_struct;

extern __thread struct task_struct *current;
extern __thread int preempt_count;
extern __thread bool need_resched;

extern void __set_current_state(long state);
#define set_current_state(s) __set_current_state(s)
extern int get_current_flags(void);
extern void set_current_flags(int flags);
extern void clear_current_flags(int flags);

extern void *task_data(struct task_struct *task);

extern void init_sched(void);
extern struct task_struct *task_create(task_func_t *func, void *param);
extern unsigned int tasks_to_run(void);

extern void get_task_struct(struct task_struct *task);
extern void put_task_struct(struct task_struct *task);

extern bool kthread_should_stop(struct task_struct *task);
extern int kthread_stop(struct task_struct *task);
extern int __wake_up_process(struct task_struct *task, int wake_flags);
extern int wake_up_process(struct task_struct *task);

extern void schedule(void);
extern long schedule_timeout(long timeout);
extern long io_schedule_timeout(long timeout);

extern void msleep(unsigned int msecs);

static inline void preempt_disable(void)
{
	preempt_count++;
}

static inline void preempt_enable(void)
{
	BUG_ON(!preempt_count);
	preempt_count--;
	if (!preempt_count && need_resched)
		schedule();
}

static inline bool preemptable(void)
{
	return !preempt_count;
}

static inline void preempt_schedule(void)
{
	need_resched = true;
	if (!preemptable())
		return;

	schedule();
}

static inline int signal_pending(struct task_struct *p)
{
	/* Pretend something is pending if we need to stop a task */
	return unlikely(kthread_should_stop(p));
}

static inline int __fatal_signal_pending(struct task_struct *p)
{
	/* We do not have normal signals */
	return 0;
}

static inline int fatal_signal_pending(struct task_struct *p)
{
	return signal_pending(p) && __fatal_signal_pending(p);
}

static inline int signal_pending_state(long state, struct task_struct *p)
{
	if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
		return 0;
	if (!signal_pending(p))
		return 0;

	return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
}

#endif
