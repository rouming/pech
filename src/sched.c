#include <stdlib.h>
#include <ucontext.h>
#define USE_VALGRIND
#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include "types.h"
#include "sched.h"
#include "wait.h"
#include "completion.h"
#include "timedef.h"
#include "timer.h"
#include "err.h"

#define TASK_STACK_SIZE (1<<12)

struct task_struct {
	struct list_head tsk_list;
	int         tsk_ref;
	ucontext_t  tsk_ctx;
	void	    *tsk_stack;
	task_func_t *tsk_func;
	void        *tsk_arg;
	long        tsk_state;
	int         tsk_flags;
	struct completion
		    tsk_exited;
	bool        tsk_should_stop;
	int         tsk_exit_code;
};

__thread struct task_struct *current;
static __thread struct task_struct idle_task;

void init_sched(void)
{
	BUG_ON(current);
	INIT_LIST_HEAD(&idle_task.tsk_list);
	current = &idle_task;
	current->tsk_state = TASK_RUNNING;
}

void __set_current_state(long state)
{
	current->tsk_state = state;
}

int get_current_flags(void)
{
	return current->tsk_flags;
}

void set_current_flags(int flags)
{
	current->tsk_flags |= flags;
}

void clear_current_flags(int flags)
{
	current->tsk_flags &= ~flags;
}

void *task_data(struct task_struct *task)
{
	return task->tsk_arg;
}

static struct task_struct *task_alloc(task_func_t *func, void *arg,
				      size_t stack_sz)
{
	struct task_struct *task;

	task = calloc(1, sizeof(*task));
	if (!task)
		return NULL;

	task->tsk_stack = malloc(stack_sz);
	if (!task->tsk_stack) {
		free(task);
		return NULL;
	}
#ifdef USE_VALGRIND
	VALGRIND_STACK_REGISTER(task->tsk_stack, task->tsk_stack + stack_sz);
#endif
	init_completion(&task->tsk_exited);
	task->tsk_func = func;
	task->tsk_arg = arg;
	task->tsk_state = TASK_NEW;
	task->tsk_ref = 1;

	return task;
}

static void task_destroy(struct task_struct *task)
{
	BUG_ON(task == &idle_task);
	BUG_ON(task->tsk_state != TASK_DEAD);
	BUG_ON(!list_empty(&task->tsk_list));
#ifdef USE_VALGRIND
	VALGRIND_STACK_DEREGISTER(task->tsk_stack);
#endif
	free(task->tsk_stack);
	free(task);
}

static void get_task_struct(struct task_struct *task)
{
	task->tsk_ref++;
}

static void put_task_struct(struct task_struct *task)
{
	if (!--task->tsk_ref)
		task_destroy(task);
}

static void task_switch_to(struct task_struct *from, struct task_struct *to)
{
	current = to;
	swapcontext(&from->tsk_ctx, &to->tsk_ctx);
}

/* workqueue.c  */
void wq_worker_running(struct task_struct *task);
void wq_worker_sleeping(struct task_struct *task);

void schedule(void)
{
	static __thread struct task_struct *dead_task;
	struct task_struct *next;

	if (current->tsk_flags & PF_WQ_WORKER)
		wq_worker_sleeping(current);

	next = list_first_entry_or_null(&current->tsk_list,
					struct task_struct, tsk_list);
	if (next) {
		if (current->tsk_state == TASK_DEAD)
			dead_task = current;

		if (current->tsk_state != TASK_RUNNING)
			list_del_init(&current->tsk_list);
		task_switch_to(current, next);
	} else {
		/* No tasks to execute */
		BUG_ON(current != &idle_task);
		BUG_ON(current == dead_task);
		BUG_ON(current->tsk_state != TASK_RUNNING);
	}
	if (dead_task) {
		BUG_ON(current == dead_task);
		put_task_struct(dead_task);
		dead_task = NULL;
	}
	if (current->tsk_flags & PF_WQ_WORKER)
		wq_worker_running(current);

}

union task_ptr {
	void *p;
	u32 i[2];
};

__attribute__ ((noreturn))
static void task_trampoline(int i0, int i1)
{
	union task_ptr ptr = {
		.i = { i0, i1 }
	};
	struct task_struct *task = ptr.p;
	int ret;

	ret = task->tsk_func(task->tsk_arg);
	task->tsk_exit_code = ret;
	task->tsk_state = TASK_DEAD;
	complete_all(&task->tsk_exited);
	schedule();
	BUG();
	__builtin_unreachable();
}

struct task_struct *task_create(task_func_t *func, void *param)
{
	struct task_struct *task;
	union task_ptr ptr;

	task = task_alloc(func, param, TASK_STACK_SIZE);
	if (unlikely(!task))
		return NULL;

	if (getcontext(&task->tsk_ctx) == -1)
		BUG();
	task->tsk_ctx.uc_stack.ss_sp = task->tsk_stack;
	task->tsk_ctx.uc_stack.ss_size = TASK_STACK_SIZE;
	task->tsk_ctx.uc_stack.ss_flags = 0;
	task->tsk_ctx.uc_link = NULL;
	task->tsk_state = TASK_IDLE;
	task->tsk_flags = PF_KTHREAD; /* no other threads here */
	INIT_LIST_HEAD(&task->tsk_list);

	ptr.p = task;
	makecontext(&task->tsk_ctx, (void (*)(void))task_trampoline,
		    2, ptr.i[0], ptr.i[1]);

	return task;
}

/*
 * Return 0 if no tasks, 1 if there is only one task and 2 if there are many
 * tasks to run.
 */
unsigned int tasks_to_run(void)
{
	if (list_empty(&idle_task.tsk_list))
		return 0;
	else if (list_is_singular(&idle_task.tsk_list))
		return 1;

	return 2;
}

static int
try_to_wake_up(struct task_struct *task, unsigned int state, int wake_flags)
{
	(void)wake_flags;

	if (!(task->tsk_state & state))
		return 0;

	task->tsk_state = TASK_RUNNING;
	list_move_tail(&task->tsk_list, &idle_task.tsk_list);

	return 1;
}

int wake_up_process(struct task_struct *p)
{
	return try_to_wake_up(p, TASK_NORMAL, 0);
}

struct sched_timer {
	struct timer timer;
	struct task_struct *task;
};

static void process_timer(struct timer *timer)
{
	struct sched_timer *sched_timer;

	sched_timer = container_of(timer, typeof(*sched_timer), timer);
	wake_up_process(sched_timer->task);
}

long schedule_timeout(long timeout)
{
	struct sched_timer t = {
		.task = current
	};
	unsigned long expire;
	int ret;

	expire = jiffies + timeout;

	timer_add(&t.timer, expire, process_timer);
	schedule();
	timer_del(&t.timer);

	timeout = expire - jiffies;

	return timeout < 0 ? 0 : timeout;
}

int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
			  void *key)
{
	return try_to_wake_up(curr->private, mode, wake_flags);
}

/*
 * This task is about to go to sleep on IO. Increment rq->nr_iowait so
 * that process accounting knows that this is a task in IO wait state.
 */
long __sched io_schedule_timeout(long timeout)
{
	long ret;

	ret = schedule_timeout(timeout);

	return ret;
}

/**
 * kthread_should_stop - should this kthread return now?
 *
 * When someone calls kthread_stop() on your kthread, it will be woken
 * and this will return true.  You should then return, and your return
 * value will be passed through to kthread_stop().
 */
bool kthread_should_stop(void)
{
	return current->tsk_should_stop;
}

/**
 * kthread_stop - stop a thread created by kthread_create().
 * @k: thread created by kthread_create().
 *
 * Sets kthread_should_stop() for @k to return true, wakes it, and
 * waits for it to exit. This can also be called after kthread_create()
 * instead of calling wake_up_process(): the thread will exit without
 * calling threadfn().
 *
 * If threadfn() may call do_exit() itself, the caller must ensure
 * task_struct can't go away.
 *
 * Returns the result of threadfn(), or %-EINTR if wake_up_process()
 * was never called.
 */
int kthread_stop(struct task_struct *task)
{
	int ret;

	get_task_struct(task);
	task->tsk_should_stop = true;
	wake_up_process(task);
	wait_for_completion(&task->tsk_exited);
	ret = task->tsk_exit_code;
	put_task_struct(task);

	return ret;
}
