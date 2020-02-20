// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/workqueue.c - generic async execution with shared worker pool
 *
 * Copyright (C) 2002		Ingo Molnar
 *
 *   Derived from the taskqueue/keventd code by:
 *     David Woodhouse <dwmw2@infradead.org>
 *     Andrew Morton
 *     Kai Petzke <wpp@marie.physik.tu-berlin.de>
 *     Theodore Ts'o <tytso@mit.edu>
 *
 * Copyright (C) 2010		SUSE Linux Products GmbH
 * Copyright (C) 2010		Tejun Heo <tj@kernel.org>
 * Copyright (C) 2020		Roman Penyaev <r.peniaev@gmail.com>
 *                              Rework for much simpler userspace case
 *
 * Please read Documentation/core-api/workqueue.rst for details.
 */

#include <stdlib.h>

#include "types.h"
#include "hashtable.h"
#include "err.h"
#include "sched.h"
#include "event.h"
#include "timedef.h"
#include "completion.h"
#include "workqueue.h"

enum {
	MIN_IDLE_WORKERS_IN_POOL = 2,           /* how many idle workers in pool */
	MAX_IDLE_WORKERS_RATIO	 = 4,		/* 1/4 of busy can be idle */
	BUSY_WORKER_HASH_ORDER	 = 6,		/* 64 pointers */

	WQ_MAX_ACTIVE            = 64,
	WQ_DFL_ACTIVE            = WQ_MAX_ACTIVE / 2,

	WORK_NR_COLORS		 = 16,

	WORK_PENDING             = 1<<0,
	WORK_DELAYED             = 1<<1,
	WORK_LINKED              = 1<<2,
};

__thread struct workqueue_struct *system_wq;

struct worker_pool;

struct worker {
	union {
		struct list_head   entry;  /* Entry in ->idle_list while idle */
		struct hlist_node  hentry; /* Entry in ->busy_hash while busy */
	};
	struct task_struct *task;
	struct worker_pool *pool;
	struct work_struct *current_work;	/* work being processed */
	work_func_t         current_func;	/* current_work's fn */
	struct list_head    scheduled;	        /* scheduled works */
};

struct worker_pool {
	struct list_head work_list;
	struct list_head idle_list;

	/* a workers is either on busy_hash or idle_list, or the manager */
	DECLARE_HASHTABLE(busy_hash, BUSY_WORKER_HASH_ORDER);
					/* hash of busy workers */


	int              nr_idle;
	int              nr_workers;
	bool             stopped;
};

/*
 * Structure used to wait for workqueue flush.
 */
struct wq_flusher {
	struct list_head	list;		/* WQ: list of flushers */
	int			flush_color;	/* WQ: flush color waiting for */
	struct completion	done;		/* flush completion */
};

struct workqueue_struct {
	struct worker_pool *pool;
	struct list_head   delayed_works;
	unsigned int       nr_active;
	unsigned int       max_active;
	struct wq_flusher  *first_flusher;	/* first flusher */
	struct list_head   flusher_queue;	/* flush waiters */
	struct list_head   flusher_overflow;    /* flush overflow list */
	int		   work_color;	        /* work color */
	int		   flush_color;	        /* flush color */
	int		   active_flush_color;  /* currently active flush color */
	int		   nr_in_flight[WORK_NR_COLORS];
						/* nr of in_flight works */
};

/* Bound to uCPU pool */
static __thread struct worker_pool worker_pool;

static void free_worker(struct worker *worker)
{
	struct worker_pool *pool = worker->pool;

	pool->nr_workers--;
	free(worker);
}

static struct worker *first_idle_worker(struct worker_pool *pool)
{
	if (unlikely(list_empty(&pool->idle_list)))
		return NULL;

	return list_first_entry(&pool->idle_list, struct worker, entry);
}

static void wake_up_worker(struct worker_pool *pool)
{
	struct worker *worker = first_idle_worker(pool);

	if (likely(worker))
		wake_up_process(worker->task);
}

/**
 * Return %true if there is something to do
 */
static bool works_to_run(struct worker_pool *pool)
{
	return !list_empty(&pool->work_list);
}

/**
 * Return %true if there is something to do and no more workers left
 * (all running, no one is idling)
 */
static bool need_worker(struct worker_pool *pool)
{
	return works_to_run(pool) && !pool->nr_idle;
}

/* Do we have too many workers and should some go away? */
static bool too_many_workers(struct worker_pool *pool)
{
	int nr_idle = pool->nr_idle;
	int nr_busy = pool->nr_workers - nr_idle;

	return nr_idle > MIN_IDLE_WORKERS_IN_POOL &&
		(nr_idle - MIN_IDLE_WORKERS_IN_POOL) * MAX_IDLE_WORKERS_RATIO >=
		nr_busy;
}

/**
 * find_worker_executing_work - find worker which is executing a work
 * @work: work to find worker for
 *
 * Find a worker which is executing @work by searching
 * @pool->busy_hash which is keyed by the address of @work.  For a worker
 * to match, its current execution should match the address of @work and
 * its work function.  This is to avoid unwanted dependency between
 * unrelated work executions through a work item being recycled while still
 * being executed.
 *
 * This is a bit tricky.  A work item may be freed once its execution
 * starts and nothing prevents the freed area from being recycled for
 * another work item.  If the same work item address ends up being reused
 * before the original execution finishes, workqueue will identify the
 * recycled work item as currently executing and make it wait until the
 * current execution finishes, introducing an unwanted dependency.
 *
 * This function checks the work item address and work function to avoid
 * false positives.  Note that this isn't complete as one may construct a
 * work function which can introduce dependency onto itself through a
 * recycled work item.  Well, if somebody wants to shoot oneself in the
 * foot that badly, there's only so much we can do, and if such deadlock
 * actually occurs, it should be easy to locate the culprit work function.
 *
 * Return:
 * Pointer to worker which is executing @work if found, %NULL
 * otherwise.
 */
static struct worker *find_worker_executing_work(struct work_struct *work)
{
	struct worker_pool *pool = &worker_pool;
	struct worker *worker;

	hash_for_each_possible(pool->busy_hash, worker, hentry,
			       (unsigned long)work)
		if (worker->current_work == work &&
		    worker->current_func == work->func)
			return worker;

	return NULL;
}

static void worker_enter_idle(struct worker *worker)
{
	struct worker_pool *pool = worker->pool;

	pool->nr_idle++;

	/* idle_list is LIFO */
	list_add(&worker->entry, &pool->idle_list);
}

static void worker_leave_idle(struct worker *worker)
{
	struct worker_pool *pool = worker->pool;

	pool->nr_idle--;
	list_del_init(&worker->entry);
}

/**
 * move_linked_works - move linked works to a list
 * @work: start of series of works to be scheduled
 * @head: target list to append @work to
 * @nextp: out parameter for nested worklist walking
 *
 * Schedule linked works starting from @work to @head.  Work series to
 * be scheduled starts at @work and includes any consecutive work with
 * WORK_LINKED set in its predecessor.
 *
 */
static void move_linked_works(struct work_struct *work, struct list_head *head)
{
	struct work_struct *n;

	/*
	 * Linked worklist will always end before the end of the list,
	 * use NULL for list head.
	 */
	list_for_each_entry_safe_from(work, n, NULL, entry) {
		list_move_tail(&work->entry, head);
		if (!(work->flags & WORK_LINKED))
			break;
	}
}

/**
 * pwq_dec_nr_in_flight - decrement wq's nr_in_flight and nr_active
 * @wq: wq of interest
 *
 * A work either has completed or is removed from pending queue,
 * decrement nr_in_flight of its wq and handle workqueue flushing.
 */
static void wq_dec_nr_in_flight(struct workqueue_struct *wq,
				unsigned int work_flags,
				int work_color)
{

	if (!(work_flags & WORK_DELAYED)) {
		BUG_ON(!wq->nr_active);
		wq->nr_active--;
	}

	wq->nr_in_flight[work_color]--;

	/* is flush in progress and are we at the flushing tip? */
	if (likely(wq->active_flush_color != work_color))
		return;

	/* are there still in-flight works? */
	if (wq->nr_in_flight[work_color])
		return;

	/* this wq is done, clear active_flush_color */
	wq->active_flush_color = -1;

	/* eventually wake up the first flusher */
	complete(&wq->first_flusher->done);
}

static void process_one_work(struct worker *worker, struct work_struct *work)
{
	struct worker_pool *pool = worker->pool;
	struct workqueue_struct *wq;
	struct worker *collision;
	int work_color;

	/*
	 * A single work shouldn't be executed concurrently by
	 * multiple workers on a single cpu.  Check whether anyone is
	 * already processing the work.  If so, defer the work to the
	 * currently executing one.
	 */
	collision = find_worker_executing_work(work);
	if (unlikely(collision)) {
		move_linked_works(work, &collision->scheduled);
		return;
	}

	list_del_init(&work->entry);

	/* Careful, can be NULL for linked barriers */
	wq = work->wq;

	/* Drop all flags including pending */
	work->flags = 0;

	work_color = work->color;

	/*
	 * Hash work opaque pointer in order to find a worker,
	 * see find_worker_executing_work() for details.
	 */
	hash_add(pool->busy_hash, &worker->hentry, (unsigned long)work);
	worker->current_work = work;
	worker->current_func = work->func;

	/* Mark to catch further possible scheduling events */
	set_current_flags(PF_WQ_WORKER);
	work->func(work);
	clear_current_flags(PF_WQ_WORKER);

	/* we're done with it, release */
	hash_del(&worker->hentry);
	worker->current_work = NULL;
	worker->current_func = NULL;

	/* Only regular works have ->wq set, not barriers */
	if (wq) {
		wq_dec_nr_in_flight(wq, 0, work_color);

		if (!list_empty(&wq->delayed_works)) {
			work = list_first_entry(&wq->delayed_works,
						struct work_struct,
						entry);
			work->flags &= ~WORK_DELAYED;
			/* Move delayed work and all linked barriers */
			move_linked_works(work, &pool->work_list);
			wq->nr_active++;
		}
	}
}

/**
 * process_scheduled_works - process scheduled works
 * @worker: self
 *
 * Process all scheduled works.  Please note that the scheduled list
 * may change while processing a work, so this function repeatedly
 * fetches a work from the top and executes it.
 */
static void process_scheduled_works(struct worker *worker)
{
	while (!list_empty(&worker->scheduled)) {
		struct work_struct *work = list_first_entry(&worker->scheduled,
						struct work_struct, entry);
		process_one_work(worker, work);
	}
}

static int worker_thread(void *arg)
{
	struct worker *collision, *worker = arg;
	struct worker_pool *pool = worker->pool;
	struct work_struct *work;

	struct workqueue_struct *wq;

repeat:
	worker_leave_idle(worker);
	/*
	 * ->scheduled list can only be filled while a worker is
	 * preparing to process a work or actually processing it.
	 * Make sure nobody diddled with it while I was sleeping.
	 */
	WARN_ON_ONCE(!list_empty(&worker->scheduled));

	while (!list_empty(&pool->work_list)) {
		struct work_struct *work =
			list_first_entry(&pool->work_list,
					 struct work_struct, entry);

		if (likely(!(work->flags & WORK_LINKED))) {
			/* optimization path, not strictly necessary */
			process_one_work(worker, work);
			if (unlikely(!list_empty(&worker->scheduled)))
				process_scheduled_works(worker);
		} else {
			move_linked_works(work, &worker->scheduled);
			process_scheduled_works(worker);
		}
	}
	if (!too_many_workers(pool)) {
		worker_enter_idle(worker);
		__set_current_state(TASK_IDLE);
		schedule();
		goto repeat;
	}

	/* Eventually free worker and exit the thread */
	free_worker(worker);

	return 0;
}

static struct worker *create_worker(struct worker_pool *pool)
{
	struct worker *worker;

	worker = malloc(sizeof(*worker));
	if (unlikely(!worker))
		return NULL;

	worker->task = task_create(worker_thread, worker);
	if (unlikely(!worker->task)) {
		free(worker);
		return NULL;
	}
	worker->pool = pool;
	INIT_LIST_HEAD(&worker->scheduled);

	pool->nr_workers++;
	worker_enter_idle(worker);

	return worker;
}

void wq_worker_sleeping(struct task_struct *task)
{
	struct worker *next, *worker = task_data(task);
	struct worker_pool *pool = worker->pool;

	if (works_to_run(pool)) {
		if (need_worker(pool))
		    create_worker(pool);

		next = first_idle_worker(pool);
		if (!WARN_ON(!next))
			wake_up_process(next->task);
	}
}

void wq_worker_running(struct task_struct *task)
{
}

static void init_worker_pool(struct worker_pool *pool)
{
	int i;

	INIT_LIST_HEAD(&pool->work_list);
	INIT_LIST_HEAD(&pool->idle_list);
	hash_init(pool->busy_hash);

	for (i = 0; i < MIN_IDLE_WORKERS_IN_POOL; i++) {
		struct worker *worker;

		worker = create_worker(pool);
		BUG_ON(!worker);
	}
}

void init_workqueue(void)
{
	struct worker_pool *pool = &worker_pool;

	init_worker_pool(pool);

	system_wq = alloc_workqueue("events", 0, 0);
	BUG_ON(!system_wq);
}

void deinit_workqueue(void)
{
	//XXX
}

struct workqueue_struct *alloc_workqueue(const char *fmt,
					 unsigned int flags,
					 int max_active, ...)
{
	(void)fmt;
	(void)flags;

	struct worker_pool *pool = &worker_pool;
	struct workqueue_struct *wq;

	wq = calloc(1, sizeof(*wq));
	if (wq) {
		INIT_LIST_HEAD(&wq->delayed_works);
		INIT_LIST_HEAD(&wq->flusher_queue);
		INIT_LIST_HEAD(&wq->flusher_overflow);
		wq->active_flush_color = -1;
		wq->max_active = (max_active ?: WQ_DFL_ACTIVE);
		wq->max_active = clamp_val(wq->max_active, 1, WQ_MAX_ACTIVE);
		wq->pool = pool;
	}

	return wq;
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int i;

	BUG_ON(wq->nr_active);
	for (i = 0; i < ARRAY_SIZE(wq->nr_in_flight); i++) {
		BUG_ON(wq->nr_in_flight[i]);
	}
	free(wq);
}

static int work_next_color(int color)
{
	return (color + 1) % WORK_NR_COLORS;
}

/**
 * flush_workqueue_prep - prepare wq for workqueue flushing
 * @wq: workqueue being flushed
 * @flush_color: new flush color
 *
 * Prepare wq for workqueue flushing.
 *
 * @currnet_flush_color on wq should be -1.  If wq does not have
 * in-flight commands at the specified color, wq->active_flush_color's
 * stays at -1 and %false is returned.  If wq has in flight commands,
 * its wq->active_flush_color is set to @flush_color
 *
 * The caller should have initialized @wq->first_flusher prior to
 * calling this function.
 *
 * Return:
 * %true if there's something to flush.  %false otherwise.
 */
static bool flush_workqueue_prep(struct workqueue_struct *wq, int flush_color)
{
	bool wait = false;

	WARN_ON_ONCE(wq->active_flush_color != -1);

	if (wq->nr_in_flight[flush_color]) {
		wq->active_flush_color = flush_color;
		wait = true;
	}
	else
		complete(&wq->first_flusher->done);

	return wait;
}

/**
 * flush_workqueue - ensure that any scheduled work has run to completion.
 * @wq: workqueue to flush
 *
 * This function sleeps until all work items which were queued on entry
 * have finished execution, but it is not livelocked by new incoming ones.
 */
void flush_workqueue(struct workqueue_struct *wq)
{
	struct wq_flusher this_flusher = {
		.list = LIST_HEAD_INIT(this_flusher.list),
		.flush_color = -1,
		.done = COMPLETION_INITIALIZER_ONSTACK_MAP(this_flusher.done, NULL),
	};
	int next_color;

	/*
	 * Start-to-wait phase
	 */
	next_color = work_next_color(wq->work_color);

	if (next_color != wq->flush_color) {
		/*
		 * Color space is not full.  The current work_color
		 * becomes our flush_color and work_color is advanced
		 * by one.
		 */
		WARN_ON_ONCE(!list_empty(&wq->flusher_overflow));
		this_flusher.flush_color = wq->work_color;
		wq->work_color = next_color;

		if (!wq->first_flusher) {
			/* no flush in progress, become the first flusher */
			WARN_ON_ONCE(wq->flush_color != this_flusher.flush_color);

			wq->first_flusher = &this_flusher;

			if (!flush_workqueue_prep(wq, wq->flush_color)) {
				/* nothing to flush, done */
				wq->flush_color = next_color;
				wq->first_flusher = NULL;
				return;
			}
		} else {
			/* wait in queue */
			WARN_ON_ONCE(wq->flush_color == this_flusher.flush_color);
			list_add_tail(&this_flusher.list, &wq->flusher_queue);
		}
	} else {
		/*
		 * Oops, color space is full, wait on overflow queue.
		 * The next flush completion will assign us
		 * flush_color and transfer to flusher_queue.
		 */
		list_add_tail(&this_flusher.list, &wq->flusher_overflow);
	}

	wait_for_completion(&this_flusher.done);

	/*
	 * Wake-up-and-cascade phase
	 *
	 * First flushers are responsible for cascading flushes and
	 * handling overflow.  Non-first flushers can simply return.
	 */
	if (wq->first_flusher != &this_flusher)
		return;

	wq->first_flusher = NULL;

	WARN_ON_ONCE(!list_empty(&this_flusher.list));
	WARN_ON_ONCE(wq->flush_color != this_flusher.flush_color);

	while (true) {
		struct wq_flusher *next, *tmp;

		/* complete all the flushers sharing the current flush color */
		list_for_each_entry_safe(next, tmp, &wq->flusher_queue, list) {
			if (next->flush_color != wq->flush_color)
				break;
			list_del_init(&next->list);
			complete(&next->done);
		}

		WARN_ON_ONCE(!list_empty(&wq->flusher_overflow) &&
			     wq->flush_color != work_next_color(wq->work_color));

		/* this flush_color is finished, advance by one */
		wq->flush_color = work_next_color(wq->flush_color);

		/* one color has been freed, handle overflow queue */
		if (!list_empty(&wq->flusher_overflow)) {
			/*
			 * Assign the same color to all overflowed
			 * flushers, advance work_color and append to
			 * flusher_queue.  This is the start-to-wait
			 * phase for these overflowed flushers.
			 */
			list_for_each_entry(tmp, &wq->flusher_overflow, list)
				tmp->flush_color = wq->work_color;

			wq->work_color = work_next_color(wq->work_color);

			list_splice_tail_init(&wq->flusher_overflow,
					      &wq->flusher_queue);
		}

		if (list_empty(&wq->flusher_queue)) {
			WARN_ON_ONCE(wq->flush_color != wq->work_color);
			break;
		}

		/*
		 * Need to flush more colors.  Make the next flusher
		 * the new first flusher and arm pwqs.
		 */
		WARN_ON_ONCE(wq->flush_color == wq->work_color);
		WARN_ON_ONCE(wq->flush_color != next->flush_color);

		list_del_init(&next->list);
		wq->first_flusher = next;

		if (flush_workqueue_prep(wq, wq->flush_color))
			break;

		/*
		 * Meh... this color is already done, clear first
		 * flusher and repeat cascading.
		 */
		wq->first_flusher = NULL;
	}
}

static bool work_is_pending(struct work_struct *work)
{
	return (work->flags & WORK_PENDING);
}

static bool __queue_work(struct work_struct *work)
{
	struct worker_pool *pool = &worker_pool;
	struct workqueue_struct *wq = work->wq;

	work->color = wq->work_color;
	wq->nr_in_flight[wq->work_color]++;

	if (likely(wq->nr_active < wq->max_active)) {
		wq->nr_active++;
		list_add_tail(&work->entry, &pool->work_list);
		wake_up_worker(pool);
	} else {
		work->flags |= WORK_DELAYED;
		list_add_tail(&work->entry, &wq->delayed_works);
	}

	return true;
}

static bool prepare_work(struct workqueue_struct *wq,
			 struct work_struct *work)
{
	if (work_is_pending(work))
		return false;

	work->flags = WORK_PENDING;
	work->wq = wq;

	return true;
}

bool queue_work(struct workqueue_struct *wq,
		struct work_struct *work)
{
	struct worker_pool *pool = &worker_pool;

	if (!prepare_work(wq, work))
		return false;

	return __queue_work(work);
}

struct wq_barrier {
	struct work_struct work;
	struct completion  done;
};

static void wq_barrier_func(struct work_struct *work)
{
	struct wq_barrier *barrier;

	barrier = container_of(work, struct wq_barrier, work);
	complete(&barrier->done);
}

static void init_wq_barrier(struct wq_barrier *barrier)
{
	INIT_WORK(&barrier->work, wq_barrier_func);
	init_completion(&barrier->done);
}

/**
 * flush_work - wait for a work to finish executing the last queueing instance
 * @work: the work to flush
 *
 * Wait until @work has finished execution.  @work is guaranteed to be idle
 * on return if it hasn't been requeued since flush started.
 *
 * Return:
 * %true if flush_work() waited for the work to finish execution,
 * %false if it was already idle.
 */
bool flush_work(struct work_struct *work)
{
	struct list_head *head = NULL;
	struct worker *worker;

	unsigned int linked_flags = 0;

	if (work_is_pending(work)) {
		/*
		 * If work is pending we can schedule a barrier just after it
		 */
		head = work->entry.next;
		/* there can already be other linked works, inherit and set */
		linked_flags = work->flags & WORK_LINKED;
		work->flags |= WORK_LINKED;

	} else if ((worker = find_worker_executing_work(work))) {
		/*
		 * Worker can be found if work is sleeping and blocking that worker
		 */
		head = worker->scheduled.next;
	}

	/* Yay, insert a barrier to the list and wait for a completion */
	if (head) {
		struct wq_barrier barrier;

		init_wq_barrier(&barrier);
		barrier.work.flags = (linked_flags | WORK_PENDING);
		list_add_tail(&barrier.work.entry, head);
		wait_for_completion(&barrier.done);

		return true;
	}

	return false;
}

/**
 * Return: %true if @work was pending and canceled; %false if it wasn't
 * pending.
 */
static bool cancel_work(struct work_struct *work)
{
	if (!work_is_pending(work)) {
		/*
		 * Pending is cleared, nothing to do.
		 * Either work is idle (completed), either it is busy
		 * (i.e. is in ->func and blocks the worker).
		 */
		return false;
	}
	/*
	 * Please note that barriers which can be linked to the @work after
	 * flush_work() is invoked can'be canceled. They are just left on the
	 * queue and will be completed in a regular way. This behavior repeats
	 * original kernel workqueue implementation, see insert_wq_barrier()
	 * for details.
	 */

	wq_dec_nr_in_flight(work->wq, work->flags, work->color);
	list_del_init(&work->entry);

	/* Clear all flags including pending */
	work->flags = 0;

	return true;
}

/**
 * cancel_work_sync - cancel a work and wait for it to finish
 * @work: the work to cancel
 *
 * Cancel @work and wait for its execution to finish.  This function
 * can be used even if the work re-queues itself or migrates to
 * another workqueue.  On return from this function, @work is
 * guaranteed to be not pending or executing.
 *
 * cancel_work_sync(&delayed_work->work) must not be used for
 * delayed_work's.  Use cancel_delayed_work_sync() instead.
 *
 * The caller must ensure that the workqueue on which @work was last
 * queued can't be destroyed before this function returns.
 *
 * Return:
 * %true if @work was pending, %false otherwise.
 */
bool cancel_work_sync(struct work_struct *work)
{
	bool canceled;

	canceled = cancel_work(work);
	if (canceled)
		return true;

	/*
	 * Either work is idle (completed), either it is busy in the worker.
	 * In all the cases do the flush and reach a completion.
	 */
	flush_work(work);

	return false;
}

static void delayed_work_timer_fn(struct timer *timer)
{
	struct delayed_work *dwork;

	dwork = container_of(timer, typeof(*dwork), timer);
	__queue_work(&dwork->work);
}

bool queue_delayed_work(struct workqueue_struct *wq,
			struct delayed_work *dwork,
			unsigned long delay)
{
	struct timer *timer = &dwork->timer;
	struct work_struct *work = &dwork->work;

	if (!prepare_work(wq, work))
		return false;

	/* If @delay is 0, queue @dwork->work immediately. */
	if (!delay)
		return __queue_work(work);

	timer_add(timer, jiffies + delay, delayed_work_timer_fn);

	return true;
}

/**
 * flush_delayed_work - wait for a dwork to finish executing the last queueing
 * @dwork: the delayed work to flush
 *
 * Delayed timer is cancelled and the pending work is queued for
 * immediate execution.  Like flush_work(), this function only
 * considers the last queueing instance of @dwork.
 *
 * Return:
 * %true if flush_work() waited for the work to finish execution,
 * %false if it was already idle.
 */
bool flush_delayed_work(struct delayed_work *dwork)
{
	if (timer_del(&dwork->timer))
		__queue_work(&dwork->work);

	return flush_work(&dwork->work);
}

/**
 * cancel_delayed_work - cancel a delayed work
 * @dwork: delayed_work to cancel
 *
 * Kill off a pending delayed_work.
 *
 * Return: %true if @dwork was pending and canceled; %false if it wasn't
 * pending.
 *
 * Note:
 * The work callback function may still be running on return, unless
 * it returns %true and the work doesn't re-arm itself.  Explicitly flush or
 * use cancel_delayed_work_sync() to wait on it.
 *
 */
bool cancel_delayed_work(struct delayed_work *dwork)
{
	struct work_struct *work = &dwork->work;
	bool del;

	del = timer_del(&dwork->timer);
	if (del) {
		/* Timer was not executed yet, so work was not even queued */
		WARN_ON(work->flags != WORK_PENDING);
		work->flags = 0;
		return true;
	}

	return cancel_work(work);
}

/**
 * cancel_delayed_work_sync - cancel a delayed work and wait for it to finish
 * @dwork: the delayed work cancel
 *
 * This is cancel_work_sync() for delayed works.
 *
 * Return:
 * %true if @dwork was pending, %false otherwise.
 */
bool cancel_delayed_work_sync(struct delayed_work *dwork)
{
	bool canceled;

	canceled = cancel_delayed_work(dwork);
	if (canceled)
		return true;

	/*
	 * Either work is idle (completed), either it is busy in the worker.
	 * In all the cases do the flush and reach a completion.
	 */
	flush_work(&dwork->work);

	return false;
}

/**
 * mod_delayed_work - modify delay of or queue a delayed work
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * If @dwork is idle, equivalent to queue_delayed_work_on(); otherwise,
 * modify @dwork's timer so that it expires after @delay.  If @delay is
 * zero, @work is guaranteed to be scheduled immediately regardless of its
 * current state.
 *
 * Return: %false if @dwork was idle and queued, %true if @dwork was
 * pending and its timer was modified.
 */
bool mod_delayed_work(struct workqueue_struct *wq,
		      struct delayed_work *dwork,
		      unsigned long delay)
{
	bool canceled, queued;

	canceled = cancel_delayed_work(dwork);
	queued = queue_delayed_work(wq, dwork, delay);
	WARN_ON(!queued);

	return canceled;
}
