#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "types.h"
#include "err.h"
#include "event.h"
#include "sched.h"
#include "timer.h"

struct event_task_struct {
	struct list_head set_events;
	int              epollfd;
	bool             stopped;
};

static void event_item_do_action(struct epoll_event *ev)
{
	struct event_item *item;

	item = (struct event_item *)ev->data.ptr;
	item->revents |= ev->events;
	item->action(item);

	/* No need to call action again */
	item->revents = 0;
	list_del_init(&item->entry);
}

static void events_set_do_action(struct event_task_struct *s)
{
	struct event_item *item;
	LIST_HEAD(set_events);

	/* Use temporal list to avoid live lock */
	list_splice_init(&s->set_events, &set_events);

	while (!list_empty(&set_events)) {
		item = list_first_entry(&set_events, typeof(*item), entry);
		WARN_ON(!item->revents);
		item->action(item);
		item->revents = 0;
		list_del_init(&item->entry);
	}
}

static bool events_are_set(struct event_task_struct *s)
{
	return !list_empty(&s->set_events);
}

static int event_task(void *arg)
{
	struct event_task_struct *s = arg;
	struct epoll_event evs[128];
	unsigned int timeout;
	int i, num;

	while (!s->stopped) {
		/* Get closest expiration timeout from timer */
		timeout = timer_calc_msecs_timeout();

		/*
		 * Do not block if there is a task except us to run or
		 * events were forcly set to be executed
		 */
		if (tasks_to_run() > 1 || events_are_set(s))
			timeout = 0;

		num = epoll_wait(s->epollfd, evs, ARRAY_SIZE(evs), timeout);
		if (num < 0) {
			if (errno != EINTR) {
				pr_err("epoll_wait() failed, errno=%d\n", errno);
				break;
			}
			num = 0;
		}

		/* Firstly run all possibly expired timers */
		timer_run();

		/* Then handle all possible events */
		for (i = 0; i < num; i++)
			event_item_do_action(&evs[i]);

		/* Run all set events actions */
		events_set_do_action(s);

		schedule();
	}

	/* Finalizion */
	close(s->epollfd);

	s->epollfd = -1;
	s->stopped = false;

	return 0;
}

static __thread struct event_task_struct event_struct = {
	.epollfd = -1,
};

void init_event(void)
{
	struct task_struct *task;

	BUG_ON(event_struct.epollfd >= 0);

	INIT_LIST_HEAD(&event_struct.set_events);

	event_struct.epollfd = epoll_create1(EPOLL_CLOEXEC);
	BUG_ON(event_struct.epollfd < 0);

	task = task_create(event_task, &event_struct);
	BUG_ON(!task);

	wake_up_process(task);
}

void deinit_event(void)
{
	event_struct.stopped = true;
}

static int __event_item_mod(struct event_item *item, int op)
{
	struct epoll_event ev = {
		.events = item->events,
		.data.ptr = item
	};
	int ret;

	ret = epoll_ctl(event_struct.epollfd, op,
			item->fd, &ev);
	if (ret < 0)
		return -errno;

	return 0;
}

int event_item_add(struct event_item *item, int fd)
{
	item->fd = fd;

	return __event_item_mod(item, EPOLL_CTL_ADD);
}

int event_item_del(struct event_item *item)
{
	int ret = -EBADF;

	if (item->fd >= 0) {
		ret = __event_item_mod(item, EPOLL_CTL_DEL);
		item->fd = -1;
	}

	return ret;
}

int event_item_mod(struct event_item *item)
{
	return __event_item_mod(item, EPOLL_CTL_MOD);
}

void event_item_set(struct event_item *item)
{
	list_move_tail(&item->entry, &event_struct.set_events);
}
