#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "types.h"
#include "err.h"
#include "event.h"
#include "sched.h"
#include "timer.h"

struct event_task_struct {
	int epollfd;
	bool stopped;
};

static void event_item_action(struct epoll_event *ev)
{
	struct event_item *item;

	item = (struct event_item *)ev->data.ptr;
	item->revents = ev->events;
	item->action(item);
}

static int event_task(void *arg)
{
	struct event_task_struct *s = arg;
	struct epoll_event evs[128];
	int i, num, timeout;

	while (!s->stopped) {
		/* Get closest expiration timeout from timer */
		timeout = timer_calc_msecs_timeout();

		/* Do not block if there is a task except us to run */
		if (tasks_to_run() > 1)
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
			event_item_action(&evs[i]);

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
	struct epoll_event ev;

	BUG_ON(event_struct.epollfd >= 0);

	event_struct.epollfd = epoll_create1(EPOLL_CLOEXEC);
	BUG_ON(event_struct.epollfd < 0);

	task = task_create(event_task, &event_struct);
	BUG_ON(!task);

	wake_up_process(task);
}

void stop_event(void)
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
