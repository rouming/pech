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

static inline int to_epoll_op(int op)
{
	int epollop = 0;

	if (op == EV_CTL_ADD)
		epollop = EPOLL_CTL_ADD;
	else if (op == EV_CTL_MOD)
		epollop = EPOLL_CTL_MOD;
	else if (op == EV_CTL_DEL)
		epollop = EPOLL_CTL_DEL;
	else
		return -EINVAL;

	return epollop;
}

static inline int to_epoll_events(int ev)
{
	int epollev = 0;

	if (ev & EV_IN)
		epollev |= EPOLLIN;
	if (ev & EV_OUT)
		epollev |= EPOLLOUT;
	if (ev & EV_ERR)
		epollev |= EPOLLERR;

	return epollev;
}

static inline int from_epoll_events(int epollev)
{
	int ev = 0;

	if (epollev & EPOLLIN)
		ev |= EV_IN;
	if (epollev & EPOLLOUT)
		ev |= EV_OUT;
	if (epollev & EPOLLERR)
		ev |= EV_ERR;

	return ev;
}

static void event_item_action(struct epoll_event *ev)
{
	struct event_item *item;

	item = (struct event_item *)ev->data.ptr;
	item->revents = from_epoll_events(ev->events);
	item->action(item);
}

static void event_task(void *arg)
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
	BUG_ON(IS_ERR(task));

	wake_up_process(task);
}

void stop_event(void)
{
	event_struct.stopped = true;
}

static int __event_item_mod(struct event_item *item, int op)
{
	struct epoll_event ev = {
		.events = to_epoll_events(item->events),
		.data.ptr = item
	};
	int ret;

	ret = epoll_ctl(event_struct.epollfd, to_epoll_op(op),
			item->fd, &ev);
	if (ret < 0)
		return -errno;

	return 0;
}

int event_item_add(struct event_item *item)
{
	return __event_item_mod(item, EPOLL_CTL_ADD);
}

int event_item_del(struct event_item *item)
{
	return __event_item_mod(item, EPOLL_CTL_DEL);
}

int event_item_mod(struct event_item *item)
{
	return __event_item_mod(item, EPOLL_CTL_MOD);
}
