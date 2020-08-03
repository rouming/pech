#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "types.h"
#include "err.h"
#include "event.h"
#include "sched.h"
#include "timer.h"

/* Flags for epoll_create */
#define EPOLL_USERPOLL 1

/* User item marked as removed for EPOLL_USERPOLL */
#define EPOLLREMOVED	((__force __poll_t)(1U << 27))

#define EPOLL_USERPOLL_HEADER_MAGIC 0xeb01eb01
#define EPOLL_USERPOLL_HEADER_SIZE  128

/*
 * Item, shared with userspace.  Unfortunately we can't embed epoll_event
 * structure, because it is badly aligned on all 64-bit archs, except
 * x86-64 (see EPOLL_PACKED).  sizeof(epoll_uitem) == 16
 */
struct epoll_uitem {
	__poll_t ready_events;
	__poll_t events;
	__u64 data;
};

/*
 * Header, shared with userspace. sizeof(epoll_uheader) == 128
 */
struct epoll_uheader {
	__u32 magic;          /* epoll user header magic */
	__u32 header_length;  /* length of the header + items */
	__u32 index_length;   /* length of the index ring, always pow2 */
	__u32 max_items_nr;   /* max number of items */
	__u32 head;           /* updated by userland */
	__u32 tail;           /* updated by kernel */

	struct epoll_uitem items[]
		__attribute__((__aligned__(EPOLL_USERPOLL_HEADER_SIZE)));
};

struct event_task_struct {
	struct list_head set_events;
	int              epollfd;
	bool             is_uepoll;
	struct epoll_uheader
			 *uheader;
	unsigned int     *uindex;
	bool             stopped;
};

#ifndef __NR_sys_epoll_create2
#define __NR_sys_epoll_create2  436
#endif

static inline long epoll_create2(int flags, size_t size)
{
	return syscall(__NR_sys_epoll_create2, flags, size);
}

static inline unsigned int max_index_nr(struct epoll_uheader *header)
{
	return header->index_length >> 2;
}

static inline bool uepoll_read_event(struct epoll_uheader *header,
				     unsigned int *index, unsigned int idx,
				     struct epoll_event *event)
{
	struct epoll_uitem *item;
	unsigned int *item_idx_ptr;
	unsigned int indeces_mask;

	indeces_mask = max_index_nr(header) - 1;
	if (indeces_mask & max_index_nr(header)) {
		BUG_ON(1);
		/* Should be pow2, corrupted header? */
		return 0;
	}

	item_idx_ptr = &index[idx & indeces_mask];

	/* Load index */
	idx = __atomic_load_n(item_idx_ptr, __ATOMIC_ACQUIRE);
	if (idx >= header->max_items_nr) {
		BUG_ON(1);
		/* Corrupted index? */
		return 0;
	}

	item = &header->items[idx];

	/*
	 * Fetch data first, if event is cleared by the kernel we drop the data
	 * returning false.
	 */
	event->data.u64 = item->data;
	event->events = __atomic_exchange_n(&item->ready_events, 0,
					    __ATOMIC_RELEASE);
	WARN_ON(!event->events);

	return (event->events & ~EPOLLREMOVED);
}

static int uepoll_wait(struct epoll_uheader *header, unsigned int *index,
		       int epfd, struct epoll_event *events, int maxevents,
		       unsigned int timeout)

{
	/*
	 * Before entering kernel we do busy wait for ~1ms, naively assuming
	 * each iteration costs 1 cycle, 1 ns.
	 */
	unsigned int spins = 0;
	unsigned int tail;
	int i;

	BUG_ON(maxevents <= 0);

again:
	/*
	 * Cache the tail because we don't want refetch it on each iteration
	 * and then catch live events updates, i.e. we don't want user @events
	 * array consist of events from the same fds.
	 */
	tail = READ_ONCE(header->tail);
	if (header->head == tail) {
		if (spins--)
			/* Busy loop a bit */
			goto again;

		i = epoll_wait(epfd, NULL, 0, timeout);
		if (i == 0)
			return i;
		if (errno != ESTALE)
			return i;

		tail = READ_ONCE(header->tail);
		BUG_ON(header->head == tail);
	}

	for (i = 0; header->head != tail && i < maxevents; header->head++) {
		if (uepoll_read_event(header, index, header->head, &events[i]))
			/* Account event unless is not removed */
			i++;
	}

	return i;
}

static void uepoll_mmap(int epfd, struct epoll_uheader **_header,
		       unsigned int **_index)
{
	struct epoll_uheader *header;
	unsigned int *index, len;

	BUILD_BUG_ON(sizeof(*header) != EPOLL_USERPOLL_HEADER_SIZE);
	BUILD_BUG_ON(sizeof(header->items[0]) != 16);

	len = sysconf(_SC_PAGESIZE);
again:
	header = mmap(NULL, len, PROT_WRITE|PROT_READ, MAP_SHARED, epfd, 0);
	if (header == MAP_FAILED) {
		pr_err("Failed map(header)\n");
		BUG_ON(1);
	}

	if (header->header_length != len) {
		unsigned int tmp_len = len;

		len = header->header_length;
		munmap(header, tmp_len);
		goto again;
	}
	BUG_ON(header->magic != EPOLL_USERPOLL_HEADER_MAGIC);

	index = mmap(NULL, header->index_length, PROT_WRITE|PROT_READ,
		     MAP_SHARED, epfd, header->header_length);
	if (index == MAP_FAILED) {
		pr_err("Failed map(index)\n");
		BUG_ON(1);
	}

	*_header = header;
	*_index = index;
}

static void uepoll_munmap(struct epoll_uheader *header,
			  unsigned int *index)
{
	int rc;

	rc = munmap(index, header->index_length);
	if (rc)
		pr_err("Failed munmap(index)\n");

	rc = munmap(header, header->header_length);
	if (rc)
		pr_err("Failed munmap(header)\n");
}

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

		if (s->is_uepoll)
			num = uepoll_wait(s->uheader, s->uindex, s->epollfd,
					  evs, ARRAY_SIZE(evs), timeout);
		else
			num = epoll_wait(s->epollfd, evs, ARRAY_SIZE(evs),
					 timeout);
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
	if (s->is_uepoll)
		uepoll_munmap(s->uheader, s->uindex);
	close(s->epollfd);

	s->epollfd = -1;
	s->stopped = false;

	return 0;
}

static __thread struct event_task_struct event_struct = {
	.epollfd = -1,
};

void init_event(bool uepoll)
{
	struct task_struct *task;
	int efd;

	BUG_ON(event_struct.epollfd >= 0);

	INIT_LIST_HEAD(&event_struct.set_events);

	switch (uepoll) {
	case true:
		efd = epoll_create2(EPOLL_USERPOLL | EPOLL_CLOEXEC, 2048);
		if (efd >= 0) {
			/* Mmap all pointers */
			uepoll_mmap(efd, &event_struct.uheader,
				    &event_struct.uindex);
			event_struct.is_uepoll = true;
			pr_notice("USEREPOLL is used!\n");
			break;
		}
		/* Fallback to original epoll */
	case false:
		efd = epoll_create1(EPOLL_CLOEXEC);
		break;
	}
	BUG_ON(efd < 0);
	event_struct.epollfd = efd;

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
	/* Delete from set events list */
	list_del_init(&item->entry);

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
