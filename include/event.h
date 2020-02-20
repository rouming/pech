#ifndef _EVENT_H
#define _EVENT_H

#include <sys/epoll.h>

struct event_item {
	void (*action)(struct event_item *);
	int fd;
	int events;
	int revents;
};

#define INIT_EVENT(item, action_fn)		\
	*(item) = (typeof(*(item))) {		\
		.action = action_fn,		\
		.fd = -1,			\
	}

extern void init_event(void);
extern void stop_event(void);

extern int event_item_add(struct event_item *, int fd);
extern int event_item_del(struct event_item *);
extern int event_item_mod(struct event_item *);

#endif
