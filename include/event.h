#ifndef _EVENT_H
#define _EVENT_H

#include <sys/epoll.h>
#include "list.h"

struct event_item {
	struct list_head entry;
	void (*action)(struct event_item *);
	int fd;
	int events;
	int revents;
};

#define INIT_EVENT(item, action_fn)			\
	*(item) = (typeof(*(item))) {			\
		.entry = LIST_HEAD_INIT((item)->entry), \
		.action = action_fn,			\
		.fd = -1,				\
	}

extern void init_event(bool uepoll);
extern void deinit_event(void);

extern int event_item_add(struct event_item *, int fd);
extern int event_item_del(struct event_item *);
extern int event_item_mod(struct event_item *);
extern void event_item_set(struct event_item *);

#endif
