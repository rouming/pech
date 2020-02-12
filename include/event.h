#ifndef _EVENT_H
#define _EVENT_H

enum {
	EV_CTL_ADD = 0,
	EV_CTL_MOD = 1,
	EV_CTL_DEL = 2,

	EV_ERR = 1,
	EV_IN  = 2,
	EV_OUT = 4,
};

struct event_item {
	void (*action)(struct event_item *);
	int fd;
	int events;
	int revents;
};

extern void init_event(void);
extern void stop_event(void);

extern int event_item_add(struct event_item *);
extern int event_item_del(struct event_item *);
extern int event_item_mod(struct event_item *);

#endif
