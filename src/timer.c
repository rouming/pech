#include "timer.h"
#include "rbtree.h"
#include "timedef.h"

static struct rb_root timer_root = RB_ROOT;

unsigned int timer_calc_msecs_timeout(void)
{
	struct timer *first;
	unsigned long now;

	if (RB_EMPTY_ROOT(&timer_root))
		/* Far in the future */
		return -1;

	first = container_of(rb_first(&timer_root), typeof(*first), node);
	now = jiffies;
	if (first->expire > now)
		return jiffies_to_msecs(first->expire - now);

	/* Expire now */
	return 0;
}

void timer_run(void)
{
	struct rb_node *next_rb = rb_first(&timer_root);
	struct timer *timer, *next;

	unsigned long now = jiffies;

	while (next_rb) {
		timer = rb_entry(next_rb, typeof(*timer), node);
		if (timer->expire > now)
			break;

		next_rb = rb_next(&timer->node);
		rb_erase_init(&timer->node, &timer_root);

		/* Run timer for the head and for the rest */
		while (timer) {
			next = list_first_entry_or_null(&timer->list,
							typeof(*next), list);
			list_del_init(&timer->list);
			timer->func(timer);
			timer = next;
		}
	}
}

static struct rb_node *
rbtree_insert(struct rb_root *root,
	      struct rb_node *new,
	      int (*cmp)(const struct rb_node *a,
			 const struct rb_node *b))
{
	struct rb_node **this = &root->rb_node, *parent = NULL;
	int rc;

	while (*this) {
		parent = *this;
		rc = cmp(new, *this);
		if (rc < 0)
			this = &(*this)->rb_left;
		else if (rc > 0)
			this = &(*this)->rb_right;
		else
			return *this;
	}
	/* Add new node to the tree and rebalance it */
	rb_link_node(new, parent, this);
	rb_insert_color(new, root);

	return new;
}

static int cmp_timers(const struct rb_node *a_, const struct rb_node *b_)
{
	struct timer *a, *b;

	a = container_of(a_, struct timer, node);
	b = container_of(b_, struct timer, node);

	if (a->expire < b->expire)
		return -1;
	if (a->expire > b->expire)
		return 1;

	return 0;
}

static void timer_ins(struct timer *timer)
{
	struct rb_node *node;
	struct timer *old;

	node = rbtree_insert(&timer_root, &timer->node, cmp_timers);
	if (node != &timer->node) {
		old = container_of(node, typeof(*old), node);
		/* Add current timer to the list of found timer */
		list_add_tail(&timer->list, &old->list);
	}
}

/**
 * timer_add - start a timer
 * @timer: the timer to be added
 *
 * The event loop will do a ->action(@timer) callback at the ->expires
 * point in the future. The current time is 'jiffies'.
 *
 * The timer's ->expires, ->action fields must be set prior calling this
 * function.
 *
 * Timers with an ->expires field in the past will be executed in the next
 * event loop run.
 */
void timer_add(struct timer *timer, unsigned long jexpire, timer_func_t func)
{
	INIT_LIST_HEAD(&timer->list);
	RB_CLEAR_NODE(&timer->node);
	timer->func = func;
	timer->expire = jexpire;

	timer_ins(timer);
}

/**
 * timer_del - deactivate a timer.
 * @timer: the timer to be deactivated
 *
 * timer_del() deactivates a timer - this works on both active and inactive
 * timers.
 *
 * The function returns whether it has deactivated a pending timer or not.
 * (ie. timer_del() of an inactive timer returns 0, timer_del() of an
 * active timer returns 1.)
 */
bool timer_del(struct timer *timer)
{
	struct timer *next;

	if (list_empty(&timer->list) && RB_EMPTY_NODE(&timer->node)) {
		/* Already deleted */
		return false;
	} else if (list_empty(&timer->list)) {
		/* Timer is a single one */
		rb_erase_init(&timer->node, &timer_root);
	} else if (RB_EMPTY_NODE(&timer->node)) {
		/* Timer was added to the list of another timer */
		list_del_init(&timer->list);
	} else {
		/* Carefully remove timer head and replace it with the next one */
		next = list_first_entry(&timer->list, typeof(*next), list);
		list_del_init(&timer->list);
		rb_replace_node(&timer->node, &next->node, &timer_root);
		RB_CLEAR_NODE(&timer->node);
	}

	return true;
}

/**
 * timer_mod - modify a timer's timeout
 * @timer: the timer to be modified
 * @jexpire: new timeout in jiffies
 *
 * The function returns whether it has modified a pending timer or not.
 * (ie. timer_mod() of an inactive timer returns 0, timer_mod() of an
 * active timer returns 1.)
 */
bool timer_mod(struct timer *timer, unsigned long jexpire)
{
	bool del;

	del = timer_del(timer);
	timer->expire = jexpire;
	timer_ins(timer);

	return del;
}
