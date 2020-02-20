/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ATOMIC_H
#define _ATOMIC_H

#include "types.h"

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	s64 counter;
} atomic64_t;


/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 *
 * Excerpts obtained from the Linux kernel sources.
 */

#define ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read(const atomic_t *v)
{
	return v->counter;
}

static inline s64 atomic64_read(const atomic64_t *v)
{
	return v->counter;
}

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
	v->counter++;
}

static inline void atomic_dec(atomic_t *v)
{
	v->counter--;
}

static inline int atomic_inc_return(atomic_t *v)
{
	return ++v->counter;
}

static inline s64 atomic64_inc_return(atomic64_t *v)
{
	return ++v->counter;
}

static inline int atomic_fetch_add_relaxed(int i, atomic_t *v)
{
	int old = v->counter;
	v->counter += i;
	return old;
}

static inline int atomic_fetch_sub_release(int i, atomic_t *v)
{
	int old = v->counter;
	v->counter -= i;
	return old;
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static inline int atomic_dec_and_test(atomic_t *v)
{
	return (--v->counter == 0);
}

static inline int atomic_cmpxchg(atomic_t *v, int oldval, int newval)
{
	int old = v->counter;
	if (old == oldval)
		v->counter = newval;
	return old;
}

static inline int atomic_xchg(atomic_t *v, int val)
{
	int old = v->counter;
	v->counter = val;
	return old;
}

static inline bool atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg(v, o, new);
	if (unlikely(r != o))
		*old = r;
	return likely(r == o);
}

#endif
