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
	return READ_ONCE((v)->counter);
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
	WRITE_ONCE(v->counter, i);
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
	__sync_add_and_fetch(&v->counter, 1);
}

static inline int atomic_inc_return(atomic_t *v)
{
	return __sync_add_and_fetch(&v->counter, 1);
}

static inline int atomic_fetch_add_relaxed(int i, atomic_t *v)
{
	return __atomic_fetch_add(&v->counter, i, __ATOMIC_RELAXED);
}

static inline int atomic_fetch_sub_release(int i, atomic_t *v)
{
	return __atomic_fetch_sub(&v->counter, i, __ATOMIC_RELEASE);
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
	return __sync_sub_and_fetch(&v->counter, 1) == 0;
}

#define cmpxchg(ptr, oldval, newval) \
	__sync_val_compare_and_swap(ptr, oldval, newval)

#define xchg(ptr, val) \
	__atomic_exchange_n(ptr, val, __ATOMIC_ACQ_REL)

static inline int atomic_cmpxchg(atomic_t *v, int oldval, int newval)
{
	return cmpxchg(&(v)->counter, oldval, newval);
}

static inline int atomic_xchg(atomic_t *v, int val)
{
	return xchg(&(v)->counter, val);
}

static __always_inline bool
atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg(v, o, new);
	if (unlikely(r != o))
		*old = r;
	return likely(r == o);
}

#endif
