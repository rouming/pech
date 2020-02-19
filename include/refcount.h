/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _REFCOUNT_H_
#define _REFCOUNT_H_

#include "types.h"
#include "atomic.h"

typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }
#define REFCOUNT_MAX		INT_MAX
#define REFCOUNT_SATURATED	(INT_MIN / 2)

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF,
	REFCOUNT_ADD_OVF,
	REFCOUNT_ADD_UAF,
	REFCOUNT_SUB_UAF,
	REFCOUNT_DEC_LEAK,
};

void refcount_warn_saturate(refcount_t *r, enum refcount_saturation_type t);

/**
 * refcount_set - set a refcount's value
 * @r: the refcount
 * @n: value to which the refcount will be set
 */
static inline void refcount_set(refcount_t *r, int n)
{
	atomic_set(&r->refs, n);
}

/**
 * refcount_read - get a refcount's value
 * @r: the refcount
 *
 * Return: the refcount's value
 */
static inline unsigned int refcount_read(const refcount_t *r)
{
	return atomic_read(&r->refs);
}


/**
 * refcount_add_not_zero - add a value to a refcount unless it is 0
 * @i: the value to add to the refcount
 * @r: the refcount
 *
 * Will saturate at REFCOUNT_SATURATED and WARN.
 *
 * Provides no memory ordering, it is assumed the caller has guaranteed the
 * object memory to be stable (RCU, etc.). It does provide a control dependency
 * and thereby orders future stores. See the comment on top.
 *
 * Use of this function is not recommended for the normal reference counting
 * use case in which references are taken and released one at a time.  In these
 * cases, refcount_inc(), or one of its variants, should instead be used to
 * increment a reference count.
 *
 * Return: false if the passed refcount is 0, true otherwise
 */
static inline __must_check bool refcount_add_not_zero(int i, refcount_t *r)
{
	int old = refcount_read(r);

	do {
		if (!old)
			break;
	} while (!atomic_try_cmpxchg_relaxed(&r->refs, &old, old + i));

	if (unlikely(old < 0 || old + i < 0))
		refcount_warn_saturate(r, REFCOUNT_ADD_NOT_ZERO_OVF);

	return old;
}

/**
 * refcount_add - add a value to a refcount
 * @i: the value to add to the refcount
 * @r: the refcount
 *
 * Similar to atomic_add(), but will saturate at REFCOUNT_SATURATED and WARN.
 *
 * Provides no memory ordering, it is assumed the caller has guaranteed the
 * object memory to be stable (RCU, etc.). It does provide a control dependency
 * and thereby orders future stores. See the comment on top.
 *
 * Use of this function is not recommended for the normal reference counting
 * use case in which references are taken and released one at a time.  In these
 * cases, refcount_inc(), or one of its variants, should instead be used to
 * increment a reference count.
 */
static inline void refcount_add(int i, refcount_t *r)
{
	int old = atomic_fetch_add_relaxed(i, &r->refs);

	if (unlikely(!old))
		refcount_warn_saturate(r, REFCOUNT_ADD_UAF);
	else if (unlikely(old < 0 || old + i < 0))
		refcount_warn_saturate(r, REFCOUNT_ADD_OVF);
}

/**
 * refcount_inc_not_zero - increment a refcount unless it is 0
 * @r: the refcount to increment
 *
 * Similar to atomic_inc_not_zero(), but will saturate at REFCOUNT_SATURATED
 * and WARN.
 *
 * Provides no memory ordering, it is assumed the caller has guaranteed the
 * object memory to be stable (RCU, etc.). It does provide a control dependency
 * and thereby orders future stores. See the comment on top.
 *
 * Return: true if the increment was successful, false otherwise
 */
static inline __must_check bool refcount_inc_not_zero(refcount_t *r)
{
	return refcount_add_not_zero(1, r);
}

/**
 * refcount_inc - increment a refcount
 * @r: the refcount to increment
 *
 * Similar to atomic_inc(), but will saturate at REFCOUNT_SATURATED and WARN.
 *
 * Provides no memory ordering, it is assumed the caller already has a
 * reference on the object.
 *
 * Will WARN if the refcount is 0, as this represents a possible use-after-free
 * condition.
 */
static inline void refcount_inc(refcount_t *r)
{
	refcount_add(1, r);
}

/**
 * refcount_sub_and_test - subtract from a refcount and test if it is 0
 * @i: amount to subtract from the refcount
 * @r: the refcount
 *
 * Similar to atomic_dec_and_test(), but it will WARN, return false and
 * ultimately leak on underflow and will fail to decrement when saturated
 * at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides an acquire ordering on success such that free()
 * must come after.
 *
 * Use of this function is not recommended for the normal reference counting
 * use case in which references are taken and released one at a time.  In these
 * cases, refcount_dec(), or one of its variants, should instead be used to
 * decrement a reference count.
 *
 * Return: true if the resulting refcount is 0, false otherwise
 */
static inline __must_check bool refcount_sub_and_test(int i, refcount_t *r)
{
	int old = atomic_fetch_sub_release(i, &r->refs);

	if (old == i) {
		smp_acquire__after_ctrl_dep();
		return true;
	}

	if (unlikely(old < 0 || old - i < 0))
		refcount_warn_saturate(r, REFCOUNT_SUB_UAF);

	return false;
}

/**
 * refcount_dec_and_test - decrement a refcount and test if it is 0
 * @r: the refcount
 *
 * Similar to atomic_dec_and_test(), it will WARN on underflow and fail to
 * decrement when saturated at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides an acquire ordering on success such that free()
 * must come after.
 *
 * Return: true if the resulting refcount is 0, false otherwise
 */
static inline __must_check bool refcount_dec_and_test(refcount_t *r)
{
	return refcount_sub_and_test(1, r);
}

#endif
