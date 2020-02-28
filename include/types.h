/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bits/wordsize.h>
#include <linux/types.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <ctype.h>
#include <stddef.h>
#include <inttypes.h>

#include "kconfig.h"

#define BITS_PER_LONG __WORDSIZE

#if BITS_PER_LONG != 64
#error Currently 64 bits are supported only
#endif

#define U8_MAX		((u8)~0U)
#define S8_MAX		((s8)(U8_MAX >> 1))

#define U64_MAX		((u64)~0ULL)
#define S64_MAX		((s64)(U64_MAX >> 1))
#define S64_MIN		((s64)(-S64_MAX - 1))

/*
 * calling noreturn functions, __builtin_unreachable() and __builtin_trap()
 * confuse the stack allocation in gcc, leading to overly large stack
 * frames, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82365
 *
 * Adding an empty inline assembly before it works around the problem
 */
#define barrier_before_unreachable() asm volatile("")

/* Copied from linux/compiler-gcc.h since we can't include it directly */
#define barrier() __asm__ __volatile__("": : :"memory")

#define smp_acquire__after_ctrl_dep()		barrier()
#define smp_mb() barrier()
#define smp_store_mb(var, value)  do { WRITE_ONCE(var, value); barrier(); } while (0)

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#include "bug.h"

#define __must_check		__attribute__((__warn_unused_result__))
#define __packed		__attribute__((__packed__))
#define __malloc		__attribute__((__malloc__))
#define __aligned(x)		__attribute__((__aligned__(x)))
#define __force
#define __rcu
#define __user
#define __init
#define __exit
#define __sched
#define __kernel

#define might_sleep()
#define might_fault()

#define access_ok(...) (1)
#define kasan_check_read(...)
#define kasan_check_write(...)

#define raw_copy_to_user(to, from, n) ({			\
	memcpy(to, from, n);					\
        0;							\
})

#define raw_copy_from_user(to, from, n) ({			\
	memcpy(to, from, n);					\
	0;							\
})

#define copy_from_user(to, from, n)		\
	raw_copy_from_user(to, from, n)
#define copy_to_user(to, from, n)		\
	raw_copy_to_user(to, from, n)

#define zero_user_segment(page, start, end)			\
	memset(page_address(page) + start, 0, end - start)

#define fault_in_pages_writeable(...) (0)

//XXX
typedef unsigned int gfp_t;

typedef int8_t   __s8;
typedef uint8_t  __u8;
typedef int16_t  __s16;
typedef uint16_t __u16;
typedef int32_t  __s32;
typedef uint32_t __u32;
typedef size_t   __kernel_size_t;

typedef __u32 u32;
typedef __u64 u64;
typedef __u16 u16;
typedef __u8 u8;
typedef __s8 s8;
typedef __s64 s64;
typedef __s32 s32;

#define ERESTARTSYS	512
#define ENOPARAM	519	/* Parameter not supported */
#define ENOTSUPP	524	/* Operation is not supported */

#define kstrtouint(s, b, r)						\
	({ typeof(*r) n; errno = 0; n = strtoumax(s, NULL, b);		\
	   -errno ?: (*r = n, 0);					\
	})
#define kstrtoint(s, b, r)						\
	({ typeof(*r) n; errno = 0; n = strtoimax(s, NULL, b);		\
	   -errno ?: (*r = n, 0);					\
	})
#define kstrtoull(s, b, r)						\
	({ typeof(*r) n; errno = 0; n = strtoull(s, NULL, b);		\
	   -errno ?: (*r = n, 0);					\
	})

#include "overflow.h"

typedef u64 sector_t;
typedef unsigned int __bitwise slab_flags_t;

#define le64_to_cpu(x)  le64toh(x)
#define le32_to_cpu(x)  le32toh(x)
#define le16_to_cpu(x)  le16toh(x)

#define cpu_to_le64(x)  htole64(x)
#define cpu_to_le32(x)  htole32(x)
#define cpu_to_le16(x)  htole16(x)

#define __cpu_to_le64(x)  htole64(x)
#define __cpu_to_le32(x)  htole32(x)
#define __cpu_to_le16(x)  htole16(x)

#define be64_to_cpu(x)  be64toh(x)
#define be32_to_cpu(x)  be32toh(x)
#define be16_to_cpu(x)  be16toh(x)

#define cpu_to_be64(x)  htobe64(x)
#define cpu_to_be32(x)  htobe32(x)
#define cpu_to_be16(x)  htobe16(x)

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_AUTHOR(x);
#define MODULE_DESCRIPTION(x);
#define MODULE_LICENSE(x);

#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

#define KBUILD_MODNAME ""

# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)


#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))

/**
 * BUILD_BUG_ON_MSG - break compile if a condition is true & emit supplied
 *		      error message.
 * @condition: the condition which the compiler should know is false.
 *
 * See BUILD_BUG_ON for description.
 */
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * some other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 */
#define BUILD_BUG_ON(condition) \
	BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)



/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define	MAX_SCHEDULE_TIMEOUT		LONG_MAX

/* generic data direction definitions */
#define READ			0
#define WRITE			1

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))



/* Indirect macros required for expanded argument pasting, eg. __LINE__. */
#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)


// kernel.h

#define DIV64_U64_ROUND_UP(ll, d)	\
	({ u64 _tmp = (d); div64_u64((ll) + _tmp - 1, _tmp); })

#define DIV_ROUND_DOWN_ULL(ll, d)					\
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })

#define DIV_ROUND_UP_ULL(ll, d) \
	DIV_ROUND_DOWN_ULL((unsigned long long)(ll) + (d) - 1, (d))

/*
 * min()/max()/clamp() macros must accomplish three things:
 *
 * - avoid multiple evaluations of the arguments (so side-effects like
 *   "x++" happen only once) when non-constant.
 * - perform strict type-checking (to generate warnings instead of
 *   nasty runtime surprises). See the "unnecessary" pointer comparison
 *   in __typecheck().
 * - retain result as a constant expressions when called with only
 *   constant expressions (to avoid tripping VLA warnings in stack
 *   allocation usage).
 */
#define __typecheck(x, y) \
		(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))

#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))

#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))

#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })

#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))

/**
 * min - return minimum of two values of the same or compatible types
 * @x: first value
 * @y: second value
 */
#define min(x, y)	__careful_cmp(x, y, <)

/**
 * max - return maximum of two values of the same or compatible types
 * @x: first value
 * @y: second value
 */
#define max(x, y)	__careful_cmp(x, y, >)

/**
 * min_t - return minimum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)

/**
 * max_t - return maximum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define max_t(type, x, y)	__careful_cmp((type)(x), (type)(y), >)

/**
 * clamp_t - return a value clamped to a given range using a given type
 * @type: the type of variable to use
 * @val: current value
 * @lo: minimum allowable value
 * @hi: maximum allowable value
 *
 * This macro does no typechecking and uses temporary variables of type
 * @type to make all the comparisons.
 */
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)

/**
 * clamp_val - return a value clamped to a given range using val's type
 * @val: current value
 * @lo: minimum allowable value
 * @hi: maximum allowable value
 *
 * This macro does no typechecking and uses temporary variables of whatever
 * type the input argument @val is.  This is useful when @val is an unsigned
 * type and @lo and @hi are literals that will otherwise be assigned a signed
 * integer type.
 */
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })




#define __compiletime_warning(message) __attribute__((__warning__(message)))
#define __compiletime_error(message) __attribute__((__error__(message)))

#define __compiletime_object_size(obj) __builtin_object_size(obj, 0)

static inline void check_object_size(const void *ptr, unsigned long n,
				     bool to_user)
{ }

extern void __compiletime_error("copy source size is too small")
__bad_copy_from(void);
extern void __compiletime_error("copy destination size is too small")
__bad_copy_to(void);

static inline void copy_overflow(int size, unsigned long count)
{
	WARN(1, "Buffer overflow detected (%d < %lu)!\n", size, count);
}

static __always_inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	int sz = __compiletime_object_size(addr);
	if (unlikely(sz >= 0 && sz < bytes)) {
		if (!__builtin_constant_p(bytes))
			copy_overflow(sz, bytes);
		else if (is_source)
			__bad_copy_from();
		else
			__bad_copy_to();
		return false;
	}
	if (WARN_ON_ONCE(bytes > INT_MAX))
		return false;
	check_object_size(addr, bytes, is_source);
	return true;
}

// div64.h

/**
 * do_div - returns 2 values: calculate remainder and update new dividend
 * @n: uint64_t dividend (will be updated)
 * @base: uint32_t divisor
 *
 * Summary:
 * ``uint32_t remainder = n % base;``
 * ``n = n / base;``
 *
 * Return: (uint32_t)remainder
 *
 * NOTE: macro parameter @n is evaluated multiple times,
 * beware of side effects!
 */
# define do_div(n,base) ({					\
	uint32_t __base = (base);				\
	uint32_t __rem;						\
	__rem = ((uint64_t)(n)) % __base;			\
	(n) = ((uint64_t)(n)) / __base;				\
	__rem;							\
 })

// math64.h

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 32bit divisor
 * @remainder: pointer to unsigned 32bit remainder
 *
 * Return: sets ``*remainder``, then returns dividend / divisor
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_u64_rem - unsigned 64bit divide with 64bit divisor and remainder
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 64bit divisor
 * @remainder: pointer to unsigned 64bit remainder
 *
 * Return: sets ``*remainder``, then returns dividend / divisor
 */
static inline u64 div64_u64_rem(u64 dividend, u64 divisor, u64 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_u64 - unsigned 64bit divide with 64bit divisor
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 64bit divisor
 *
 * Return: dividend / divisor
 */
static inline u64 div64_u64(u64 dividend, u64 divisor)
{
	return dividend / divisor;
}

/**
 * div64_s64 - signed 64bit divide with 64bit divisor
 * @dividend: signed 64bit dividend
 * @divisor: signed 64bit divisor
 *
 * Return: dividend / divisor
 */
static inline s64 div64_s64(s64 dividend, s64 divisor)
{
	return dividend / divisor;
}

/**
 * div_u64 - unsigned 64bit divide with 32bit divisor
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 32bit divisor
 *
 * This is the most common 64bit divide and should be used if possible,
 * as many 32bit archs can optimize this variant better than a full 64bit
 * divide.
 */
#ifndef div_u64
static inline u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;
	return div_u64_rem(dividend, divisor, &remainder);
}
#endif

// typecheck.h

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

/*
 * Check at compile time that 'function' is a certain type, or is a pointer
 * to that type (needs to use typedef for the function type.)
 */
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})

// builtin-fls.h

/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
#define __fls(x) (!(x) ? 0 : sizeof(x) * 8 - __builtin_clz(x))
#define fls(x)   __fls(x)
#define fls64(x) __fls(x)
#define fls_long(x) __fls(x)

#endif
