// SPDX-License-Identifier: GPL-2.0-only
//#include <linux/export.h>
#include "bvec.h"
#include "types.h"
#include "uio.h"
#include "slab.h"


#define iterate_iovec(i, n, __v, __p, skip, STEP) {	\
	size_t left;					\
	size_t wanted = n;				\
	__p = i->iov;					\
	__v.iov_len = min(n, __p->iov_len - skip);	\
	if (likely(__v.iov_len)) {			\
		__v.iov_base = __p->iov_base + skip;	\
		left = (STEP);				\
		__v.iov_len -= left;			\
		skip += __v.iov_len;			\
		n -= __v.iov_len;			\
	} else {					\
		left = 0;				\
	}						\
	while (unlikely(!left && n)) {			\
		__p++;					\
		__v.iov_len = min(n, __p->iov_len);	\
		if (unlikely(!__v.iov_len))		\
			continue;			\
		__v.iov_base = __p->iov_base;		\
		left = (STEP);				\
		__v.iov_len -= left;			\
		skip = __v.iov_len;			\
		n -= __v.iov_len;			\
	}						\
	n = wanted - n;					\
}

#define iterate_kvec(i, n, __v, __p, skip, STEP) {	\
	size_t wanted = n;				\
	__p = i->kvec;					\
	__v.iov_len = min(n, __p->iov_len - skip);	\
	if (likely(__v.iov_len)) {			\
		__v.iov_base = __p->iov_base + skip;	\
		(void)(STEP);				\
		skip += __v.iov_len;			\
		n -= __v.iov_len;			\
	}						\
	while (unlikely(n)) {				\
		__p++;					\
		__v.iov_len = min(n, __p->iov_len);	\
		if (unlikely(!__v.iov_len))		\
			continue;			\
		__v.iov_base = __p->iov_base;		\
		(void)(STEP);				\
		skip = __v.iov_len;			\
		n -= __v.iov_len;			\
	}						\
	n = wanted;					\
}

#define iterate_bvec(i, n, __v, __bi, skip, STEP) {	\
	struct bvec_iter __start;			\
	__start.bi_size = n;				\
	__start.bi_bvec_done = skip;			\
	__start.bi_idx = 0;				\
	for_each_bvec(__v, i->bvec, __bi, __start) {	\
		if (!__v.bv_len)			\
			continue;			\
		(void)(STEP);				\
	}						\
}

#define iterate_all_kinds(i, n, v, I, B, K) {			\
	if (likely(n)) {					\
		size_t skip = i->iov_offset;			\
		if (unlikely(i->type & ITER_BVEC)) {		\
			struct bio_vec v;			\
			struct bvec_iter __bi;			\
			iterate_bvec(i, n, v, __bi, skip, (B))	\
		} else if (unlikely(i->type & ITER_KVEC)) {	\
			const struct kvec *kvec;		\
			struct kvec v;				\
			iterate_kvec(i, n, v, kvec, skip, (K))	\
		} else if (unlikely(i->type & ITER_DISCARD)) {	\
		} else {					\
			const struct iovec *iov;		\
			struct iovec v;				\
			iterate_iovec(i, n, v, iov, skip, (I))	\
		}						\
	}							\
}

#define iterate_and_advance(i, n, v, I, B, K) {			\
	if (unlikely(i->count < n))				\
		n = i->count;					\
	if (i->count) {						\
		size_t skip = i->iov_offset;			\
		if (unlikely(i->type & ITER_BVEC)) {		\
			const struct bio_vec *bvec = i->bvec;	\
			struct bio_vec v;			\
			struct bvec_iter __bi;			\
			iterate_bvec(i, n, v, __bi, skip, (B))	\
			i->bvec = __bvec_iter_bvec(i->bvec, __bi);	\
			i->nr_segs -= i->bvec - bvec;		\
			skip = __bi.bi_bvec_done;		\
		} else if (unlikely(i->type & ITER_KVEC)) {	\
			const struct kvec *kvec;		\
			struct kvec v;				\
			iterate_kvec(i, n, v, kvec, skip, (K))	\
			if (skip == kvec->iov_len) {		\
				kvec++;				\
				skip = 0;			\
			}					\
			i->nr_segs -= kvec - i->kvec;		\
			i->kvec = kvec;				\
		} else if (unlikely(i->type & ITER_DISCARD)) {	\
			skip += n;				\
		} else {					\
			const struct iovec *iov;		\
			struct iovec v;				\
			iterate_iovec(i, n, v, iov, skip, (I))	\
			if (skip == iov->iov_len) {		\
				iov++;				\
				skip = 0;			\
			}					\
			i->nr_segs -= iov - i->iov;		\
			i->iov = iov;				\
		}						\
		i->count -= n;					\
		i->iov_offset = skip;				\
	}							\
}

void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
			const struct kvec *kvec, unsigned long nr_segs,
			size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	i->type = ITER_KVEC | (direction & (READ | WRITE));
	i->kvec = kvec;
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	i->count = count;
}

void iov_iter_bvec(struct iov_iter *i, unsigned int direction,
			const struct bio_vec *bvec, unsigned long nr_segs,
			size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	i->type = ITER_BVEC | (direction & (READ | WRITE));
	i->bvec = bvec;
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	i->count = count;
}

int iov_iter_for_each_range(struct iov_iter *i, size_t bytes,
			    int (*f)(struct kvec *vec, void *context),
			    void *context)
{
	struct kvec w;
	int err = -EINVAL;
	if (!bytes)
		return 0;

	iterate_all_kinds(i, bytes, v, -EINVAL, ({
		w.iov_base = kmap(v.bv_page) + v.bv_offset;
		w.iov_len = v.bv_len;
		err = f(&w, context);
		kunmap(v.bv_page);
		err;}), ({
		w = v;
		err = f(&w, context);})
	)
	return err;
}
