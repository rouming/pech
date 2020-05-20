/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CEPH_STORE_H
#define __CEPH_STORE_H

#include "ceph/libceph.h"
#include "ceph/osd_client.h"
#include "ceph/osdmap.h"

struct ceph_store;
struct ceph_store_coll;
struct ceph_transaction;
struct ceph_msg_data_cursor;

struct ceph_store_ops {
	struct ceph_store_coll *(*open_collection)(struct ceph_store *store,
						   struct ceph_spg *spg);
	struct ceph_store_coll *(*create_collection)(struct ceph_store *store,
						     struct ceph_spg *spg);
	int (*execute_ro_osd_op)(struct ceph_store_coll *coll,
				 struct ceph_hobject_id *hoid,
				 struct ceph_osd_req_op *op);
	int (*execute_transaction)(struct ceph_store *store,
				   struct ceph_transaction *txn);
	void (*destroy)(struct ceph_store *store);
};

struct ceph_store {
	struct ceph_store_ops *ops;
	struct ceph_options   *opt;
};

static inline struct ceph_store_coll *
ceph_store_open_collection(struct ceph_store *s, struct ceph_spg *spg)
{
	return s->ops->open_collection(s, spg);
}

static inline struct ceph_store_coll *
ceph_store_create_collection(struct ceph_store *s, struct ceph_spg *spg)
{
	return s->ops->create_collection(s, spg);
}

static inline int ceph_store_execute_ro_osd_op(struct ceph_store *s,
					       struct ceph_store_coll *coll,
					       struct ceph_hobject_id *hoid,
					       struct ceph_osd_req_op *op)
{
	return s->ops->execute_ro_osd_op(coll, hoid, op);
}

static inline int ceph_store_execute_transaction(struct ceph_store *s,
						 struct ceph_transaction *txn)
{
	return s->ops->execute_transaction(s, txn);
}

static inline void ceph_store_destroy(struct ceph_store *s)
{
	s->ops->destroy(s);
}

#endif /* __CEPH_STORE_H */
