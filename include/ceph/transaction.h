/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CEPH_TRANSACTION_H
#define __CEPH_TRANSACTION_H

#include "ceph/messenger.h"
#include "ceph/osdmap.h"
#include "ceph/osd_client.h"

enum {
	TXN_OP_OSD    =       0,
	TXN_OP_TOUCH  =       9,   /* cid, oid */
	TXN_OP_MKCOLL =       20,  /* cid */
};

struct ceph_transaction_op {
	struct ceph_spg             spg;
	struct ceph_hobject_id      hoid;
	struct timespec64           mtime;
	struct ceph_osd_req_op      *op;
	int                         type;
};

struct ceph_transaction {
	struct ceph_transaction_op *ops_arr[8];
	struct ceph_transaction_op **ops;
	int                        max_ops;
	int                        nr_ops;
};

void ceph_transaction_init(struct ceph_transaction *txn);
void ceph_transaction_deinit(struct ceph_transaction *txn);

int ceph_transaction_add_osd_op(struct ceph_transaction *txn,
				struct ceph_spg *spg,
				struct ceph_hobject_id *hoid,
				struct timespec64 *mtime,
				struct ceph_osd_req_op *op);

int ceph_transaction_mkcoll(struct ceph_transaction *txn,
			    struct ceph_spg *spg);

int ceph_transaction_touch(struct ceph_transaction *txn,
			   struct ceph_spg *spg,
			   struct ceph_hobject_id *hoid);

#endif /* __CEPH_TRANSACTION_H */
