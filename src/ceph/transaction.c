// SPDX-License-Identifier: GPL-2.0

#include "ceph/transaction.h"

void ceph_transaction_init(struct ceph_transaction *txn)
{
	txn->ops = txn->ops_arr;
	txn->max_ops = ARRAY_SIZE(txn->ops_arr);
	txn->nr_ops = 0;
}

void ceph_transaction_deinit(struct ceph_transaction *txn)
{
	struct ceph_transaction_op *op;
	int i;

	for (i = 0; i < txn->nr_ops; i++) {
		op = txn->ops[i];
		kfree(op);
	}
	if (txn->ops != txn->ops_arr)
		kfree(txn->ops);
}

static struct ceph_transaction_op *add_trans_op(struct ceph_transaction *txn)
{
	struct ceph_transaction_op *txn_op;

	if (unlikely(txn->nr_ops == txn->max_ops)) {
		struct ceph_transaction_op **ops;
		int sz = txn->max_ops << 1;
		bool fixed_arr;

		fixed_arr = (txn->ops == txn->ops_arr);
		ops = (fixed_arr ? NULL : txn->ops);
		ops = krealloc(ops, sz * sizeof(*ops), GFP_KERNEL);
		if (!ops)
			return NULL;

		if (unlikely(fixed_arr))
			memcpy(ops, txn->ops_arr, sizeof(txn->ops_arr));

		txn->ops = ops;
		txn->max_ops = sz;
	}

	txn_op = kmalloc(sizeof(*txn_op), GFP_KERNEL);
	if (unlikely(!txn_op))
		return NULL;

	txn->ops[txn->nr_ops++] = txn_op;

	return txn_op;
}

int ceph_transaction_add_osd_op(struct ceph_transaction *txn,
				struct ceph_spg *spg,
				struct ceph_hobject_id *hoid,
				struct timespec64 *mtime,
				struct ceph_osd_req_op *op)
{
	struct ceph_transaction_op *txn_op;

	txn_op = add_trans_op(txn);
	if (unlikely(!txn_op))
		return -ENOMEM;

	txn_op->type = TXN_OP_OSD;
	txn_op->spg = *spg;
	txn_op->mtime = *mtime;
	txn_op->op = op;

	ceph_hoid_init(&txn_op->hoid);
	ceph_hoid_copy(&txn_op->hoid, hoid);

	return 0;
}

int ceph_transaction_mkcoll(struct ceph_transaction *txn,
			    struct ceph_spg *spg)
{
	struct ceph_transaction_op *txn_op;

	txn_op = add_trans_op(txn);
	if (unlikely(!txn_op))
		return -ENOMEM;

	txn_op->type = TXN_OP_MKCOLL;
	txn_op->spg = *spg;
	ceph_hoid_init(&txn_op->hoid);

	return 0;
}

int ceph_transaction_touch(struct ceph_transaction *txn,
			   struct ceph_spg *spg,
			   struct ceph_hobject_id *hoid)
{
	struct ceph_transaction_op *txn_op;

	txn_op = add_trans_op(txn);
	if (unlikely(!txn_op))
		return -ENOMEM;

	txn_op->type = TXN_OP_TOUCH;
	txn_op->spg = *spg;

	ceph_hoid_init(&txn_op->hoid);
	ceph_hoid_copy(&txn_op->hoid, hoid);

	return 0;

}
