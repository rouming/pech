/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CEPH_MEMSTORE_H
#define __CEPH_MEMSTORE_H

#include "ceph/store.h"

struct ceph_store *ceph_memstore_create(struct ceph_options *opt);

#endif /* __CEPH_MEMSTORE_H */
