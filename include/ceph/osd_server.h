/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_CEPH_OSD_SERVER_H
#define _FS_CEPH_OSD_SERVER_H

#include "ceph/types.h"
#include "ceph/osdmap.h"
#include "ceph/messenger.h"

struct ceph_osd_server;

extern struct ceph_osd_server *ceph_create_osd_server(
	struct ceph_options *opt, int osd);
extern int ceph_start_osd_server(struct ceph_osd_server *osds);
extern void ceph_destroy_osd_server(struct ceph_osd_server *server);

#endif
