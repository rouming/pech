// SPDX-License-Identifier: GPL-2.0

#include "mutex.h"
#include "ceph/osd_client.h"

int ceph_osdc_setup(void)
{
	return 0;
}

void ceph_osdc_cleanup(void)
{
}

int ceph_osdc_init(struct ceph_osd_client *osdc,
		   struct ceph_client *client)
{
	return 0;
}

void ceph_osdc_stop(struct ceph_osd_client *osdc)
{
}

void ceph_osdc_reopen_osds(struct ceph_osd_client *osdc)
{
}

void ceph_osdc_handle_map(struct ceph_osd_client *osdc,
			  struct ceph_msg *msg)
{
}

void ceph_osdc_maybe_request_map(struct ceph_osd_client *osdc)
{
}
