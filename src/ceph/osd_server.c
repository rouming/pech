// SPDX-License-Identifier: GPL-2.0

#include "ceph/ceph_debug.h"

#include "module.h"
#include "err.h"
#include "slab.h"

#include "semaphore.h"

#include "ceph/ceph_features.h"
#include "ceph/libceph.h"
#include "ceph/osd_server.h"
#include "ceph/messenger.h"
#include "ceph/decode.h"
#include "ceph/auth.h"

static const struct ceph_connection_operations osds_con_ops;

struct ceph_osds_con {
	struct ceph_connection con;
	struct kref ref;
};

static int osds_accept_con(struct ceph_connection *con)
{
	pr_err("@@ con %p\n", con);

	return 0;
}

static struct ceph_connection *osds_alloc_con(struct ceph_messenger *msgr)
{
	struct ceph_osds_con *osds_con;

	osds_con = kzalloc(sizeof(*osds_con), GFP_NOIO | __GFP_NOFAIL);
	if (unlikely(!osds_con))
		return NULL;

	kref_init(&osds_con->ref);

	return &osds_con->con;
}

static struct ceph_connection *osds_con_get(struct ceph_connection *con)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(con, typeof(*osds_con), con);
	kref_get(&osds_con->ref);

	return con;
}

static void osds_free_con(struct kref *ref)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(ref, typeof(*osds_con), ref);
	kfree(osds_con);
}

static void osds_con_put(struct ceph_connection *con)
{
	struct ceph_osds_con *osds_con;

	osds_con = container_of(con, typeof(*osds_con), con);
	kref_put(&osds_con->ref, osds_free_con);
}

static void osds_dispatch(struct ceph_connection *con, struct ceph_msg *msg)
{
	int type = le16_to_cpu(msg->hdr.type);

	pr_err("@@ message type %d %s\n", type,
	       ceph_msg_type_name(type));


	ceph_msg_put(msg);
}

static struct ceph_msg *alloc_msg_with_page_vector(struct ceph_msg_header *hdr)
{
	struct ceph_msg *m;
	int type = le16_to_cpu(hdr->type);
	u32 front_len = le32_to_cpu(hdr->front_len);
	u32 data_len = le32_to_cpu(hdr->data_len);

	m = ceph_msg_new2(type, front_len, 1, GFP_NOIO, false);
	if (!m)
		return NULL;

	if (data_len) {
		struct page **pages;

		pages = ceph_alloc_page_vector(calc_pages_for(0, data_len),
					       GFP_NOIO);
		if (IS_ERR(pages)) {
			ceph_msg_put(m);
			return NULL;
		}

		ceph_msg_data_add_pages(m, pages, data_len, 0, true);
	}

	return m;
}

static struct ceph_msg *osds_alloc_msg(struct ceph_connection *con,
				       struct ceph_msg_header *hdr,
				       int *skip)
{
	int type = le16_to_cpu(hdr->type);

	*skip = 0;
	switch (type) {
	case CEPH_MSG_OSD_MAP:
	case CEPH_MSG_OSD_BACKOFF:
	case CEPH_MSG_WATCH_NOTIFY:
	case CEPH_MSG_OSD_OP:
		return alloc_msg_with_page_vector(hdr);
	case CEPH_MSG_OSD_OPREPLY:
		/* fall through */
	default:
		pr_warn("%s unknown msg type %d, skipping\n", __func__,
			type);
		*skip = 1;
		return NULL;
	}
}

static void osds_fault(struct ceph_connection *con)
{
	ceph_con_close(con);
	osds_con_put(con);
}

struct ceph_osd_server *
ceph_create_osd_server(struct ceph_options *opt, int osd)
{
	struct ceph_osd_server *osds;
	struct ceph_client *client;
	int ret;

	osds = kzalloc(sizeof(*osds), GFP_KERNEL);
	if (unlikely(!osds))
		return ERR_PTR(-ENOMEM);

	osds->osd = osd;

	client = __ceph_create_client(opt, osds, CEPH_ENTITY_TYPE_OSD,
				      osd, CEPH_FEATURES_SUPPORTED_OSD,
				      CEPH_FEATURES_REQUIRED_DEFAULT);
	if (unlikely(IS_ERR(client))) {
		ret = PTR_ERR(client);
		goto err;
	}
	osds->client = client;

	return osds;

err:
	kfree(osds);
	return ERR_PTR(ret);
}

static void ceph_stop_osd_server(struct ceph_osd_server *osds)
{
	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	unsigned long started;

	struct ceph_client *client = osds->client;
	bool is_down;
	int ret;

	ret = ceph_monc_osd_mark_me_down(&client->monc, osds->osd);
	if (unlikely(ret && ret != -ETIMEDOUT)) {
		pr_err("mark_me_down: failed %d\n", ret);
		return;
	}

	started = jiffies;
	is_down = false;
	while (!time_after_eq(jiffies, started + _5s)) {
		ret = ceph_wait_for_latest_osdmap(client, _300ms);
		if (unlikely(ret && ret != -ETIMEDOUT)) {
			pr_err("latest_osdmap: failed %d\n", ret);
			break;
		}
		if (!ret &&
		    ceph_osdmap_contains(client->osdc.osdmap, osds->osd,
					 ceph_client_addr(client)) &&
		    !ceph_osd_is_up(client->osdc.osdmap, osds->osd)) {
			is_down = true;
			break;
		}
	}
	if (is_down)
		pr_notice(">>>> Tear down osd.%d\n", osds->osd);
}

void ceph_destroy_osd_server(struct ceph_osd_server *osds)
{
	ceph_stop_osd_server(osds);
	ceph_destroy_client(osds->client);
	kfree(osds);
}

int ceph_start_osd_server(struct ceph_osd_server *osds)
{
	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	unsigned long started;

	struct ceph_client *client = osds->client;
	bool is_up;
	int ret;

	ret = ceph_open_session(client);
	if (unlikely(ret))
		return ret;

	pr_notice(">>>> Ceph session opened\n");

	ret = ceph_messenger_start_listen(&client->msgr, &osds_con_ops);
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Start listening\n");

	ret = ceph_monc_osd_to_crush_add(&client->monc, osds->osd, "0.0010");
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Add osd.%d to crush\n", osds->osd);

	ret = ceph_monc_osd_boot(&client->monc, osds->osd,
				 &client->options->fsid);
	if (unlikely(ret))
		goto err;

	started = jiffies;
	is_up = false;
	while (!time_after_eq(jiffies, started + _5s)) {
		ret = ceph_wait_for_latest_osdmap(client, _300ms);
		if (unlikely(ret && ret != -ETIMEDOUT))
			goto err;

		if (!ret &&
		    ceph_osdmap_contains(client->osdc.osdmap, osds->osd,
					 ceph_client_addr(client)) &&
		    ceph_osd_is_up(client->osdc.osdmap, osds->osd)) {
			is_up = true;
			break;
		}
	}
	if (!is_up) {
		ret = -ETIMEDOUT;
		goto err;
	}

	WARN_ON(!ceph_osd_is_up(client->osdc.osdmap, osds->osd));

	pr_notice(">>>> Boot osd.%d\n", osds->osd);

	return 0;

err:
	ceph_messenger_stop_listen(&client->msgr);

	return ret;
}

static const struct ceph_connection_operations osds_con_ops = {
	.alloc_con     = osds_alloc_con,
	.accept_con    = osds_accept_con,
	.get           = osds_con_get,
	.put           = osds_con_put,
	.dispatch      = osds_dispatch,
	.fault         = osds_fault,
	.alloc_msg     = osds_alloc_msg,
};
