#ifndef CEPH_OBJCLASS_H
#define CEPH_OBJCLASS_H

#include "ceph/messenger.h"
#include "ceph/msgr.h"
#include "ceph/rados.h"

struct ceph_cls_call_ctx;
struct ceph_cls_req_desc;
struct ceph_cls_method;
struct ceph_cls;

typedef void ceph_cls_method_call_t;

/**
 * Method call context with everything needed for back calls.
 *
 * NOTE: do not change the members without fixing the proxy
 *       'cls_proxy_method_call' in libceph_pech_proxy.so.
 */
struct ceph_cls_call_ctx {
	struct ceph_cls_callback_ops
				*ops;
	const void              *in;
	struct ceph_kvec        **out;
	unsigned int            in_len;
};

/**
 * Back calls operations for classes.
 *
 * NOTE: do not change the parameters without fixing the proxy
 *       'cls_proxy_method_call' in libceph_pech_proxy.so.
 */
struct ceph_cls_callback_ops {
	int (*execute_op)(struct ceph_cls_call_ctx *ctx,
			  struct ceph_osd_op *op,
			  struct ceph_kvec *in,
			  struct ceph_kvec **out);
	int (*describe_req)(struct ceph_cls_call_ctx *ctx,
			    struct ceph_cls_req_desc *desc);
};

/**
 * Proxy call context, describes how method should be called.
 *
 * NOTE: do not change the parameters without fixing the proxy
 *       'cls_proxy_method_call' in libceph_pech_proxy.so.
 */
struct ceph_cls_proxy_call_ctx {
	struct ceph_cls_call_ctx *ctx;
	ceph_cls_method_call_t   *func;
	unsigned int             is_cxx;  /* 1 if method is registered as CXX */
};

/**
 * Request description.
 *
 * NOTE: do not change the members without fixing the proxy
 *       'cls_proxy_method_call' in libceph_pech_proxy.so.
 */
struct ceph_cls_req_desc {
	struct ceph_entity_inst source;
	uint64_t                peer_features;
};

/* Basic entry points for classes */

int cls_log(int level, const char *fmt, ...);
int cls_register(const char *name, struct ceph_cls **pcls);
int cls_register_method(struct ceph_cls *cls, const char *mname,
			int flags, ceph_cls_method_call_t *func,
			struct ceph_cls_method **pmethod);

#endif /* CEPH_OBJCLASS_H */
