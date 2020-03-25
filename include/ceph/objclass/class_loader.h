/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CEPH_CLASS_LOADER_H
#define _CEPH_CLASS_LOADER_H

#include "ceph/libceph.h"
#include "ceph/objclass/objclass.h"
#include "rbtree.h"

enum {
	CEPH_CLS_UNKNOWN,
	CEPH_CLS_MISSING,
	CEPH_CLS_MISSING_DEPS,
	CEPH_CLS_INITIALIZING,
	CEPH_CLS_OPEN,


	CEPH_CLS_METHOD_RD      = 0x1,  /* read operations */
	CEPH_CLS_METHOD_WR      = 0x2,  /* write operations */
	CEPH_CLS_METHOD_PROMOTE = 0x8,  /* cannot be proxied to base tier */

	CEPH_CLS_METHOD_CXX     = 1<<16 /* internally set by ceph_pech_proxy */
};

typedef int (ceph_cls_proxy_call_t)(struct ceph_cls_proxy_call_ctx *);

struct ceph_cls_loader {
	struct rb_root         l_classes;
	struct ceph_options    *l_opts;
	void                   *l_proxy;
	ceph_cls_proxy_call_t  *l_proxy_call;
	bool                    l_proxy_failed;
};

struct ceph_cls {
	char             c_name[16];
	struct ceph_cls_loader
			 *c_loader;
	void             *c_handle;
	unsigned         c_status;
	struct rb_root   c_methods;
	struct rb_node   c_node;  /* entry in ->h_classes */
};

struct ceph_cls_method {
	char                   m_name[128];
	ceph_cls_method_call_t *m_func;
	struct ceph_cls        *m_cls;
	struct rb_node         m_node;  /* entry in ->c_methods */
	int                    m_flags;
};


/* Invoked by OSD server */

extern void ceph_cls_init(struct ceph_cls_loader *cl,
			  struct ceph_options *opt);
extern void ceph_cls_deinit(struct ceph_cls_loader *cl);
extern int ceph_cls_method_call(struct ceph_cls_loader *cl,
				const char *cname, const char *mname,
				struct ceph_cls_call_ctx *ctx);

/* Invoked by classes */

struct ceph_cls_loader *ceph_cls_loader_instance(void);
extern struct ceph_cls *ceph_cls_register_class(struct ceph_cls_loader *cl,
						const char *cname);
extern struct ceph_cls_method *
ceph_cls_register_method(struct ceph_cls *cls, const char *mname,
			 int flags, ceph_cls_method_call_t *func);

#endif /*_CEPH_CLASS_LOADER_H */
