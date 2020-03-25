// SPDX-License-Identifier: GPL-2.0

#include "ceph/objclass/class_loader.h"

#include <dlfcn.h>

static __thread struct ceph_cls_loader *cls_loader;

#define CLS_PREFIX "libcls_"
#define CLS_SUFFIX ".so"

#define CLS_PROXY_LIB  "libceph_pech_proxy.so"
#define CLS_PROXY_CALL "cls_proxy_method_call"

/**
 * Define RB functions for class lookup by name
 */
DEFINE_RB_FUNCS2(cls_by_name, struct ceph_cls, c_name,
		 strcmp, RB_BYVAL, char *, c_node);

/**
 * Define RB functions for method lookup by name
 */
DEFINE_RB_FUNCS2(method_by_name, struct ceph_cls_method, m_name,
		 strcmp, RB_BYVAL, char *, m_node);

void ceph_cls_init(struct ceph_cls_loader *cl,
		   struct ceph_options *opt)
{
	cl->l_classes = RB_ROOT;
	cl->l_proxy = NULL;
	cl->l_proxy_failed = false;
	cl->l_opts = opt;
}

static void cls_method_free(struct ceph_cls_method *method)
{
	erase_method_by_name(&method->m_cls->c_methods, method);
	kfree(method);
}

static void cls_free(struct ceph_cls *cls)
{
	struct ceph_cls_loader *cl = cls->c_loader;
	struct ceph_cls_method *method;

	erase_cls_by_name(&cl->l_classes, cls);

	while ((method = rb_entry_safe(rb_first(&cls->c_methods),
				       typeof(*method), m_node))) {
		cls_method_free(method);
	}

	if (cls->c_handle)
		dlclose(cls->c_handle);

	kfree(cls);
}

void ceph_cls_deinit(struct ceph_cls_loader *cl)
{
	struct ceph_cls *cls;

	while ((cls = rb_entry_safe(rb_first(&cl->l_classes),
				    typeof(*cls), c_node))) {
		cls_free(cls);
	}

	if (cl->l_proxy)
		dlclose(cl->l_proxy);
}

static int cls_load_proxy(struct ceph_cls_loader *cl)
{
	char path[PATH_MAX];
	char *error;

	if (likely(cl->l_proxy))
		return 0;

	if (cl->l_proxy_failed)
		/* Already failed once */
		return -ENOENT;

	snprintf(path, sizeof(path), "%s/" CLS_PROXY_LIB,
		 cl->l_opts->class_dir ?: ".");

	cl->l_proxy = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (!cl->l_proxy) {
		pr_err("%s: failed to load '%s': %s\n",
		       __func__, path, dlerror());

		cl->l_proxy_failed = true;
		return -ENOENT;
	}

	dlerror(); /* clear any existing error */

	cl->l_proxy_call = dlsym(cl->l_proxy, CLS_PROXY_CALL);
	error = dlerror();
	if (error) {
		pr_err("%s: failed to load '%s' in '%s': %s\n",
		       __func__, CLS_PROXY_CALL, path, error);

		dlclose(cl->l_proxy);
		cl->l_proxy = NULL;
		cl->l_proxy_call = NULL;
		cl->l_proxy_failed = true;

		return -ENOENT;
	}

	return 0;
}

static struct ceph_cls *cls_find_or_load(struct ceph_cls_loader *cl,
					 const char *cname)
{
	void (*cls_init)(void);
	struct ceph_cls *cls;
	char path[PATH_MAX];
	const char *error;
	size_t len;
	int ret;

	/* Load proxy library at the very beginning */
	ret = cls_load_proxy(cl);
	if (unlikely(ret))
		return NULL;

	cls = lookup_cls_by_name(&cl->l_classes, (char *)cname);
	if (likely(cls))
		return cls;

	cls = kmalloc(sizeof(*cls), GFP_KERNEL);
	if (!cls)
		return NULL;

	cls->c_handle = NULL;
	cls->c_loader = cl;
	cls->c_status = CEPH_CLS_UNKNOWN;
	cls->c_methods = RB_ROOT;
	RB_CLEAR_NODE(&cls->c_node);

	len = snprintf(cls->c_name, sizeof(cls->c_name), "%s", cname);
	if (len >= sizeof(cls->c_name)) {
		pr_warn("%s: class name '%s' is too long\n",
			__func__, cname);
		kfree(cls);
		return NULL;
	}
	snprintf(path, sizeof(path), "%s/" CLS_PREFIX "%s" CLS_SUFFIX,
		 cl->l_opts->class_dir ?: ".", cname);

	/* Now is in the tree */
	insert_cls_by_name(&cl->l_classes, cls);

	/* Load class library */
	cls->c_handle = dlopen(path, RTLD_NOW);
	if (!cls->c_handle) {
		pr_err("%s: failed to load '%s': %s\n",
		       __func__, path, dlerror());

		cls->c_status = CEPH_CLS_MISSING;
		return cls;
	}

	dlerror(); /* clear any existing error */

	cls_init = dlsym(cls->c_handle, "__cls_init");
	error = dlerror();
	if (error) {
		pr_err("%s: failed to load '__cls_init' in '%s': %s\n",
		       __func__, path, error);

		dlclose(cls->c_handle);
		cls->c_handle = NULL;

		cls->c_status = CEPH_CLS_MISSING;
		return cls;
	}

	cls->c_status = CEPH_CLS_INITIALIZING;
	/* Argh, that's ugly */
	cls_loader = cl;
	cls_init();
	cls_loader = NULL;
	cls->c_status = CEPH_CLS_OPEN;

	return cls;
}

int ceph_cls_method_call(struct ceph_cls_loader *cl,
			 const char *cname, const char *mname,
			 struct ceph_cls_call_ctx *ctx)
{
	struct ceph_cls_proxy_call_ctx proxy_ctx;
	struct ceph_cls_method *method;
	struct ceph_cls *cls;

	cls = cls_find_or_load(cl, cname);
	if (!cls)
		return -EPERM;

	if (cls->c_status != CEPH_CLS_OPEN)
		return -ENOENT;

	method = lookup_method_by_name(&cls->c_methods, (char *)mname);
	if (!method)
		return -EOPNOTSUPP;

	proxy_ctx = (struct ceph_cls_proxy_call_ctx) {
		.ctx     = ctx,
		.func    = method->m_func,
		.is_cxx  = !!(method->m_flags & CEPH_CLS_METHOD_CXX),
	};
	return cl->l_proxy_call(&proxy_ctx);
}

/*
 * Called from classes side
 */

/**
 * ceph_cls_loader_instance() - should be called only as a callback
 *                              from __cls_init() entry point.
 */
struct ceph_cls_loader *ceph_cls_loader_instance(void)
{
	BUG_ON(!cls_loader);
	return cls_loader;
}

struct ceph_cls *ceph_cls_register_class(struct ceph_cls_loader *cl,
					 const char *cname)
{
	struct ceph_cls *cls;

	cls = lookup_cls_by_name(&cl->l_classes, (char *)cname);
	if (unlikely(!cls || cls->c_status != CEPH_CLS_INITIALIZING))
		return NULL;

	return cls;
}

struct ceph_cls_method *
ceph_cls_register_method(struct ceph_cls *cls, const char *mname,
			 int flags, ceph_cls_method_call_t *func)
{
	struct ceph_cls_method *method;
	size_t len;

	if (!(flags & ~CEPH_CLS_METHOD_CXX)) {
		pr_warn("%s: wrong flags '%d' for method '%s'\n",
			__func__, flags, mname);
		return NULL;
	}

	method = lookup_method_by_name(&cls->c_methods, (char *)mname);
	if (unlikely(method)) {
		pr_warn("%s: method '%s' is already registered\n",
			__func__, mname);
		return NULL;
	}

	method = kmalloc(sizeof(*method), GFP_KERNEL);
	if (!method)
		return NULL;

	method->m_func = func;
	method->m_cls = cls;
	method->m_flags = flags;
	RB_CLEAR_NODE(&method->m_node);

	len = snprintf(method->m_name, sizeof(method->m_name), "%s", mname);
	if (len >= sizeof(method->m_name)) {
		pr_warn("%s: method name '%s' is too long\n",
			__func__, mname);
		kfree(method);
		return NULL;
	}

	/* Now is in the tree */
	insert_method_by_name(&cls->c_methods, method);

	return method;
}
