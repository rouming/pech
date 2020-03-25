// SPDX-License-Identifier: GPL-2.0

#include "types.h"

#include "ceph/objclass/objclass.h"
#include "ceph/objclass/class_loader.h"

int cls_log(int level, const char *fmt, ...)
{
	char fmt_cpy[128];
	va_list args;
	int ret;

	level = clamp_val(level, 0, 20);

	if (level == 20)
		level = LOGLEVEL_DEBUG;
	else
		/* Map to log level where max DEBUG is 7 */
		level = level/3;

	/* Add forgotten '\n' to format */
	ret = snprintf(fmt_cpy, sizeof(fmt_cpy), "%s\n", fmt);
	if (ret < sizeof(fmt_cpy))
		fmt = fmt_cpy;

	va_start(args, fmt);
	vprintk(level, fmt, args);
	va_end(args);

	return 0;
}

int cls_register(const char *name, struct ceph_cls **pcls)
{
	struct ceph_cls_loader *cl = ceph_cls_loader_instance();
	struct ceph_cls *cls;

	cls  = ceph_cls_register_class(cl, name);
	if (!cls)
		/* Argh */
		return 0;

	*pcls = cls;
	return 1;
}

int cls_register_method(struct ceph_cls *cls, const char *mname,
			int flags, ceph_cls_method_call_t *func,
			struct ceph_cls_method **pmethod)
{
	struct ceph_cls_method *method;

	if (!(flags & (CEPH_CLS_METHOD_RD | CEPH_CLS_METHOD_WR |
		       CEPH_CLS_METHOD_CXX)))
		return -EINVAL;

	method = ceph_cls_register_method(cls, mname, flags, func);
	if (!method)
		/* Sigh */
		return 0;

	*pmethod = method;
	return 1;
}
