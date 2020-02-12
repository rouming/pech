/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MODULE_H
#define _MODULE_H

struct kernel_param;

struct kernel_param_ops {
	/* How the ops should behave */
	unsigned int flags;
	/* Returns 0, or -errno.  arg is in kp->arg. */
	int (*set)(const char *val, const struct kernel_param *kp);
	/* Returns length written or -errno.  Buffer is 4k (ie. be short!) */
	int (*get)(char *buffer, const struct kernel_param *kp);
	/* Optional function to free kp->arg when module unloaded. */
	void (*free)(void *arg);
};

struct kernel_param {
	const struct kernel_param_ops *ops;
};

#define module_param_cb(...)
#define module_init(...)
#define module_exit(...)


#endif
