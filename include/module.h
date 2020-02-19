/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MODULE_H
#define _MODULE_H

#include "types.h"
#include "list.h"

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

struct module {
	struct list_head entry;
	int (*init)(void);
	void (*exit)(void);
};

extern struct list_head modules_list;

extern void init_modules(void);

#define module_param_cb(...)

#define module_init(init_fn)						\
	static struct module this_module = {				\
		.entry = LIST_HEAD_INIT(this_module.entry),		\
		.init  = init_fn					\
	};								\
	__attribute__((constructor))					\
	static void register_##init_fn(void)				\
	{								\
		list_add_tail(&this_module.entry, &modules_list);	\
	}

#define module_exit(exit_fn)						\
	__attribute__((constructor))					\
	static void register_##init_fn(void)				\
	{								\
		this_module.exit = exit_fn;				\
	}

#endif
