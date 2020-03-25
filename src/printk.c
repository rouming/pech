// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>

#include "types.h"
#include "bug.h"
#include "printk.h"

#define CUT_HERE		"------------[ cut here ]------------\n"

struct warn_args {
	const char *fmt;
	va_list args;
};

void __warn(const char *file, int line, void *caller, unsigned taint,
	    struct warn_args *args)
{
	if (file)
		pr_warn(" at %s:%d %pS\n", file, line,	caller);
	else
		pr_warn(" at %pS\n", caller);

	if (args)
		vprintf(args->fmt, args->args);
}

void warn_slowpath_fmt(const char *file, int line, unsigned taint,
		       const char *fmt, ...)
{
	struct warn_args args;

	pr_warn(CUT_HERE);

	if (!fmt) {
		__warn(file, line, __builtin_return_address(0), taint,
		       NULL);
		return;
	}

	args.fmt = fmt;
	va_start(args.args, fmt);
	__warn(file, line, __builtin_return_address(0), taint, &args);
	va_end(args.args);
}

static inline int printk_get_level(const char *buffer)
{
	if (buffer[0] == KERN_SOH_ASCII && buffer[1]) {
		switch (buffer[1]) {
		case '0' ... '7':
		case 'c':	/* KERN_CONT */
			return buffer[1] & 0x7;
		}
	}
	return 0;
}

static inline const char *printk_skip_level(const char *buffer)
{
	if (printk_get_level(buffer))
		return buffer + 2;

	return buffer;
}

static int current_log_level = LOGLEVEL_NOTICE;

static const char *prefix[] = {
	"  EMERG ",
	"  ALERT ",
	"   CRIT ",
	"    ERR ",
	"WARNING ",
	" NOTICE ",
	"   INFO ",
	"  DEBUG ",
};

void printk_set_current_level(int level)
{
	current_log_level = level & 0x7;
}

int vprintk(int level, const char *fmt, va_list args)
{
	int ret;

	level &= 0x7;

	if (current_log_level < level)
		return 0;

	ret = printf(prefix[level]);
	fmt = printk_skip_level(fmt);
	ret += vprintf(fmt, args);

	return ret;
}

int printk(const char *fmt, ...)
{
	int ret, level;
	va_list args;

	level = printk_get_level(fmt);
	va_start(args, fmt);
	ret = vprintk(level, fmt, args);
	va_end(args);

	return ret;
}
