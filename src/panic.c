#include <stdio.h>

#include "types.h"
#include "bug.h"

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
