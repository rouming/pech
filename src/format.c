#include <arpa/inet.h>
#include <printf.h>

#include "types.h"

struct printf_spec {
    /* Information parsed from the format spec.  */
    struct printf_info info;

    /* Pointers into the format string for the end of this format
       spec and the next (or to the end of the string if no more).  */
    const unsigned char *end_of_fmt, *next_fmt;
};

static int addr_type;

static void inet_addr_va_arg_function(void *mem, va_list *ap)
{
	void **pptr;

	pptr = mem;
	*pptr = va_arg(*ap, void *);
}

static int inet_addr_printf_function (FILE *fp, const struct printf_info *info,
				      const void *const *args)
{
	struct printf_spec *spec;
	char buff[128];
	void **addr;
	int ret, af;

	/*
	 * Here we need to be a bit smarter then glibc wants and look ahead
	 * into format, thus cast to a hidden glibc struct and get format
	 * pointers.
	 */
	spec = container_of(info, typeof(*spec), info);

	/* NB: Triple pointer indirection.  ARGS is an array of void *,
	   and those pointers point to a pointer to the memory area
	   supplied to inet_addr_va_arg_function.  */
	addr = *(void **) args[0];

	if (!strncmp("i4", spec->end_of_fmt, 2)) {
		/* Format 001.002.003.004 contiguous */
		spec->end_of_fmt += 2;
		af = AF_INET;
	} else if (!strncmp("i6", spec->end_of_fmt, 2)) {
		/* Format 000102...0f contiguous */
		spec->end_of_fmt += 2;
		af = AF_INET6;
	} else if (!strncmp("I4", spec->end_of_fmt, 2)) {
		/* Format 1.2.3.4 */
		spec->end_of_fmt += 2;
		af = AF_INET;
	} else if (!strncmp("I6", spec->end_of_fmt, 2)) {
		/* Format 0001:0203:...:0708 */
		spec->end_of_fmt += 2;
		af = AF_INET6;
	} else if (!strncmp("I6c", spec->end_of_fmt, 3)) {
		/* Format 1::708 or 1::1.2.3.4 */
		spec->end_of_fmt += 3;
		af = AF_INET6;
	} else {
		/* Emulate a normal %p behaviour */
		af = AF_UNSPEC;
	}

	if (af != AF_UNSPEC) {
		inet_ntop(af, *addr, buff, sizeof(buff));
	} else {
		if (*addr)
			snprintf(buff, sizeof(buff), "0x%lx", *addr);
		else
			snprintf(buff, sizeof(buff), "(nil)");
	}

	ret = fprintf(fp, "%s", buff);
	if (ret < 0)
		return -1;

	return ret;
}

static int inet_addr_arginfo_function (const struct printf_info *info,
				       size_t n, int *argtypes, int *size)
{
	argtypes[0] = addr_type;
	size[0] = sizeof(void *);

	return 1;
}

/*
 * Register specific to kernel printf formatting, like
 *   %pI4, %pI6, %pI6c, %pi4, %pi6
 */
void init_formatting(void)
{
	addr_type = register_printf_type(inet_addr_va_arg_function);
	register_printf_specifier('p', inet_addr_printf_function,
				  inet_addr_arginfo_function);
}
