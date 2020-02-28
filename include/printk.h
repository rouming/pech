/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PRINTK_H
#define _PRINTK_H

#define __printf(a, b)		__attribute__((__format__(printf, a, b)))

#define KERN_SOH	"\001"		/* ASCII Start Of Header */
#define KERN_SOH_ASCII	'\001'

#define KERN_EMERG	KERN_SOH "0"	/* system is unusable */
#define KERN_ALERT	KERN_SOH "1"	/* action must be taken immediately */
#define KERN_CRIT	KERN_SOH "2"	/* critical conditions */
#define KERN_ERR	KERN_SOH "3"	/* error conditions */
#define KERN_WARNING	KERN_SOH "4"	/* warning conditions */
#define KERN_NOTICE	KERN_SOH "5"	/* normal but significant condition */
#define KERN_INFO	KERN_SOH "6"	/* informational */
#define KERN_DEBUG	KERN_SOH "7"	/* debug-level messages */

#define LOGLEVEL_EMERG		0	/* system is unusable */
#define LOGLEVEL_ALERT		1	/* action must be taken immediately */
#define LOGLEVEL_CRIT		2	/* critical conditions */
#define LOGLEVEL_ERR		3	/* error conditions */
#define LOGLEVEL_WARNING	4	/* warning conditions */
#define LOGLEVEL_NOTICE		5	/* normal but significant condition */
#define LOGLEVEL_INFO		6	/* informational */
#define LOGLEVEL_DEBUG		7	/* debug-level messages */

extern __printf(1, 2) int printk(const char *s, ...);
extern void printk_set_current_level(int level);

/* TODO */
#define print_hex_dump(...)

/*
 * These can be used to print at the various log levels.
 * All of these will print unconditionally, although note that pr_debug()
 * and other debug macros are compiled out unless either DEBUG is defined
 * or CONFIG_DYNAMIC_DEBUG is set.
 */
#define pr_emerg(fmt, ...) \
	printk(KERN_EMERG fmt, ##__VA_ARGS__)
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	printk(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) \
	printk(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	printk(KERN_INFO fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	printk(KERN_DEBUG fmt, ##__VA_ARGS__)

/* TODO */
#define printk_ratelimited(...) printk(__VA_ARGS__)

#define pr_emerg_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_EMERG fmt, ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ALERT fmt, ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_CRIT fmt, ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_NOTICE fmt, ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_INFO fmt, ##__VA_ARGS__)
/* no pr_cont_ratelimited, don't do that... */

#define pr_devel_ratelimited(...)					\
	printk_ratelimited(__VA_ARGS__)


#endif
