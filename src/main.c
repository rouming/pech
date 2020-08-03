#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <unistd.h>

#include "types.h"
#include "sched.h"
#include "timer.h"
#include "event.h"
#include "workqueue.h"
#include "timedef.h"
#include "err.h"
#include "module.h"
#include "printk.h"

#include "ceph/libceph.h"
#include "ceph/ceph_features.h"
#include "ceph/osd_server.h"

struct init_struct {
	struct task_struct  *start_task;
	struct ceph_options *opt;
	struct ceph_osd_server *osds;
	struct event_item   sig_ev;
	bool                stop_in_progress;
	int                 sig_fd;
	int                 osd;
};

static int parse_options(struct ceph_options *opts, int argc, char **argv)
{
	int ret = 0, i;

	for (i = 1; i < argc; i++) {
		struct fs_parameter param;
		char *key, *value;
		size_t v_len;

		key = argv[i];
		dout("%s '%s'\n", __func__, key);

		if (strncmp(key, "--", 2)) {
			pr_err("%s: key '%s' does not start with '--'\n",
			       __func__, key);
			return -EINVAL;
		}
		key += 2;

		param = (struct fs_parameter) {
			.key	= key,
			.type	= fs_value_is_flag,
		};

		if (i + 1 < argc) {
			value = argv[i + 1];
			if (strncmp(value, "--", 2))
				i++;
			else
				value = NULL;
		} else {
			value = NULL;
		}

		v_len = 0;
		if (value) {
			v_len = strlen(value);

			/* Parse 'mon_addrs=' just here */
			if (!strcmp(key, "mon_addrs")) {
				ret = ceph_parse_mon_ips(value, v_len,
							 opts, NULL);
				if (ret)
					break;
				continue;
			}
			/* Parse 'log_level=' just here */
			if (!strcmp(key, "log_level")) {
				printk_set_current_level(atoi(value));
				continue;
			}

			param.string = strndup(value, v_len);
			if (!param.string)
				return -ENOMEM;
			param.type = fs_value_is_string;
		}
		param.size = v_len;

		ret = ceph_parse_param(&param, opts, NULL);
		free(param.string);
		if (ret)
			break;
	}

	return ret;
}

static void destroy_loop(void)
{
	/* Eventually tear down the rest after which we exit the loop */
	deinit_workqueue();
	deinit_event();
}

static int start_task(void *arg)
{
	struct init_struct *init = arg;
	struct ceph_osd_server *osds;
	int ret;

	osds = ceph_create_osd_server(init->opt, init->osd);
	if (unlikely(IS_ERR(osds))) {
		ret = PTR_ERR(osds);
		goto err;
	}

	ret = ceph_start_osd_server(osds);
	if (unlikely(ret))
		goto err;

	/* Ok, now can be set for outer usage */
	init->osds = osds;

	return 0;

err:
	ceph_destroy_osd_server(osds);

	/* Destroy the loop ourselves if stop task was not started */
	if (!init->stop_in_progress)
		destroy_loop();

	return ret;
}

static int stop_task(void *arg)
{
	struct init_struct *init = arg;
	int ret;

	ret = kthread_stop(init->start_task);
	put_task_struct(init->start_task);
	init->start_task = NULL;

	/* We mark osd down only if start task was successful */
	if (!ret)
		ceph_destroy_osd_server(init->osds);

	/* Stops the rest */
	destroy_loop();

	return 0;
}

static void signal_event(struct event_item *ev)
{
	struct init_struct *init;
	struct task_struct *task;
	int ret;

	init = container_of(ev, typeof(*init), sig_ev);

	/* Firstly delete signal event to avoid repeating calls */
	ret = event_item_del(&init->sig_ev);
	BUG_ON(ret);
	close(init->sig_fd);
	init->sig_fd = -1;

	/* Create and wake up task which stops everything */
	task = task_create(stop_task, init);
	BUG_ON(!task);
	wake_up_process(task);

	/*
	 * Let the start task know that there is a reaper which will do
	 * the stop job.
	 */
	init->stop_in_progress = true;
}

static __thread struct init_struct *init_struct;

static void sig_handler(int signum)
{
	u64 v = 1;
	write(init_struct->sig_fd, &v, sizeof(v));
}

static void init_signals(struct init_struct *init)
{
	struct sigaction sa;
	sigset_t set;
	int ret;

	BUG_ON(init_struct);
	init_struct = init;

	sigfillset(&set);
	ret = sigprocmask(SIG_BLOCK, &set, NULL);
	BUG_ON(ret);

	/*
	 * Why not to use signalfd? The problem is that kernel
	 * function signalfd_poll() checks pending signals for
	 * *current* process, but userpoll offloads vfs_epoll() call
	 * to a worker (see ep_poll_callback_work()), which means
	 * pending signals of the worker will be checked and 0 is
	 * returned, obviously not what we expected.
	 */
	init->sig_fd = eventfd(0, EFD_NONBLOCK);
	BUG_ON(init->sig_fd < 0);

	INIT_EVENT(&init->sig_ev, signal_event);
	init->sig_ev.events = EPOLLET | EPOLLIN;
	ret = event_item_add(&init->sig_ev, init->sig_fd);
	BUG_ON(ret);

	/* We care about SIGINT and SIGTERM only */
	sigfillset(&set);
	sigdelset(&set, SIGINT);
	sigdelset(&set, SIGTERM);
	ret = sigprocmask(SIG_SETMASK, &set, NULL);
	BUG_ON(ret);

	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	ret = sigaction(SIGINT, &sa, NULL);
	BUG_ON(ret);
	ret = sigaction(SIGTERM, &sa, NULL);
	BUG_ON(ret);
}

static int parse_osd_id(const char *name)
{
	long osd_id;
	char *end;

	osd_id = strtol(name, &end, 10);
	if (strlen(end))
		return -EINVAL;

	if (osd_id > INT_MAX || osd_id < 0)
		return -EINVAL;

	return osd_id;
}

static void init_logging(void)
{
	/*
	 * Disable buffering for stdout. This is needed in case of
	 * systemd service.
	 */
	setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char **argv)
{
	struct init_struct init;
	struct task_struct *task;
	int ret;

	memset(&init, 0, sizeof(init));

	/* First init logging and formatting */
	init_logging();
	init_formatting();

	init.opt = ceph_alloc_options();
	BUG_ON(!init.opt);

	ret = parse_options(init.opt, argc, argv);
	if (WARN(ret < 0, "failed to parse options: %d\n", ret))
		return -1;

	/* Firstly check required options */
	if (WARN(!init.opt->num_mon, "no 'mon_addrs' option is provided\n"))
		return -1;
	if (WARN(!init.opt->name, "no 'name' option is provided, which should be an id of osd\n"))
		return -1;

	init.osd = parse_osd_id(init.opt->name);
	if (WARN(init.osd < 0, "'name' option does not contain a valid integer\n"))
		return -1;

	/* Init the rest */
	init_pages();
	init_sched();
	init_event(!ceph_test_opt(init.opt, NO_UEPOLL));
	init_workqueue();
	init_modules();
	init_signals(&init);

	/* Create start task and wake up it */
	task = task_create(start_task, &init);
	BUG_ON(!task);
	wake_up_process(task);

	/* Start task is accessed from stop_task, so increase the ref */
	get_task_struct(task);
	init.start_task = task;

	/* Run till the end */
	while (tasks_to_run())
		schedule();

	deinit_pages();

	return 0;
}
