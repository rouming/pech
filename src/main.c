#include <stdio.h>
#include <stdlib.h>
#include <sys/signalfd.h>
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

struct init_struct {
	struct task_struct  *start_task;
	struct ceph_options *opt;
	struct ceph_client  *client;
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

		param = (struct fs_parameter) {
			.key	= key,
			.type	= fs_value_is_flag,
		};
		value = strchr(key, '=');
		v_len = 0;

		if (value) {
			if (value == key)
				continue;

			*value++ = 0;
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
	struct ceph_client *client;

	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	unsigned long started;

	int ret, osd = init->osd;
	bool is_up;

	client = ceph_create_client(init->opt, NULL,
				    CEPH_ENTITY_TYPE_OSD, osd);
	if (unlikely(IS_ERR(client))) {
		ret = PTR_ERR(client);
		goto err;
	}

	ret = ceph_open_session(client);
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Ceph session opened\n");

	ret = ceph_monc_osd_to_crush_add(&client->monc, osd, "0.0010");
	if (unlikely(ret))
		goto err;

	pr_notice(">>>> Add osd.%d to crush\n", osd);

	ret = ceph_monc_osd_boot(&client->monc, osd, &init->opt->fsid);
	if (unlikely(ret))
		goto err;

	started = jiffies;
	is_up = false;
	while (!time_after_eq(jiffies, started + _5s)) {
		ret = ceph_wait_for_latest_osdmap(client, _300ms);
		if (unlikely(ret && ret != -ETIMEDOUT))
			goto err;

		if (!ret &&
		    ceph_osdmap_contains(client->osdc.osdmap, osd,
					 ceph_client_addr(client)) &&
		    ceph_osd_is_up(client->osdc.osdmap, osd)) {
			is_up = true;
			break;
		}
	}
	if (!is_up) {
		ret = -ETIMEDOUT;
		goto err;
	}

	BUG_ON(!ceph_osd_is_up(client->osdc.osdmap, osd));

	pr_notice(">>>> Boot osd.%d\n", osd);

	/* Ok, now can be set for outer usage */
	init->client = client;

	return 0;

err:
	ceph_destroy_client(client);

	/* Destroy the loop ourselves if stop task was not started */
	if (!init->stop_in_progress)
		destroy_loop();

	return ret;
}

static int stop_task(void *arg)
{
	struct init_struct *init = arg;

	unsigned long _300ms = msecs_to_jiffies(300);
	unsigned long _5s    = msecs_to_jiffies(5000);
	unsigned long started;

	int ret, osd = init->osd;
	bool is_down;

	ret = kthread_stop(init->start_task);
	put_task_struct(init->start_task);
	init->start_task = NULL;

	/* We mark osd down only if start task was successful */
	if (!ret) {
		struct ceph_client *client = init->client;

		ret = ceph_monc_osd_mark_me_down(&client->monc, osd);
		if (unlikely(ret && ret != -ETIMEDOUT)) {
			pr_err("mark_me_down: failed %d\n", ret);
			goto destroy_client;
		}

		started = jiffies;
		is_down = false;
		while (!time_after_eq(jiffies, started + _5s)) {
			ret = ceph_wait_for_latest_osdmap(client, _300ms);
			if (unlikely(ret && ret != -ETIMEDOUT)) {
				pr_err("latest_osdmap: failed %d\n", ret);
				break;
			}
			if (!ret &&
			    ceph_osdmap_contains(client->osdc.osdmap, osd,
						 ceph_client_addr(client)) &&
			    !ceph_osd_is_up(client->osdc.osdmap, osd)) {
				is_down = true;
				break;
			}
		}
		if (is_down)
			pr_notice(">>>> Tear down osd.%d\n", osd);
destroy_client:
		ceph_destroy_client(client);
	}

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

static void init_signals(struct init_struct *init)
{
	sigset_t set;
	int ret;

	sigfillset(&set);
	ret = sigprocmask(SIG_BLOCK, &set, NULL);
	BUG_ON(ret);

	/* We care about SIGINT and SIGTERM only */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	init->sig_fd = signalfd(-1, &set, 0);
	BUG_ON(init->sig_fd < 0);

	INIT_EVENT(&init->sig_ev, signal_event);
	init->sig_ev.events = EPOLLIN;
	ret = event_item_add(&init->sig_ev, init->sig_fd);
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

int main(int argc, char **argv)
{
	struct init_struct init;
	struct task_struct *task;
	int ret;

	memset(&init, 0, sizeof(init));

	init_sched();
	init_event();
	init_workqueue();
	init_modules();
	init_signals(&init);

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

	return 0;
}
