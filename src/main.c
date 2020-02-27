#include <stdio.h>
#include <stdlib.h>

#include "types.h"
#include "sched.h"
#include "timer.h"
#include "event.h"
#include "workqueue.h"
#include "timedef.h"
#include "err.h"
#include "module.h"

#include "ceph/libceph.h"

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

static int start_task(void *arg)
{
	struct ceph_options *opt = arg;
	struct ceph_client *client;
	int ret;

	client = ceph_create_client(opt, NULL,
				    CEPH_ENTITY_TYPE_OSD, 0);
	BUG_ON(IS_ERR(client));

	ret = ceph_open_session(client);
	BUG_ON(ret);

	printf("Ceph session opened!\n");

	ceph_destroy_client(client);

	return ret;
}

int main(int argc, char **argv)
{
	struct ceph_options *copt;
	struct task_struct *task;
	int ret;

	init_sched();
	init_event();
	init_workqueue();
	init_modules();

	copt = ceph_alloc_options();
	BUG_ON(!copt);

	ret = parse_options(copt, argc, argv);
	if (WARN(ret < 0, "failed to parse options: %d\n", ret))
		return -1;

	/* Firstly check required options */
	if (WARN(!copt->num_mon, "no 'mon_addrs' option is provided\n"))
		return -1;

	task = task_create(start_task, copt);
	BUG_ON(!task);
	wake_up_process(task);

	/* Run till the end */
	while (tasks_to_run())
		schedule();

	ceph_destroy_options(copt);

	/* Shut up valgrind and others */
//XXX	deinit_workqueue();

	return 0;
}
