#include <stdio.h>
#include <stdlib.h>

#include "types.h"
#include "sched.h"
#include "timer.h"
#include "event.h"
#include "workqueue.h"
#include "timedef.h"
#include "err.h"

static void wq1(struct work_struct *work)
{
	printf("%s begin %p\n", __func__, work);
	schedule();
	printf("%s end %p\n", __func__, work);
}

static void dwq1(struct work_struct *work)
{
	printf("%s\n", __func__);
}

static void start_task(void *arg)
{
	struct workqueue_struct *wq;
	struct work_struct works[32];
	struct delayed_work dwork;

	int i;
	bool res;

	wq = alloc_workqueue("1", 0, 2);

	for (i = 0; i < ARRAY_SIZE(works); i++) {
		INIT_WORK(&works[i], wq1);
	}
	INIT_DELAYED_WORK(&dwork, dwq1);

	res = queue_delayed_work(wq, &dwork, msecs_to_jiffies(1000));
	BUG_ON(!res);

	res = flush_delayed_work(&dwork);
	BUG_ON(!res);

	printf("flushed delayed work\n");

	for (i = 0; i < 10; i++) {
		res = queue_work(wq, &works[i]);
		BUG_ON(!res);
	}

	flush_workqueue(wq);

	printf("everything flushed, destroy\n");

	destroy_workqueue(wq);

	/* Stop event loop, which forces app to exit */
//	stop_event();
}

int main(int argc, char **argv)
{
	struct task_struct *task;

	init_sched();
	init_event();
	init_workqueue();

	task = task_create(start_task, NULL);
	BUG_ON(IS_ERR(task));
	wake_up_process(task);

	/* Run till the end */
	while (tasks_to_run())
		schedule();

	/* Shut up valgrind and others */
//XXX	deinit_workqueue();

	return 0;
}
