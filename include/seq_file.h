/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SEQ_FILE_H
#define _SEQ_FILE_H

#include "types.h"
#include "mutex.h"

struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	u64 version;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};

#define seq_puts(...)
#define seq_putc(...)
#define seq_escape(...)
#define seq_printf(...)

#endif
