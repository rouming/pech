/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KEY_H
#define _KEY_H

union key_payload {
	void __rcu		*rcu_data0;
	void			*data[4];
};

struct key {
	union key_payload payload;
};

struct key_type {};
struct key_acl {};

extern struct key *request_key(struct key_type *type,
			       const char *description,
			       const char *callout_info,
			       struct key_acl *acl);

extern void key_put(struct key *key);

#endif
