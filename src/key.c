// SPDX-License-Identifier: GPL-2.0-or-later

#include "types.h"
#include "err.h"
#include "key.h"

struct key *request_key(struct key_type *type,
			const char *description,
			const char *callout_info,
			struct key_acl *acl)
{
	return ERR_PTR(-ENOTSUP);
}

void key_put(struct key *key)
{
}
