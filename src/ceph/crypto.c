// SPDX-License-Identifier: GPL-2.0

#include "types.h"
#include "key.h"
#include "types.h"
#include "crypto.h"

/*
 * Currently nothing interesting here
 */

int ceph_crypto_key_clone(struct ceph_crypto_key *dst,
			  const struct ceph_crypto_key *src)
{
	return -ENOTSUP;
}

int ceph_crypto_key_encode(struct ceph_crypto_key *key, void **p, void *end)
{
	return -ENOTSUP;
}

int ceph_crypto_key_decode(struct ceph_crypto_key *key, void **p, void *end)
{
	return -ENOTSUP;
}

int ceph_crypto_key_unarmor(struct ceph_crypto_key *key, const char *in)
{
	return -ENOTSUP;
}

void ceph_crypto_key_destroy(struct ceph_crypto_key *key)
{
}

int ceph_crypt(const struct ceph_crypto_key *key, bool encrypt,
	       void *buf, int buf_len, int in_len, int *pout_len)
{
	return -ENOTSUP;
}

struct key_type key_type_ceph = {
};

int __init ceph_crypto_init(void)
{
	return -ENOTSUP;
}

void ceph_crypto_shutdown(void)
{
}
