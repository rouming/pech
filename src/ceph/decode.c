// SPDX-License-Identifier: GPL-2.0

#include "ceph/decode.h"
#include "ceph/ceph_features.h"

static int
ceph_decode_entity_addr_versioned(void **p, void *end,
				  struct ceph_entity_addr *addr)
{
	int ret;
	u8 struct_v;
	u32 struct_len, addr_len;
	void *struct_end;

	ret = ceph_start_decoding(p, end, 1, "entity_addr_t", &struct_v,
				  &struct_len);
	if (ret)
		goto bad;

	ret = -EINVAL;
	struct_end = *p + struct_len;

	ceph_decode_copy_safe(p, end, &addr->type, sizeof(addr->type), bad);

	ceph_decode_copy_safe(p, end, &addr->nonce, sizeof(addr->nonce), bad);

	ceph_decode_32_safe(p, end, addr_len, bad);
	if (addr_len > sizeof(addr->in_addr))
		goto bad;

	memset(&addr->in_addr, 0, sizeof(addr->in_addr));
	if (addr_len) {
		ceph_decode_copy_safe(p, end, &addr->in_addr, addr_len, bad);

		addr->in_addr.ss_family =
			le16_to_cpu((__force __le16)addr->in_addr.ss_family);
	}

	/* Advance past anything the client doesn't yet understand */
	*p = struct_end;
	ret = 0;
bad:
	return ret;
}

static int
ceph_decode_entity_addr_legacy(void **p, void *end,
			       struct ceph_entity_addr *addr)
{
	int ret = -EINVAL;

	/* Skip rest of type field */
	ceph_decode_skip_n(p, end, 3, bad);

	/*
	 * Clients that don't support ADDR2 always send TYPE_NONE, change it
	 * to TYPE_LEGACY for forward compatibility.
	 */
	addr->type = CEPH_ENTITY_ADDR_TYPE_LEGACY;
	ceph_decode_copy_safe(p, end, &addr->nonce, sizeof(addr->nonce), bad);
	memset(&addr->in_addr, 0, sizeof(addr->in_addr));
	ceph_decode_copy_safe(p, end, &addr->in_addr,
			      sizeof(addr->in_addr), bad);
	addr->in_addr.ss_family =
			be16_to_cpu((__force __be16)addr->in_addr.ss_family);
	ret = 0;
bad:
	return ret;
}

int
ceph_decode_entity_addr(void **p, void *end, struct ceph_entity_addr *addr)
{
	u8 marker;

	ceph_decode_8_safe(p, end, marker, bad);
	if (marker == 1)
		return ceph_decode_entity_addr_versioned(p, end, addr);
	else if (marker == 0)
		return ceph_decode_entity_addr_legacy(p, end, addr);
bad:
	return -EINVAL;
}
EXPORT_SYMBOL(ceph_decode_entity_addr);

static size_t
ceph_get_sockaddr_len(struct ceph_entity_addr *addr)
{
	switch (addr->in_addr.ss_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	}
	return sizeof(addr->in_addr);
}

static void ceph_copy_sock_addr(struct sockaddr_storage *in_addr,
				const struct ceph_entity_addr *addr)
{
	BUILD_BUG_ON(sizeof(*in_addr) != sizeof(addr->in_addr));
	memcpy(in_addr, &addr->in_addr, sizeof(*in_addr));
}

static int
ceph_encode_entity_addr_versioned(void **p, void *end,
				  struct ceph_entity_addr *addr)
{
	struct sockaddr_storage in_addr;
	u32 type, addr_len, *struct_len;
	void *start;

	int ret = -EINVAL;

	/* Marker */
	ceph_encode_8_safe(p, end, 1, bad);
	ceph_start_encoding_safe(p, end, 1, 1, &struct_len, bad);
	start = *p;

	type = CEPH_ENTITY_ADDR_TYPE_LEGACY;
	ceph_encode_copy_safe(p, end, &type, sizeof(type), bad);
	ceph_encode_copy_safe(p, end, &addr->nonce, sizeof(addr->nonce), bad);

	addr_len = ceph_get_sockaddr_len(addr);
	ceph_encode_32_safe(p, end, addr_len, bad);

	ceph_copy_sock_addr(&in_addr, addr);
	ceph_encode_copy_safe(p, end, &in_addr, addr_len, bad);

	/* Finalize structure size */
	*struct_len = *p - start;

	ret = 0;
bad:
	return ret;
}

static int
ceph_encode_entity_addr_legacy(void **p, void *end,
			       struct ceph_entity_addr *addr)
{
	struct sockaddr_storage in_addr;
	int ret = -EINVAL;

	ceph_encode_32_safe(p, end, 0, bad);
	ceph_encode_copy_safe(p, end, &addr->nonce, sizeof(addr->nonce), bad);
	ceph_copy_sock_addr(&in_addr, addr);
	ceph_encode_copy_safe(p, end, &in_addr, sizeof(in_addr), bad);

	ret = 0;
bad:
	return ret;
}

int
ceph_encode_single_entity_addrvec(void **p, void *end,
				  struct ceph_entity_addr *addr,
				  uint64_t features)
{
	int ret = -EINVAL;

	if (!(features & CEPH_FEATURE_MSG_ADDR2))
		/* Legacy addr */
		return ceph_encode_entity_addr_legacy(p, end, addr);

	/* Vector addr marker */
	ceph_encode_8_safe(p, end, 2, bad);
	/* Vector addr size */
	ceph_encode_32_safe(p, end, 1, bad);
	/* Single addr entity */
	ret = ceph_encode_entity_addr_versioned(p, end, addr);

bad:
	return ret;
}
EXPORT_SYMBOL(ceph_encode_single_entity_addrvec);
