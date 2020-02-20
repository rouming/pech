/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_H
#define _NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "gfp.h"
#include "uio.h"

typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;

/*
 *	As we do 4.4BSD message passing we use a 4.4BSD message passing
 *	system, not 4.3. Thus msg_accrights(len) are now missing. They
 *	belong in an obscure libc emulation or the bin.
 */

struct kmsghdr {
	void		*msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */
	struct iov_iter	msg_iter;	/* data */
	void		*msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
	unsigned int	msg_flags;	/* flags on received message */
	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
};

static inline
int in_pton(int af, const char *src, int srclen, u8 *dst,
	    int delim, const char **end)
{
	char *src_dup, *port;
	int ret;

	(void)delim;

	if ((port = strchr(src, ':')))
		srclen = min(srclen, (int)(port - src));
	src_dup = strndup(src, srclen);
	if (!src_dup)
		return -ENOMEM;
	ret = inet_pton(AF_INET, src_dup, dst);
	ret = ret < 0 ? -errno : ret;
	free(src_dup);

	if (ret == 1 && end)
		*end = src + srclen;

	return ret;
}

static inline
int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end)
{
	return in_pton(AF_INET, src, srclen, dst, delim, end);
}

static inline
int in6_pton(const char *src, int srclen, u8 *dst, int delim, const char **end)
{
	return in_pton(AF_INET6, src, srclen, dst, delim, end);
}

static inline bool ipv6_addr_any(const struct in6_addr *a)
{
#if BITS_PER_LONG == 64
	const unsigned long *ul = (const unsigned long *)a;

	return (ul[0] | ul[1]) == 0UL;
#else
	return (a->s6_addr32[0] | a->s6_addr32[1] |
		a->s6_addr32[2] | a->s6_addr32[3]) == 0;
#endif
}

struct possible_net {};
typedef struct possible_net possible_net_t;

struct net {};

static inline void write_pnet(possible_net_t *pnet, struct net *net)
{
}

static inline struct net *read_pnet(const possible_net_t *pnet)
{
	return NULL;
}

#define get_net(x) NULL
#define put_net(x)
#define net_eq(...) 1

#endif
