/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_H
#define _NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "uio.h"

/* Historically, SOCKWQ_ASYNC_NOSPACE & SOCKWQ_ASYNC_WAITDATA were located
 * in sock->flags, but moved into sk->sk_wq->flags to be RCU protected.
 * Eventually all flags will be in sk->sk_wq->flags.
 */
#define SOCKWQ_ASYNC_NOSPACE	0
#define SOCKWQ_ASYNC_WAITDATA	1
#define SOCK_NOSPACE		2
#define SOCK_PASSCRED		3
#define SOCK_PASSSEC		4

#define MSG_SENDPAGE_NOPOLICY 0x10000 /* sendpage() internal : do no apply policy */
#define MSG_SENDPAGE_NOTLAST 0x20000 /* sendpage() internal : not the last page */

struct sock;
struct socket;

struct proto_ops {
	int		(*connect)   (struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags);
	int		(*shutdown)  (struct socket *sock, int flags);
	ssize_t		(*sendpage)  (struct socket *sock, struct page *page,
				      int offset, size_t size, int flags);
};

struct socket {
	struct sock *sk;
	unsigned long flags;
	const struct proto_ops *ops;
};

struct sock {
	void *sk_user_data;
	unsigned char sk_state;
	struct socket *sk_socket;
	gfp_t sk_allocation;

	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk);
	void			(*sk_write_space)(struct sock *sk);
};

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

static inline bool sk_stream_is_writeable(const struct sock *sk)
{
	//XXX
	return false;
}


static inline
int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end)
{
	//XXX
	return inet_pton(AF_INET, src, dst);
}

static inline
int in6_pton(const char *src, int srclen, u8 *dst, int delim, const char **end)
{
	//XXX
	return inet_pton(AF_INET6, src, dst);
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

static inline ssize_t
sock_no_sendpage(struct socket *sock, struct page *page,
		 int offset, size_t size, int flags)
{
	//XXX
	return -EINVAL;
}


/**
 *	sock_create_kern - creates a socket (kernel space)
 *	@net: net namespace
 *	@family: protocol family (AF_INET, ...)
 *	@type: communication type (SOCK_STREAM, ...)
 *	@protocol: protocol (0, ...)
 *	@res: new socket
 *
 *	A wrapper around __sock_create().
 *	Returns 0 or an error. This function internally uses GFP_KERNEL.
 */

static inline int
sock_create_kern(struct net *net, int family, int type, int protocol,
		 struct socket **res)
{
	(void)net;

	//XXX
	return -EINVAL;
}

/**
 *	sock_release - close a socket
 *	@sock: socket to close
 *
 *	The socket is released from the protocol stack if it has a release
 *	callback, and the inode is then released if the socket is bound to
 *	an inode not a file.
 */

static inline void
sock_release(struct socket *sock)
{
	//XXX
}

/**
 *	kernel_setsockopt - set a socket option (kernel space)
 *	@sock: socket
 *	@level: API level (SOL_SOCKET, ...)
 *	@optname: option tag
 *	@optval: option value
 *	@optlen: option length
 *
 *	Returns 0 or an error.
 */

static inline int
kernel_setsockopt(struct socket *sock, int level, int optname,
		  char *optval, unsigned int optlen)
{
	//XXX
	return -EINVAL;
}

/**
 *	sock_recvmsg - receive a message from @sock
 *	@sock: socket
 *	@msg: message to receive
 *	@flags: message flags
 *
 *	Receives @msg from @sock, passing through LSM. Returns the total number
 *	of bytes received, or an error.
 */

static inline int
sock_recvmsg(struct socket *sock, struct kmsghdr *msg, int flags)
{
	//XXX
	return -EINVAL;
}

/**
 *	sock_sendmsg - send a message through @sock
 *	@sock: socket
 *	@msg: message to send
 *
 *	Sends @msg through @sock, passing through LSM.
 *	Returns the number of bytes sent, or an error code.
 */

static inline int
sock_sendmsg(struct socket *sock, struct kmsghdr *msg)
{
	//XXX
	return -EINVAL;
}


/**
 *	kernel_sendmsg - send a message through @sock (kernel-space)
 *	@sock: socket
 *	@msg: message header
 *	@vec: kernel vec
 *	@num: vec array length
 *	@size: total message data size
 *
 *	Builds the message data with @vec and sends it through @sock.
 *	Returns the number of bytes sent, or an error code.
 */

static inline int
kernel_sendmsg(struct socket *sock, struct kmsghdr *msg,
	       struct kvec *vec, size_t num, size_t size)
{
	iov_iter_kvec(&msg->msg_iter, WRITE, vec, num, size);
	return sock_sendmsg(sock, msg);
}

#endif
