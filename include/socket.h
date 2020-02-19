/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCKET_H
#define _SOCKET_H

#include "net.h"


/* Historically, SOCKWQ_ASYNC_NOSPACE & SOCKWQ_ASYNC_WAITDATA were located
 * in sock->flags, but moved into sk->sk_wq->flags to be RCU protected.
 * Eventually all flags will be in sk->sk_wq->flags.
 */
#define SOCKWQ_ASYNC_NOSPACE	0
#define SOCKWQ_ASYNC_WAITDATA	1
#define SOCK_NOSPACE		2
#define SOCK_PASSCRED		3
#define SOCK_PASSSEC		4

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

struct sock {
	void *sk_user_data;
	unsigned char sk_state;
	struct socket *sk_socket;
	gfp_t sk_allocation;

	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk);
	void			(*sk_write_space)(struct sock *sk);
};

struct socket {
	struct sock *sk;
	unsigned long flags;
	const struct proto_ops *ops;
};

static inline bool sk_stream_is_writeable(const struct sock *sk)
{
	//XXX
	return false;
}

extern ssize_t sock_no_sendpage(struct socket *sock, struct page *page,
				int offset, size_t size, int flags);
extern int sock_create_kern(struct net *net, int family, int type,
			    int protocol, struct socket **res);

extern void sock_release(struct socket *sock);
extern int kernel_setsockopt(struct socket *sock, int level, int optname,
			     char *optval, unsigned int optlen);
extern int sock_recvmsg(struct socket *sock, struct kmsghdr *msg, int flags);
extern int sock_sendmsg(struct socket *sock, struct kmsghdr *msg);
extern int kernel_sendmsg(struct socket *sock, struct kmsghdr *msg,
			  struct kvec *vec, size_t num, size_t size);

#endif
