/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCKET_H
#define _SOCKET_H

#include "net.h"
#include "event.h"


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
	int		(*bind)	     (struct socket *sock,
				      struct sockaddr *myaddr,
				      int sockaddr_len);
	int		(*accept)    (struct socket *sock,
				      struct socket *newsock, int flags, bool kern);
	int		(*listen)    (struct socket *sock, int len);
	int		(*getname)   (struct socket *sock, struct sockaddr *uaddr,
				      int peer);
	int		(*shutdown)  (struct socket *sock, int flags);
	ssize_t		(*sendpage)  (struct socket *sock, struct page *page,
				      int offset, size_t size, int flags);
};

struct sock {
	void *sk_user_data;
	unsigned char sk_state;
	struct socket *sk_socket;
	gfp_t sk_allocation;
	unsigned short sk_family;
	unsigned short sk_type;
	unsigned short sk_protocol;

	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk);
	void			(*sk_write_space)(struct sock *sk);
};

struct socket {
	struct event_item      ev;
	struct sock            *sk;
	struct sock            __sk;
	unsigned long          flags;
	int                    state;
	const struct proto_ops *ops;
	int                    fd;
	char                   cache[128<<10]; /* must be ^2 */
	unsigned int           cache_pos;
	unsigned int           cache_len;
};

extern bool sk_stream_is_writeable(const struct sock *sk);

extern ssize_t sock_no_sendpage(struct socket *sock, struct page *page,
				int offset, size_t size, int flags);
extern int sock_create_kern(struct net *net, int family, int type,
			    int protocol, struct socket **res);
extern int kernel_bind(struct socket *sock, struct sockaddr *addr, int addrlen);
extern int kernel_listen(struct socket *sock, int backlog);
extern int kernel_accept(struct socket *sock, struct socket **newsock,
			 int flags);

extern void sock_release(struct socket *sock);
extern int kernel_setsockopt(struct socket *sock, int level, int optname,
			     char *optval, unsigned int optlen);
extern int kernel_getsockname(struct socket *sock, struct sockaddr *addr);
extern int kernel_getpeername(struct socket *sock, struct sockaddr *addr);
extern int sock_recvmsg(struct socket *sock, struct kmsghdr *msg, int flags);
extern int sock_sendmsg(struct socket *sock, struct kmsghdr *msg);
extern int kernel_sendmsg(struct socket *sock, struct kmsghdr *msg,
			  struct kvec *vec, size_t num, size_t size);

#endif
