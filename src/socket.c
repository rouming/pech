#include <unistd.h>

#include "socket.h"
#include "bitops.h"
#include "page.h"

static void socket_event(struct event_item *ev)
{
	struct socket *sock;
	struct sock* sk;
	int ret;

	sock = container_of(ev, typeof(*sock), ev);
	sk = sock->sk;

	if (ev->revents & EPOLLERR) {
		if (sock->state != SS_UNCONNECTED) {
			/*
			 * If we were ever connecting or connected pretend socket
			 * was closed in case of any socket error.
			 */
			sock->state = SS_UNCONNECTED;
			sk->sk_state = TCP_CLOSE;
			sk->sk_state_change(sock->sk);
		}
		/* Stop receiving further events in case of a socket error */
		ret = event_item_del(&sock->ev);
		WARN(ret, "event_item_del(): err=%d\n", ret);
		return;
	}

	switch (sock->state) {
	case SS_CONNECTING:
		WARN_ON(!(ev->revents & EPOLLOUT));
		sock->state = SS_CONNECTED;
		sk->sk_state = TCP_ESTABLISHED;
		sk->sk_state_change(sk);

		/* Want to read */
		sock->ev.events |= EPOLLIN;
		ret = event_item_mod(&sock->ev);
		WARN(ret, "event_item_mod(): err=%d\n", ret);
		break;

	case SS_CONNECTED:
		if (ev->revents & EPOLLOUT) {
			sk->sk_write_space(sk);
			if (!test_bit(SOCK_NOSPACE, &sock->flags)) {
				/* Disable further out events */
				sock->ev.events &= ~EPOLLOUT;
				ret = event_item_mod(&sock->ev);
				WARN(ret, "event_item_mod(): err=%d\n", ret);
			}
		}
		if (ev->revents & EPOLLIN) {
			sk->sk_data_ready(sk);
		}
		break;

	case SS_DISCONNECTING:
		sk->sk_state = TCP_CLOSE;
		sk->sk_state_change(sk);
		sock->state = SS_UNCONNECTED;

		/* Stop receiving further events */
		ret = event_item_del(&sock->ev);
		WARN(ret, "event_item_del(): err=%d\n", ret);

		break;

	default:
		pr_err("Unknown socket state: %d\n", sock->state);
		return;
	}
}

static int socket_connect(struct socket *sock,
			  struct sockaddr *vaddr,
			  int sockaddr_len, int flags)
{
	int ret;

	switch (sock->state) {
	default:
		return -EINVAL;

	case SS_CONNECTED:
	case SS_CONNECTING:
	case SS_UNCONNECTED:
		if (flags & O_NONBLOCK) {
			ret = fcntl(sock->fd, F_SETFL, O_NONBLOCK);
			if (unlikely(ret)) {
				ret = -errno;
				pr_err("fcntl(): failed %d\n", ret);
				return ret;
			}
		}
		ret = connect(sock->fd, vaddr, sockaddr_len);
		if (ret)
			ret = -errno;

		if (likely(!ret || ret == -EINPROGRESS)) {
			/* Add socketfd to the event loop in edge trigger mode */
			sock->ev.events = EPOLLET | EPOLLOUT;
			ret = event_item_add(&sock->ev, sock->fd);
			if (unlikely(ret)) {
				pr_err("event_item_add: failed %d\n", ret);
				return ret;
			}

			/* Ok, wait for connection */
			sock->state = SS_CONNECTING;
		}
	}

	return ret;
}

static int socket_shutdown(struct socket *sock, int flags)
{
	int ret;

	ret = shutdown(sock->fd, flags);
	if (unlikely(ret))
		ret = -errno;

	return ret;
}

ssize_t sock_no_sendpage(struct socket *sock, struct page *page,
			 int offset, size_t size, int flags)
{
	ssize_t res;
	struct kmsghdr msg = {.msg_flags = flags};
	struct kvec iov;

	iov.iov_base = page_address(page) + offset;
	iov.iov_len = size;
	res = kernel_sendmsg(sock, &msg, &iov, 1, size);

	return res;
}

bool sk_stream_is_writeable(const struct sock *sk)
{
	/*
	 * Here we assume we are always writable without asking a socket.
	 * For current users of this function seems this is fine.
	 */
	return true;
}

static struct proto_ops sock_ops = {
	.connect  = socket_connect,
	.shutdown = socket_shutdown,
	.sendpage = sock_no_sendpage
};

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
int sock_create_kern(struct net *net, int family, int type, int protocol,
		     struct socket **res)
{
	struct socket *sock;
	int ret;

	(void)net;

	sock = calloc(1, sizeof(*sock));
	if (unlikely(!sock))
		return -ENOMEM;

	sock->fd = socket(family, type, protocol);
	if (unlikely(sock->fd < 0)) {
		ret = -errno;
		free(sock);
		return ret;
	}

	INIT_EVENT(&sock->ev, socket_event);
	sock->state = SS_UNCONNECTED;
	sock->ops = &sock_ops;

	sock->__sk.sk_socket = sock;
	sock->sk = &sock->__sk;

	*res = sock;

	return 0;
}

/**
 *	sock_release - close a socket
 *	@sock: socket to close
 *
 *	The socket is released from the protocol stack if it has a release
 *	callback, and the inode is then released if the socket is bound to
 *	an inode not a file.
 */
void sock_release(struct socket *sock)
{
	event_item_del(&sock->ev);
	close(sock->fd);
	free(sock);
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
int kernel_setsockopt(struct socket *sock, int level, int optname,
		      char *optval, unsigned int optlen)
{
	int ret;

	ret = setsockopt(sock->fd, level, optname, optval, optlen);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

/**
 *	sock_recvmsg - receive a message from @sock
 *	@sock: socket
 *	@kmsg: message to receive
 *	@flags: message flags
 *
 *	Receives @msg from @sock, passing through LSM. Returns the total number
 *	of bytes received, or an error.
 */
int sock_recvmsg(struct socket *sock, struct kmsghdr *kmsg, int flags)
{
	struct msghdr msg = {
		.msg_name    = kmsg->msg_name,
		.msg_namelen = kmsg->msg_namelen,
		.msg_iov     = (struct iovec *)kmsg->msg_iter.iov,
		.msg_iovlen  = kmsg->msg_iter.nr_segs,
		.msg_control = kmsg->msg_control,
		.msg_controllen = kmsg->msg_controllen,
		.msg_flags    = kmsg->msg_flags
	};
	int ret;

	ret = recvmsg(sock->fd, &msg, flags);
	if (unlikely(ret < 0))
		ret = -errno;
	else if (unlikely(!ret))
		/* Catch EOF, see socket_event() for details */
		sock->state = SS_DISCONNECTING;

	return ret;
}

/**
 *	sock_sendmsg - send a message through @sock
 *	@sock: socket
 *	@kmsg: message to send
 *
 *	Sends @msg through @sock, passing through LSM.
 *	Returns the number of bytes sent, or an error code.
 */
int sock_sendmsg(struct socket *sock, struct kmsghdr *kmsg)
{
	struct msghdr msg = {
		.msg_name    = kmsg->msg_name,
		.msg_namelen = kmsg->msg_namelen,
		.msg_iov     = (struct iovec *)kmsg->msg_iter.iov,
		.msg_iovlen  = kmsg->msg_iter.nr_segs,
		.msg_control = kmsg->msg_control,
		.msg_controllen = kmsg->msg_controllen,
		.msg_flags    = kmsg->msg_flags
	};
	int ret;

	ret = sendmsg(sock->fd, &msg, 0);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
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
int kernel_sendmsg(struct socket *sock, struct kmsghdr *msg,
	       struct kvec *vec, size_t num, size_t size)
{
	iov_iter_kvec(&msg->msg_iter, WRITE, vec, num, size);
	return sock_sendmsg(sock, msg);
}
