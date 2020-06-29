#include <unistd.h>

#include "socket.h"
#include "bitops.h"
#include "page.h"
#include "bvec.h"

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
		WARN_ON(!(flags& O_NONBLOCK));
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

static int socket_bind(struct socket *sock, struct sockaddr *myaddr,
		       int sockaddr_len)
{
	int ret;

	ret = bind(sock->fd, myaddr, sockaddr_len);
	if (ret < 0)
		ret = -errno;

	return ret;
}

static int socket_accept(struct socket *sock, struct socket *newsock,
			 int flags, bool kern)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	int fd, ret;

	(void)kern;

	WARN_ON(!(flags& O_NONBLOCK));

	fd = accept4(sock->fd, (struct sockaddr *)&addr, &len, flags);
	if (unlikely(fd < 0))
		return -errno;

	/* Add socketfd to the event loop in edge trigger mode */
	newsock->ev.events = EPOLLET | EPOLLIN | EPOLLOUT;
	ret = event_item_add(&newsock->ev, fd);
	if (WARN(ret, "event_item_add: failed %d\n", ret)) {
		close(fd);
		return ret;
	}

	/* Switch to CONNECTED here and avoid ->sk_change_state() call */
	newsock->fd = fd;
	newsock->state = SS_CONNECTED;
	newsock->sk->sk_state = TCP_ESTABLISHED;

	return 0;
}

static int socket_listen(struct socket *sock, int len)
{
	int ret;

	ret = listen(sock->fd, len);
	if (unlikely(ret < 0))
		return -errno;

	sock->state = SS_CONNECTED;
	sock->sk->sk_state = TCP_LISTEN;

	/* Add socketfd to the event loop in edge trigger mode */
	sock->ev.events = EPOLLET | EPOLLIN;
	ret = event_item_add(&sock->ev, sock->fd);
	if (WARN(ret, "event_item_add: failed %d\n", ret)) {
		/* Can't revert listen() call, so expect this won't happen */
		return ret;
	}

	return 0;
}

static int socket_getname(struct socket *sock, struct sockaddr *uaddr,
			  int peer)
{
	socklen_t len = sizeof(struct sockaddr_storage);
	int ret;

	switch(peer) {
	case 0:
		ret = getsockname(sock->fd, uaddr, &len);
		break;
	case 1:
		ret = getpeername(sock->fd, uaddr, &len);
		break;
	case 2:
		ret = getsockopt(sock->fd, SOL_SOCKET,
				 SO_PEERNAME, uaddr, &len);
		break;
	default:
		return -EINVAL;
	}

	if (ret)
		return -errno;

	return len;
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
	.bind     = socket_bind,
	.accept   = socket_accept,
	.listen   = socket_listen,
	.getname  = socket_getname,
	.shutdown = socket_shutdown,
	.sendpage = sock_no_sendpage
};

static int sock_create_lite(int family, int type, int protocol,
			    struct socket **res)
{
	struct socket *sock;

	sock = calloc(1, sizeof(*sock));
	if (unlikely(!sock))
		return -ENOMEM;

	sock->fd = -1;
	INIT_EVENT(&sock->ev, socket_event);
	sock->state = SS_UNCONNECTED;
	sock->ops = &sock_ops;

	sock->__sk.sk_socket = sock;
	sock->sk = &sock->__sk;
	sock->sk->sk_family   = family;
	sock->sk->sk_type     = type;
	sock->sk->sk_protocol = protocol;

	*res = sock;

	return 0;
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
int sock_create_kern(struct net *net, int family, int type, int protocol,
		     struct socket **res)
{
	int ret, fd;

	fd = socket(family, type, protocol);
	if (unlikely(fd < 0))
		return -errno;

	/* Yes, we never block */
	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (unlikely(ret)) {
		close(fd);
		return ret;
	}

	ret = sock_create_lite(family, type, protocol, res);
	if (unlikely(ret)) {
		close(fd);
		return ret;
	}
	(*res)->fd = fd;

	return 0;
}

/**
 *	kernel_bind - bind an address to a socket (kernel space)
 *	@sock: socket
 *	@addr: address
 *	@addrlen: length of address
 *
 *	Returns 0 or an error.
 */

int kernel_bind(struct socket *sock, struct sockaddr *addr, int addrlen)
{
	return sock->ops->bind(sock, addr, addrlen);
}

/**
 *	kernel_listen - move socket to listening state (kernel space)
 *	@sock: socket
 *	@backlog: pending connections queue size
 *
 *	Returns 0 or an error.
 */

int kernel_listen(struct socket *sock, int backlog)
{
	return sock->ops->listen(sock, backlog);
}

/**
 *	kernel_accept - accept a connection (kernel space)
 *	@sock: listening socket
 *	@newsock: new connected socket
 *	@flags: flags
 *
 *	@flags must be SOCK_CLOEXEC, SOCK_NONBLOCK or 0.
 *	If it fails, @newsock is guaranteed to be %NULL.
 *	Returns 0 or an error.
 */

int kernel_accept(struct socket *sock, struct socket **newsock, int flags)
{
	struct sock *sk = sock->sk;
	int err;

	err = sock_create_lite(sk->sk_family, sk->sk_type,
			       sk->sk_protocol, newsock);
	if (err < 0)
		goto done;

	err = sock->ops->accept(sock, *newsock, flags, true);
	if (err < 0) {
		sock_release(*newsock);
		*newsock = NULL;
		goto done;
	}
	(*newsock)->ops = sock->ops;

done:
	return err;
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
	if (sock->fd >= 0)
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
 *	kernel_getsockname - get the address which the socket is bound (kernel space)
 *	@sock: socket
 *	@addr: address holder
 *
 * 	Fills the @addr pointer with the address which the socket is bound.
 *	Returns 0 or an error code.
 */

int kernel_getsockname(struct socket *sock, struct sockaddr *addr)
{
	return sock->ops->getname(sock, addr, 0);
}

/**
 *	kernel_peername - get the address which the socket is connected (kernel space)
 *	@sock: socket
 *	@addr: address holder
 *
 *	Fills the @addr pointer with the address which the socket is connected.
 *	Returns 0 or an error code.
 */

int kernel_getpeername(struct socket *sock, struct sockaddr *addr)
{
	return sock->ops->getname(sock, addr, 1);
}

static unsigned int iov_iter_to_iovec(struct iov_iter *iter,
				      struct iovec *iovs)
{
	size_t skip = iter->iov_offset;
	size_t len, count = iter->count;
	unsigned i = 0;

	/*
	 * Unfortunately can't use iov_iter_for_each_range() for
	 * bvec, because it iterates over pages, but for the sake
	 * of the performance in case of multi-pages bvec we want
	 * to grab the whole contiguous bvec, not only 1 page.
	 * Not a big deal, just do the whole conversion ourselves.
	 */

	if (iter_is_iovec(iter)) {
		for (i = 0; count && i < iter->nr_segs; i++) {
			const struct iovec *src = &iter->iov[i];
			struct iovec *dst = &iovs[i];

			len = min(src->iov_len - skip, count);
			dst->iov_base = src->iov_base + skip;
			dst->iov_len = len;
			count -= len;
			skip = 0;
		}
	} else if (iov_iter_is_kvec(iter)) {
		for (i = 0; count && i < iter->nr_segs; i++) {
			const struct kvec *src = &iter->kvec[i];
			struct iovec *dst = &iovs[i];

			len = min(src->iov_len - skip, count);
			dst->iov_base = src->iov_base + skip;
			dst->iov_len = len;
			count -= len;
			skip = 0;
		}
	} else if (iov_iter_is_bvec(iter)) {
		for (i = 0; i < count && iter->nr_segs; i++) {
			const struct bio_vec *src = &iter->bvec[i];
			struct iovec *dst = &iovs[i];

			BUG_ON(skip >= src->bv_len);

			len = min(src->bv_len - skip, count);
			dst->iov_base = page_address(src->bv_page) +
				src->bv_offset + skip;
			dst->iov_len = len;
			count -= len;
			skip = 0;
		}
	} else {
		BUG();
	}

	return i;

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
	struct iov_iter *iter = &kmsg->msg_iter;
	struct iovec iovec[iter->nr_segs + 2];
	struct msghdr msg = {
		.msg_name    = kmsg->msg_name,
		.msg_namelen = kmsg->msg_namelen,
		.msg_iov     = iovec,
		.msg_control = kmsg->msg_control,
		.msg_controllen = kmsg->msg_controllen,
		.msg_flags    = kmsg->msg_flags
	};
	struct iovec *iov = iovec;
	int ret;

	off_t cache_pos;
	int read = 0;

	/* First consume from the cache if there is something */
	if (sock->cache_len) {
		size_t len_to_end = sizeof(sock->cache) - sock->cache_pos;
		size_t len = min_t(size_t, iter->count, sock->cache_len);

		if (!(flags & MSG_TRUNC)) {
			/* First half */
			read += _copy_to_iter(sock->cache + sock->cache_pos,
					      min(len_to_end, len), iter);
			if (len_to_end < len)
				/* Second half */
				read += _copy_to_iter(sock->cache,
						len - len_to_end, iter);
		} else {
			read += len;
			iov_iter_advance(iter, len);
		}

		sock->cache_len -= len;
		sock->cache_pos += len;
		sock->cache_pos &= (sizeof(sock->cache)-1);

		BUG_ON(sock->cache_len && iter->count);

		/* Leave earlier if we are done */
		if (!iter->count)
			return read;
	}

	/* Setup iovec from iter if there is still something left to read */
	if (iter->count) {
		msg.msg_iovlen = iov_iter_to_iovec(iter, iovec);
		iov = &iovec[msg.msg_iovlen];
	}

	/* Cache can't be full, there should be some space left */
	BUG_ON(sock->cache_len == sizeof(sock->cache));

	/* Read more into cache, thus take position of free space */
	cache_pos = (sock->cache_pos + sock->cache_len) &
		(sizeof(sock->cache)-1);

	/* First half */
	iov[0].iov_base = sock->cache + cache_pos;
	iov[0].iov_len = min(sizeof(sock->cache) - sock->cache_len,
			     sizeof(sock->cache) - cache_pos);
	msg.msg_iovlen += 1;
	if (iov[0].iov_len < sizeof(sock->cache) - sock->cache_len) {
		/* Second half */
		iov[1].iov_base = sock->cache;
		iov[1].iov_len = (sizeof(sock->cache) - sock->cache_len) -
			iov[0].iov_len;
		msg.msg_iovlen += 1;
	}

	ret = recvmsg(sock->fd, &msg, flags);
	if (read) {
		/* Ignore errors from sock if we've read something from cache */
		ret = ret < 0 ? 0 : ret;
		goto advance_cache;
	}
	else if (unlikely(ret < 0)) {
		ret = -errno;
	} else if (unlikely(!ret)) {
		/*
		 * Catch EOF, see socket_event() for details
		 * which will be called again on next event loop
		 * iteration
		 */
		sock->state = SS_DISCONNECTING;
		sock->ev.revents |= EPOLLIN;
		event_item_set(&sock->ev);
	} else {
		size_t rest_to_read;
advance_cache:
		rest_to_read = min_t(size_t, ret, iter->count);
		read += rest_to_read;
		/* Advance cache length */
		sock->cache_len += ret - rest_to_read;
		ret = read;
	}

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
	struct iov_iter *iter = &kmsg->msg_iter;
	struct iovec iov[iter->nr_segs];
	struct msghdr msg = {
		.msg_name    = kmsg->msg_name,
		.msg_namelen = kmsg->msg_namelen,
		.msg_iov     = iov,
		.msg_control = kmsg->msg_control,
		.msg_controllen = kmsg->msg_controllen,
		.msg_flags    = kmsg->msg_flags
	};
	int ret;

	msg.msg_iovlen = iov_iter_to_iovec(iter, iov);

	ret = sendmsg(sock->fd, &msg, 0);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EAGAIN) {
			int err;

			/* Enable further out events */
			set_bit(SOCK_NOSPACE, &sock->flags);
			sock->ev.events |= EPOLLOUT;
			err = event_item_mod(&sock->ev);
			WARN(err, "event_item_mod(): err=%d\n", err);
		}
	}

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
