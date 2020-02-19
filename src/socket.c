#include "socket.h"

ssize_t sock_no_sendpage(struct socket *sock, struct page *page,
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
int sock_create_kern(struct net *net, int family, int type, int protocol,
		     struct socket **res)
{
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
void sock_release(struct socket *sock)
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
int kernel_setsockopt(struct socket *sock, int level, int optname,
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
int sock_recvmsg(struct socket *sock, struct kmsghdr *msg, int flags)
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
int sock_sendmsg(struct socket *sock, struct kmsghdr *msg)
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
int kernel_sendmsg(struct socket *sock, struct kmsghdr *msg,
	       struct kvec *vec, size_t num, size_t size)
{
	iov_iter_kvec(&msg->msg_iter, WRITE, vec, num, size);
	return sock_sendmsg(sock, msg);
}
