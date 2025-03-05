/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "macros.h"
#include "logging.h"
#include "net.h"

/**
 * Maximum number of file descriptors (per rlimit)
 */
unsigned max_conn;

/**
 * Absolute max number of connections
 */
#define MAX_CONN 8192

/**
 * Connections and associated pollfds
 */
static struct netconn {
	void *ctx;                     /**< User-supplied context data */
	const struct netconn_ops *ops; /**< User-supplied callbacks */
	struct timespec last_activity;
	unsigned flags;
	unsigned timeout;
	struct sockaddr conn_addr;
	socklen_t conn_addrlen;
} conns[MAX_CONN];

static struct pollfd fds[MAX_CONN];

/**
 * Bitmap of free connection slots
 */
static unsigned long free_conn[MAX_CONN / (sizeof(long) << 3)];

/**
 * DeBruijn constants for computing log2 of 32 and 64-bit integers
 */
#if !(defined(__GNUC__) || !defined(__clang__)) || !__has_builtin(__builtin_clzl)
#if ULONG_MAX == 0xfffffffffffffffful
static unsigned char debruijn[64] = {
	0,   1,  2, 53,  3,  7, 54, 27,  4, 38, 41,  8, 34, 55, 48, 28,
	62,  5, 39, 46, 44, 42, 22,  9, 24, 35, 59, 56, 49, 18, 29, 11,
	63, 52,  6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
	51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
};

static const unsigned long debmul    = 0x022fdd63cc95386dul;
static const unsigned      debshift  = 58;
#else /* assume 32 bits */
static unsigned char debruijn[32] = {
	0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
	8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
};

static const unsigned long debmul = 0x07c4acddul;
static const unsigned debshift    = 27;
#endif
#endif /* !__has_builtin(__builtin_clzl) */

static unsigned long next_free_connection(void)
{
	unsigned long i,j,x;

	for (i = 0; i < sizeof free_conn / sizeof *free_conn; i++) {
		if ((x = free_conn[i]) == ULONG_MAX)
			continue;

		if (!x) {
			++x;
			j = 0;
		} else {
#if (defined(__GNUC__) || defined(__clang__)) && __has_builtin(__builtin_clzl)
			x = (ULONG_MAX >> __builtin_clzl(x)) + 1;
			j = __builtin_ctzl(x);
#else
			/* Plain 'ol C... should use bsr where available */
			x |= x >> 1;
			x |= x >> 2;
			x |= x >> 4;
			x |= x >> 8;
			x |= x >> 16;
			x = sizeof(long) > 4 ? x | (x >> 32) : x;
			j = debruijn[(++x * debmul) >> debshift];
#endif
		}

		if ((i * (sizeof(long) << 3) + j) >= max_conn)
			goto full;
		free_conn[i] |= x;
		return (i * (sizeof(long) << 3)) + j;
	}

full:
	return ULONG_MAX;
}

/**
 * Accept a connection on a listening fd
 */
static unsigned long net_accept(unsigned long parent, int fd,
                                struct sockaddr *addr, socklen_t *addrlen)
{
	int newfd = -1;
	unsigned long id;
	struct linger l;

	assert(conns[parent].ops);
	if ((newfd = accept(fd, addr, addrlen)) < 0)
		goto err;

	if (addr->sa_family == AF_INET) {
		l.l_onoff  = 1;
		l.l_linger = 1;
		if (setsockopt(newfd, SOL_SOCKET, SO_LINGER, &l, sizeof l))
			goto err;
	}

	if ((id = next_free_connection()) == ULONG_MAX)
		goto err;
	memset(conns + id, 0, sizeof *conns);
	memset(fds + id, 0, sizeof *fds);
	conns[id].flags |= conns[parent].flags & CONN_STREAM;
	conns[id].ops    = conns[parent].ops;
	conns[id].ctx    = conns[parent].ctx;
	fds[id].fd       = newfd;
	fds[id].events   = POLLIN;
	return id;

err:
	ERROR(("net_accept failed: errno=%d", errno));
	if (newfd >= 0) close(newfd);
	return ULONG_MAX;
}

/**
 * Setup a new socket
 */
unsigned long net_conn(void *ctx, const struct netconn_ops *ops,
                       struct sockaddr *addr, socklen_t addrlen,
                       unsigned flags)
{
	int fd = -1, one = 1;
	unsigned long id = ULONG_MAX;
	struct linger l;
	struct rlimit rl;

	if (!max_conn) {
		max_conn = 1024; /* Typical soft-limit */
		if (!getrlimit(RLIMIT_NOFILE, &rl))
			max_conn = (rl.rlim_cur == RLIM_INFINITY) ? MAX_CONN : rl.rlim_cur;
		max_conn = min(max_conn, MAX_CONN);
	}

	if (!ops) {
		ERROR(("No netconn ops specified"));
		goto err;
	}

	if (!addr) {
		ERROR(("No address specified"));
		goto err;
	}

	fd = socket(addr->sa_family, (flags & CONN_STREAM) ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (fd < 0) {
		ERROR(("failed to create socket"));
		goto err;
	}

	if (addr->sa_family == AF_INET) {
		l.l_onoff  = 1;
		l.l_linger = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l))
			goto err;

		if (flags & CONN_LISTEN) {
			if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,  &one, sizeof one) ||
			    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)) {
				ERROR(("failed to set socket options"));
				goto err;
			}
		}
	}

	if (flags & CONN_LISTEN) {
		if (bind(fd, addr, addrlen))
			goto err;

		if ((flags & CONN_STREAM) && listen(fd, SOMAXCONN))
			goto err;
	} else if (!(flags & CONN_DEFER_CONNECT) && connect(fd, addr, addrlen))
		goto err;

	if ((id = next_free_connection()) == ULONG_MAX)
		goto err;

	memset(conns + id, 0, sizeof *conns);
	memset(fds + id, 0, sizeof *fds);
	conns[id].flags  = flags;
	conns[id].ops    = ops;
	conns[id].ctx    = ctx;
	fds[id].fd       = fd;
	fds[id].events   = (flags & CONN_DEFER_CONNECT) ? 0 : POLLIN | POLLOUT;

	if (flags & CONN_DEFER_CONNECT) {
		conns[id].conn_addrlen = addrlen;
		memcpy(&conns[id].conn_addr, addr, addrlen);
	}

	if (ops->init) ops->init(ctx, id, fd);
	return id;

err:
	if (fd >= 0) close(fd);
	return ULONG_MAX;
}

/**
 * Set the context data for a connection
 */
void net_set_ctx(unsigned long conn, void *ctx)
{
	assert(conn < max_conn);
	assert(conns[conn].ops);
	conns[conn].ctx = ctx;
}

/**
 * Set the timeout for a connection (0 = no timeout)
 */
void net_set_timeout(unsigned long conn, unsigned secs)
{
	assert(conn < max_conn);
	assert(conns[conn].ops);
	clock_gettime(CLOCK_MONOTONIC, &conns[conn].last_activity);
	conns[conn].timeout = secs;
}

/**
 * Get the context data for a connection
 */
void *net_get_ctx(unsigned long conn)
{
	assert(conn < max_conn);
	assert(conns[conn].ops);
	return conns[conn].ctx;
}

/**
 * Get the ops for a connection
 */
const struct netconn_ops *net_get_ops(unsigned long conn)
{
	assert(conn < max_conn);
	assert(conns[conn].ops);
	return conns[conn].ops;
}

/**
 * Connect to the address originally given to net_conn()
 */
int net_connect(unsigned long conn)
{
	int ret = -1;

	assert(conn < max_conn);
	assert(conns[conn].ops);

	if (!(conns[conn].flags & CONN_DEFER_CONNECT)) {
		errno = ENOTSUP;
		return ret;
	}

	ret = connect(fds[conn].fd, &conns[conn].conn_addr, conns[conn].conn_addrlen);
	if (ret < 0 && errno == EINPROGRESS) {
		fds[conn].events = POLLOUT;
		return 0;
	} else if (ret) goto err;

	conns[conn].flags &= ~CONN_DEFER_CONNECT;
	fds[conn].events = POLLIN | POLLOUT;
	if (conns[conn].ops->connect)
		conns[conn].ops->connect(conns[conn].ctx, conn, fds[conn].fd);

err:
	ERROR(("net_connect failed: errno=%d", errno));
	if (ret && conns[conn].ops->err)
		conns[conn].ops->err(conns[conn].ctx, conn, fds[conn].fd);
	return ret;
}

int net_poll(void)
{
	int active;
	unsigned i, closeit = 0;
	unsigned long newid;
	struct netconn *c;
	struct timespec now;
	struct sockaddr_in addr;
	socklen_t addrlen;

	active = poll(fds, max_conn, 2000);
	if (active < 0 && (errno == EINTR || errno == EAGAIN))
		goto ret;

	if (active < 0 || clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		goto err;

	for (i = 0; i < max_conn; i++) {
		c       = conns + i;
		closeit = 0;
		addrlen = sizeof addr;
		if (!c->ops) continue;

		if (c->flags & CONN_DEFER_CONNECT) {
			if (fds[i].events & fds[i].revents & POLLOUT) {
				c->flags &= ~CONN_DEFER_CONNECT;
				memcpy(&c->last_activity, &now, sizeof now);
				fds[i].events = POLLIN | POLLOUT;
				if (c->ops->connect)
					c->ops->connect(c->ctx, i, fds[i].fd);
			}
			continue;
		}

		fds[i].events = POLLIN | POLLOUT;
		if (c->timeout && c->last_activity.tv_sec + c->timeout < now.tv_sec) {
			errno = ETIMEDOUT;
			if (c->ops->err) closeit = c->ops->err(c->ctx, i, fds[i].fd);
			if (closeit) net_close(i);
			continue;
		}

		if (fds[i].revents & (POLLERR | POLLNVAL | POLLHUP)) {
			errno = EINVAL;
			if (fds[i].revents == POLLHUP)
				errno = EPIPE;
			if (c->ops->err) closeit = c->ops->err(c->ctx, i, fds[i].fd);
			if (closeit) net_close(i);
			continue;
		}

		if (fds[i].revents & (POLLIN | POLLOUT))
			memcpy(&c->last_activity, &now, sizeof now);

		if (fds[i].revents & POLLIN && c->flags & CONN_LISTEN && c->ops->accept) {
			newid = net_accept(i, fds[i].fd, (struct sockaddr *)&addr, &addrlen);
			if (newid == ULONG_MAX) {
				if (c->ops->err) c->ops->err(c->ctx, i, fds[i].fd);
				continue;
			}

			c->ops->accept(c->ctx, (struct sockaddr *)&addr, addrlen, newid, fds[newid].fd);
			continue;
		}

		if (fds[i].revents & POLLIN && c->ops->read)
			c->ops->read(c->ctx, i, fds[i].fd);

		if (fds[i].revents & POLLOUT && c->ops->write)
			c->ops->write(c->ctx, i, fds[i].fd);
	}

ret:
	return 0;

err:
	ERROR(("net_poll failed: errno=%d", errno));
	return -1;
}

/**
 * Close the given connection
 */
void net_close(unsigned long conn)
{
	assert(conn < max_conn);

	if (!conns[conn].ops)
		return;

	if (conns[conn].ops->close)
		conns[conn].ops->close(conns[conn].ctx, conn, fds[conn].fd);

	if (fds[conn].fd >= 0) {
		if (conns[conn].flags & CONN_STREAM)
			shutdown(fds[conn].fd, SHUT_RDWR);
		close(fds[conn].fd);
	}

	memset(fds + conn, 0, sizeof *fds);
	fds[conn].fd = -1;
	memset(conns + conn, 0, sizeof *conns);
	free_conn[conn / (sizeof(long) << 3)] &= ~(1 << (conn % (sizeof(long) << 3)));
	return;
}

