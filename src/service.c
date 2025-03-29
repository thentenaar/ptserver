/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "net.h"
#include "service.h"
#include "logging.h"

struct service_ctx {
	struct service_ops *ops;
	pid_t pid;
	int fd;
};

static void service_init(void *ctx, unsigned long conn, int fd, int fd2)
{
	unsigned i;
	struct service_ctx *c;

	(void)fd;
	assert(ctx);
	if (!(c = calloc(1, sizeof *c))) {
		close(fd2);
		net_set_ctx(conn, NULL);
		net_close(conn);
		return;
	}

	c->ops = ctx;
	c->fd  = fd;
	net_set_ctx(conn, c);
	if (!(c->pid = fork())) {
		c->fd = fd2;
		net_reset(conn, fd2);
		if (c->ops->start) c->ops->start();
		for (i = 1; i < max_conn; i++)
			net_close(i);
		net_close(0);
		exit(EXIT_SUCCESS);
	}

	if (c->pid < 0)
		ERROR(("fork failed: %d", errno));
	close(fd2);
}

static void service_read(void *ctx, unsigned long conn, int fd)
{
	struct service_ctx *c = ctx;

	(void)conn;
	assert(c);
	if ((c->pid && !c->ops->parent_read) || !c->ops->child_read)
		return;

	(c->pid) ? c->ops->parent_read(fd) : c->ops->child_read(fd);
}

static void service_close(void *ctx, unsigned long conn, int fd)
{
	struct service_ctx *c = ctx;

	(void)fd;
	(void)conn;
	if (!c) return;

	if (c->pid) {
		close(fd);
		waitpid(c->pid, NULL, WNOHANG);
	} else if (c->ops->stop) c->ops->stop();
	free(c);
}

static int service_err(void *ctx, unsigned long conn, int fd)
{
	(void)ctx;
	(void)conn;
	(void)fd;
	return 1;
}

struct netconn_ops service_ops = {
	service_init,
	NULL,
	NULL,
	NULL,
	service_read,
	NULL,
	service_close,
	service_err
};

/**
 * Start a service with a socketpair for IPC
 * \return a service handle, or ULONG_MAX on error
 */
unsigned long service_start(struct service_ops *ops)
{
	return net_conn(ops, &service_ops, NULL, 0, CONN_SOCKETPAIR);
}

/**
 * Check a service for activity, and respond accordingly
 */
void service_recv(unsigned long handle)
{
	net_read(handle);
}

/**
 * Send data to a service
 *
 * From a service, 0 is the socket to/from the host.
 *
 * \return Number of bytes written, or -errno on error
 */
int service_send(unsigned long handle, char *data, unsigned len)
{
	struct service_ctx *c;

	if (!(c = net_get_ctx(handle)))
		return -ENOENT;

	if (len >= INT_MAX)
		return -E2BIG;

	return send(c->fd, data, len, 0);
}

/**
 * Stop a service
 */
void service_stop(unsigned long handle)
{
	if (handle != ULONG_MAX)
		net_close(handle);
}

