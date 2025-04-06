/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "net.h"
#include "hash.h"
#include "service.h"
#include "logging.h"
#include "parse_http.h"
#include "http_handlers.h"

/* server.c */
extern volatile int got_sig;
extern struct sockaddr_in server_addr;
extern struct ht *uid_to_context;
extern unsigned long http_service;
extern unsigned short http_port;

struct http_ctx {
	unsigned long        conn;
	unsigned char        state;
	struct http_request  req;
	struct http_response resp;
	char                 *buf;
	off_t                 off;
	size_t                cap;
};

static unsigned http_poll_events(void *ctx, unsigned long conn, int fd)
{
	(void)ctx;
	(void)conn;
	(void)fd;
	return NET_POLL_RW;
}

static void http_accept(void *ctx, struct sockaddr *addr, socklen_t addrlen,
                       unsigned long new_conn, int new_fd)
{
	struct http_ctx *c;

	(void)ctx;
	(void)addr;
	(void)addrlen;
	(void)new_fd;

	net_set_ctx(new_conn, NULL);
	if (!(c = calloc(1, sizeof *c))) {
		net_close(new_conn);
		return;
	}

	c->cap = HTTP_BUFSIZ;
	if (!(c->buf = calloc(1, c->cap))) {
		free(c);
		net_close(new_conn);
		return;
	}

	net_set_ctx(new_conn, c);
	net_set_timeout(new_conn, 30);
	c->conn    = new_conn;
	c->resp.fd = -1;
}

/**
 * Read and process one HTTP request
 */
static void http_read(void *ctx, unsigned long conn, int fd)
{
	int br;
	struct ht *params;
	http_handler handler;
	struct http_ctx *c = ctx;

	if (c->resp.status)
		return;

	if ((br = recv(fd, c->buf + c->off, c->cap - c->off, 0)) <= 0) {
		net_close(conn);
		return;
	}

	c->off += br;
	if (http_request(c->buf, &c->req, &c->resp)) {
		/* If we cant fit the request in the buffer, we don't need it */
		if (!c->resp.status && c->cap - c->off <= 2)
			c->resp.status = 431;
	}

	if (c->resp.status) {
		ERROR(("[%u -> %lu] %s %s%s %s", c->resp.status,
		      c->resp.len + c->resp.fd_len,
		      http_method_name[c->req.method],
		      ht_get_str(c->req.headers, "Host"),
		      c->req.target,
		      c->req.query ? c->req.query : ""));
		http_serialize_response(&c->resp);
		shutdown(fd, SHUT_RD);
		return;
	}

	/* Locate the proper handler and dispatch the request */
	handler = http_find_handler(ht_get_str(c->req.headers, "Host"),
	                            c->req.target);

	c->resp.status = 404;
	if (handler) {
		if (!(c->resp.headers = ht_alloc(HT_VALUE_DEFAULT, 0)))
			abort();
		params = http_query_params(c->req.query);
		handler(&c->req, &c->resp, params);
		ht_free(params);
	}

	if (c->req.method == HTTP_HEAD) {
		if (!c->resp.static_body)
			free(c->resp.body);
		c->resp.body   = NULL;
		c->resp.len    = 0;
		c->resp.fd_len = 0;
		if (c->resp.fd >= 0)
			close(c->resp.fd);
		c->resp.fd = -1;
	}

	/* Log the request */
	http_serialize_response(&c->resp);
	INFO(("[%u -> %lu] %s %s%s %s", c->resp.status,
	      c->resp.len + c->resp.fd_len,
	      http_method_name[c->req.method],
	      ht_get_str(c->req.headers, "Host"),
	      c->req.target,
	      c->req.query ? c->req.query : ""));
}

/**
 * Send the HTTP response
 */
static void http_write(void *ctx, unsigned long conn, int fd)
{
	ssize_t bs;
	struct http_ctx *c = ctx;

	if (!c->resp.status)
		return;

	/* We've sent our buffer, see if we have an fd too */
	if (c->resp.len && (size_t)c->resp.off == c->resp.len) {
		if (c->resp.fd_len) {
			c->resp.off = 0;
			c->resp.len = 0;
		} else goto done;
	}

	/* If the kernel moved everything from the fd... */
	if (!c->resp.len && (size_t)c->resp.off == c->resp.fd_len)
		goto done;

	if (c->resp.fd_len && !c->resp.len) {
		if ((bs = sendfile(fd, c->resp.fd, &c->resp.off, c->resp.fd_len)) <= 0)
			goto done;
	} else if ((bs = send(fd, c->resp.body + c->resp.off, c->resp.len - c->resp.off, 0)) <= 0)
		goto done;

	c->resp.off += bs;
	if ((size_t)c->resp.off < c->resp.len + c->resp.fd_len)
		return;

done:
	c->resp.status = 0;
	net_close(conn);
}

static void http_close(void *ctx, unsigned long conn, int fd)
{
	struct http_ctx *c = ctx;

	(void)conn;
	(void)fd;
	if (!c) return;
	http_request_reset(&c->req);
	http_response_reset(&c->resp);
	free(c->buf);
	free(c);
}

static int http_err(void *ctx, unsigned long conn, int fd)
{
	(void)ctx;
	(void)conn;
	(void)fd;
	return 1;
}

static struct netconn_ops http_ops = {
	NULL,
	http_poll_events,
	NULL,
	http_accept,
	http_read,
	http_write,
	http_close,
	http_err
};

static void http_service_start(void)
{
	INFO(("HTTP service starting on port %u (pid %ld)", http_port, getpid()));
	server_addr.sin_port = htons(http_port);
	if (net_conn(NULL, &http_ops, (struct sockaddr *)&server_addr,
	             sizeof server_addr, CONN_STREAM | CONN_LISTEN) == ULONG_MAX) {
		ERROR(("http service: Failed to listen on %u", http_port));
		return;
	}

	http_init_handlers();
	while (!got_sig) {
		service_recv(THIS_SERVICE);
		if (net_poll(NET_POLL_RW, 100))
			break;
	}
	http_free_handlers();
}

/**
 * Read messages from the parent process
 */
static void http_child_read(int fd)
{
	char buf[32];
	recv(fd, buf, sizeof buf, 0);
}

/**
 * Read messages from the child process
 */
static void http_parent_read(int fd)
{
	char buf[32];
	recv(fd, buf, sizeof buf, 0);
}

static void http_service_stop(void)
{
	INFO(("HTTP service shutdown..."));
	got_sig++;
}

struct service_ops http_service_ops = {
	http_service_start,
	http_parent_read,
	http_child_read,
	http_service_stop
};

