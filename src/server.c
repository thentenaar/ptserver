/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ft.h"
#include "net.h"
#include "logging.h"
#include "database.h"
#include "packet.h"
#include "hash.h"
#include "server_handler.h"

static volatile int force_exit;
static void *db_w;
struct ht *uid_to_context; /**< uid -> context for logged in users */

static void sighandler(int sig)
{
	(void)sig;
	force_exit = 1;
}

static void server_init(void *ctx, unsigned long conn, int fd)
{
	(void)ctx;
	(void)conn;
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static void server_accept(void *ctx, struct sockaddr *addr,
                          socklen_t addrlen, unsigned long new_conn,
                          int new_fd)
{
	struct pt_context *c;
	struct sockaddr_in *ain = (struct sockaddr_in *)addr;

	(void)ctx;
	if (fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL, 0) | O_NONBLOCK))
		goto err;

	INFO(("Connection received from %s:%u", inet_ntoa(ain->sin_addr), ntohs(ain->sin_port)));
	if (!(c = malloc(sizeof *c)))
		goto err;

	net_set_ctx(new_conn, c);
	pt_context_init(c, new_fd);
	c->db_r = db_open("ptserver.db", 'r');
	c->db_w = db_w;
	c->fd   = new_fd;
	memcpy(&c->addr, addr, addrlen);

	/* Start in the login flow */
	transition_to(c, login_flow);
	return;

err:
	net_close(new_conn);
	return;
}

static void server_read(void *ctx, unsigned long conn, int fd)
{
	struct pt_context *c = ctx;

	(void)fd;
	if (c->disconnect) {
		net_close(conn);
		return;
	}

	db_begin(db_w);
	packet_in(c);
	db_end(db_w);
}

static void server_write(void *ctx, unsigned long conn, int fd)
{
	struct pt_context *c = ctx;

	(void)conn;
	(void)fd;
	if (c->npkts_out)
		packet_out(c);
}

static void server_close(void *ctx, unsigned long conn, int fd)
{
	struct pt_context *c = ctx;

	(void)conn;
	(void)fd;

	if (!ctx) return;
	INFO(("Client %s:%u %s",
	     inet_ntoa(c->addr.sin_addr),
	     ntohs(c->addr.sin_port),
	     c->on_packet ? "disconnected" : "kicked"));

	if (*c->uid_str)
		ht_rm(uid_to_context, c->uid_str);

	db_close(c->db_r);
	pt_context_destroy(c);
	free(c);
}

static int server_err(void *ctx, unsigned long conn, int fd)
{
	(void)conn;
	(void)fd;

	if (!ctx) {
		ERROR(("Error on server socket: errno=%d", errno));
		++force_exit;
		return 0;
	}

	return 1;
}

static struct netconn_ops server_ops = {
	server_init,
	NULL,
	server_accept,
	server_read,
	server_write,
	server_close,
	server_err
};

/**
 * Broadcast a packet to all connected users
 */
void broadcast(struct pt_packet *pkt)
{
	unsigned long i;
	struct pt_context *ctx;

	for (i = 1; i < max_conn; i++) {
		if (net_get_ops(i) != &server_ops || !(ctx = net_get_ctx(i)))
			continue;

		if (ctx->on_packet)
			send_packet(ctx, pkt);
	}
}

int main(int argc, char *argv[])
{
	unsigned long i;
	unsigned short port = 5001;
	struct sockaddr_in addr;

	(void)argc;
	(void)argv;

	force_exit = 0;

	/* TODO: popt (port, max_conn, db_path) */

	signal(SIGINT, sighandler);
	signal(SIGPIPE, SIG_IGN);
	srand(time(NULL));

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (net_conn(NULL, &server_ops, (struct sockaddr *)&addr,
	             sizeof addr, CONN_STREAM | CONN_LISTEN) == ULONG_MAX)
		goto err;

	INFO(("Listening on 0.0.0.0:%u", port))
	db_w           = db_open("ptserver.db", 'w');
	uid_to_context = ht_alloc(HT_VALUE_DEFAULT, HT_STATIC_KEYS);

	while (!force_exit) {
		if (net_poll())
			force_exit++;
	}

	for (i = 0; i < max_conn; i++)
		net_close(i);

err:
	db_close(db_w);
	ht_free(uid_to_context);
	return !force_exit;
}

