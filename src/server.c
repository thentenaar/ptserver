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
#include <stddef.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "net.h"
#include "logging.h"
#include "database.h"
#include "packet.h"
#include "hash.h"
#include "room.h"
#include "server_handler.h"
#include "buddylist.h"
#include "protocol.h"

unsigned short voice_rx_port = 8002;
unsigned short voice_tx_port = 8003;
static unsigned timeout      = 120; /**< seconds */
static const char *db_path   = "ptserver.db";

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
	net_set_timeout(new_conn, timeout);
	pt_context_init(c, new_fd);
	c->db_r = db_open(db_path, 'r');
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

	c->status = STATUS_OFFLINE;
	if (*c->uid_str && ht_get_ptr_nc(uid_to_context, c->uid_str) == ctx) {
		part_all(c);
		broadcast_status(c);
		ht_rm(uid_to_context, c->uid_str);
	}

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
	int c;
	unsigned long i;
	struct sockaddr_in addr;

	signal(SIGINT, sighandler);
	signal(SIGPIPE, SIG_IGN);
	srand(time(NULL));

	force_exit = 0;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(5001);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	while ((c = getopt(argc, argv, ":hd:p:m:s:t:")) != -1) {
		switch (c) {
		case 'h': /* [h]elp */
			goto usage;
		case 'd': /* [d]atabase file */
			db_path = optarg;
			break;
		case 'p': /* [p]ort */
			if ((i = strtoul(optarg, NULL, 10)) >= 65535) {
				ERROR(("Invalid value for port: %ul", i));
				goto err;
			}

			voice_rx_port = i + 1;
			voice_tx_port = i + 2;
			addr.sin_port = htons(i);
			break;
		case 'm': /* [m]axconn */
			if ((i = strtoul(optarg, NULL, 10)) > MAX_CONN) {
				ERROR(("Invalid value for maxconn: %lu (%u max)", i, MAX_CONN));
				goto err;
			}

			max_conn = (unsigned)i;
			break;
		case 's': /* [s]erver ip */
			if (!inet_pton(AF_INET, optarg, &addr.sin_addr)) {
				ERROR(("Invalid value for server ip: %s", optarg));
				goto err;
			}
			break;
		case 't': /* connection [t]imeout */
			if ((i = strtoul(optarg, NULL, 10)) < UINT_MAX)
				timeout = (unsigned)i;
			break;
		case ':': /* Missing required argument */
			ERROR(("Option -%c requires an argument", optopt));
			goto usage;
		case '?': /* Option argument not in opt string */
			ERROR(("Unknown option -%c", optopt));
			goto usage;
		}
	}

	if (net_conn(NULL, &server_ops, (struct sockaddr *)&addr,
	             sizeof addr, CONN_STREAM | CONN_LISTEN) == ULONG_MAX)
		goto err;

	INFO(("Listening on %s:%u", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)));
	db_w           = db_open(db_path, 'w');
	uid_to_context = ht_alloc(HT_VALUE_DEFAULT, HT_STATIC_KEYS);
	if (!db_w || !uid_to_context)
		goto err;

	while (!force_exit) {
		if (net_poll())
			force_exit++;
	}

	INFO(("Shutting down..."));
	for (i = 0; i < max_conn; i++)
		net_close(i);

err:
	db_close(db_w);
	ht_free(uid_to_context);
	return !force_exit;

usage:
	printf("Usage: %s [-h] [-d database_file] [-p port] [-m max_connections] "
	       "[-s server_ip] [-t connection_timeout]\n\n", argv[0]);
	printf("The defaults are: -d ptserver.db -p 5001 -m %u -s 0.0.0.0 -t 120\n\n", MAX_CONN);
	puts("Note: the argument given for -m may be constrained by resource limits.");
	puts("Also, the ports used for voice rx/tx will be port + 1 and port + 2 respectively.");
	return 0;
}

