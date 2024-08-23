#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "logging.h"
#include "database.h"
#include "packet.h"
#include "hash.h"
#include "server_handler.h"

#define POLL_ERRS (POLLIN | POLLHUP | POLLERR | POLLNVAL)

static nfds_t nfds;
static struct pt_context *ctx[MAX_CONNECTIONS + 1];
static struct pollfd fds[MAX_CONNECTIONS + 1];
static unsigned max_conn = MAX_CONNECTIONS;
static volatile int force_exit;
static void *db_w;
static void *rm_room_user;
struct ht *uid_to_context; /**< uid -> context for logged in users */

static void sighandler(int sig)
{
	(void)sig;
	force_exit = 1;
}

/**
 * Create a listening IPv4 socket
 */
static int listen_v4(unsigned short port)
{
	int ret = 1, fd;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		ERROR(("failed to create IPv4 socket"));
		goto err;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,  &ret, sizeof(int)) ||
	    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)) {
		ERROR(("failed to set IPv4 socket options"));
		goto err;
	}

	if (bind(fd, (struct sockaddr *)&addr,  sizeof(addr))) {
		ERROR(("failed to bind IPv4 socket"));
		goto err;
	}

	if (listen(fd, SOMAXCONN)) {
		ERROR(("failed to listen on IPv4 socket"));
		goto err;
	}

	INFO(("Listening on %s port %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)));
	fds[0].fd     = fd;
	fds[0].events = POLLIN;
	return 0;

err:
	if (fd >= 0) close(fd);
	return -1;
}

/**
 * Accept new connections
 */
static void do_accept(void)
{
	int fd;
	void *p;
	struct linger l;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof addr;

	if ((fd = accept(fds[0].fd, (struct sockaddr *)&addr, &addrlen)) < 0)
		goto ret;

	if (nfds + 1 >= max_conn) {
		ERROR(("Refusing connection, max was reached"));
		goto err;
	}

	/* Set the socket to non-blocking mode */
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
		goto err;

	/* Shorten the time spent lingering for FIN to 2 seconds */
	l.l_onoff = 1;
	l.l_linger = 2;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)))
		goto err;

	INFO(("Connection received from %s:%u", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)));
	if (!(p = malloc(sizeof **ctx)))
		abort();
	ctx[nfds] = p;

	pt_context_init(ctx[nfds], fd);
	ctx[nfds]->db_r     = db_open("ptserver.db", 'r');
	ctx[nfds]->db_w     = db_w;
	ctx[nfds]->fd       = fd;
	fds[nfds].fd        = fd;
	fds[nfds++].events  = POLLIN | POLLOUT;
	memcpy(&ctx[nfds - 1]->addr, &addr, addrlen);

	/* Start in the login flow */
	transition_to(ctx[nfds - 1], login_flow);

ret:
	return;

err:
	if (fd > 0) close(fd);
}

/**
 * Poll and service our sockets
 */
static int poll_sockets(void)
{
	nfds_t i;
	int active;

	fds[0].events = POLLIN;
	if ((active = poll(fds, nfds, -1)) < 0 ||
	    fds[0].revents & (POLL_ERRS & ~POLLIN))
		return -1;

	if (!active)
		goto ret;

	/* Accept new connections */
	if (fds[0].revents & POLLIN)
		do_accept();

	/* Service existing connections */
	for (i = 1; i < nfds; i++) {
		if ((fds[i].revents & fds[i].events) & POLLOUT && ctx[i]->npkts_out)
			packet_out(ctx[i]);
		else if (!ctx[i]->disconnect && (fds[i].revents & fds[i].events) & POLLIN) {
			db_begin(db_w);
			packet_in(ctx[i]);
			db_end(db_w);
		} else if (ctx[i]->disconnect || !fds[i].events || fds[i].revents & POLL_ERRS) {
			INFO(("Client %s:%u %s",
			     inet_ntoa(ctx[i]->addr.sin_addr),
			     ntohs(ctx[i]->addr.sin_port),
			     ctx[i]->on_packet ? "disconnected" : "kicked"));

			if (*ctx[i]->uid_str)
				ht_rm(uid_to_context, ctx[i]->uid_str);
			shutdown(fds[i].fd, SHUT_RDWR);
			close(fds[i].fd);

			db_close(ctx[i]->db_r);
			pt_context_destroy(ctx[i]);
			free(ctx[i]);
			ctx[i] = NULL;

			if (i < nfds - 1) {
				memmove(fds + i, fds + i + 1, (nfds - i) * sizeof *fds);
				memmove(ctx + i, ctx + i + 1, (nfds - i) * sizeof *ctx);
			}

			nfds--;
			i--;
		}

		fds[i].events = ctx[i] ? (ctx[i]->on_packet ? POLLIN : 0) | (ctx[i]->npkts_out ? POLLOUT : 0) : POLLIN;
	}

ret:
	return 0;
}

/**
 * Broadcast a packet to all connected users
 */
void broadcast(struct pt_packet *pkt)
{
	nfds_t i;

	for (i = 1; i < nfds; i++) {
		if (ctx[i]->on_packet)
			send_packet(ctx[i], pkt);
	}
}

int main(int argc, char *argv[])
{
	nfds_t i;
	unsigned short port = 5001;

	(void)argc;
	(void)argv;

	nfds = 1;
	force_exit = 0;
	memset(fds, 0, sizeof fds);
	memset(ctx, 0, sizeof ctx);

	/* TODO: popt (port, max_conn, db_path) */

	signal(SIGINT, sighandler);
	signal(SIGPIPE, SIG_IGN);
	srand(time(NULL));
	listen_v4(port);

	db_w = db_open("ptserver.db", 'w');
	uid_to_context = ht_alloc(HT_VALUE_DEFAULT, HT_STATIC_KEYS);

	while (!force_exit) {
		if (poll_sockets())
			force_exit++;
	}

	for (i = 0; i < nfds; i++) {
		shutdown(fds[i].fd, SHUT_RDWR);
		close(fds[i].fd);
		if (ctx[i]) {
			db_close(ctx[i]->db_r);

			if (!rm_room_user)
				rm_room_user = db_prepare(db_w, "DELETE FROM room_users WHERE uid=?");
			db_reset_prepared(rm_room_user);
			db_bind(rm_room_user, "i", ctx[i]->uid);
			db_do_prepared(rm_room_user);
			pt_context_destroy(ctx[i]);
		}
	}

	db_free_prepared(rm_room_user);
	db_close(db_w);
	ht_free(uid_to_context);
	return !force_exit;
}

