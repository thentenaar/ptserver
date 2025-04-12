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
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "ft.h"
#include "net.h"
#include "macros.h"
#include "packet.h"
#include "protocol.h"

#define XFER_BUFSIZ  8192
#define XFER_TIMEOUT 60   /* seconds */

#define STATUS_LISTENING 0
#define STATUS_CONNECT   1
#define STATUS_ACCEPTED  2
#define STATUS_CONNECTOK 3
#define STATUS_AUTHOK    4
#define STATUS_SENDOK    5
#define STATUS_SEND_DCC  6
#define STATUS_READ_NEW  7
#define STATUS_SEND_NEW  8
#define STATUS_PROXY     9

struct ft_state {
	unsigned long uid;           /**< sender uid */
	unsigned long r_uid;         /**< recipient uid */
	unsigned long id;            /**< xfer id */
	unsigned refcnt;
	size_t buf_len;
	size_t file_size;
	unsigned long conn[2];
	in_addr_t ep[2];             /**< remote ip */
	unsigned short port[2];
	unsigned status[2];
	unsigned type[2];
	char nick[NICKNAME_MAX + 1]; /**< sender nick */
	char filename[PATH_MAX + 1];
	char buf[XFER_BUFSIZ + 512];
};

struct ft_ctx {
	unsigned recipient; /**< 0 if sender, 1 if recipient */
	struct ft_state *state;
};

static void ft_init(void *ctx, unsigned long conn, int fd, int fd2)
{
	struct ft_ctx *c = ctx;
	struct sockaddr_in addr;
	socklen_t slen = sizeof addr;

	(void)conn;
	(void)fd2;
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	if (!c->state->port[c->recipient]) {
		getsockname(fd, (struct sockaddr *)&addr, &slen);
		c->state->port[c->recipient] = ntohs(addr.sin_port);
	}

	net_set_timeout(conn, XFER_TIMEOUT);
}

static void ft_accept(void *ctx, struct sockaddr *addr, socklen_t addrlen, unsigned long new_conn, int new_fd)
{
	unsigned long old_conn;
	struct ft_ctx *c = ctx;

	(void)addr;
	(void)addrlen;
	(void)new_fd;
	old_conn = c->state->conn[c->recipient];
	c->state->status[c->recipient] = STATUS_ACCEPTED;
	c->state->conn[c->recipient]   = new_conn;
	net_close(old_conn);
}

/* We only connect to the DCC recipient */
static void ft_connect(void *ctx, unsigned long conn, int fd)
{
	struct ft_ctx *c = ctx;

	(void)conn;
	(void)fd;
	c->state->status[c->recipient] = STATUS_SEND_DCC;
}

static void ft_close(void *ctx, unsigned long conn, int fd)
{
	struct ft_ctx *c = ctx;

	(void)fd;
	if (!c || c->state->conn[c->recipient] != conn)
		return;

	c->state->conn[c->recipient] = ULONG_MAX;
	if (!--c->state->refcnt)
		free(c->state);
	free(c);
}

static int ft_err(void *ctx, unsigned long conn, int fd)
{
	struct ft_ctx *c = ctx;

	(void)conn;
	(void)fd;
	return (c->recipient || errno != EPIPE) || errno == ETIMEDOUT;
}

static void proxy_read(void *ctx, unsigned long conn, int fd)
{
	int br;
	struct ft_ctx *c = ctx;

	if (c->state->buf_len >= XFER_BUFSIZ - 1)
		return;

	if ((br = recv(fd, c->state->buf + c->state->buf_len, XFER_BUFSIZ - c->state->buf_len, 0)) < 0)
		return;

	if (!br) {
		net_close(conn);
		return;
	}

	c->state->buf_len += br;
}

static void proxy_write(void *ctx, unsigned long conn, int fd)
{
	int bs;
	struct ft_ctx *c = ctx;

	if (c->state->conn[!c->recipient] == ULONG_MAX || !c->state->file_size) {
		net_close(conn);
		return;
	}

	if (!c->state->buf_len) {
		return;
	}

	if ((bs = send(fd, c->state->buf, c->state->buf_len, MSG_NOSIGNAL)) <= 0) {
		net_close(conn);
		return;
	}

	memmove(c->state->buf, c->state->buf + bs, c->state->buf_len - bs);
	c->state->buf_len -= bs;
	c->state->file_size -= bs;
}

static void read_dcc(void *ctx, unsigned long conn, int fd)
{
	char buf[64];
	unsigned namelen;
	struct ft_ctx *c = ctx;


	switch (c->state->status[c->recipient]) {
	case STATUS_ACCEPTED:
		/**
		 * 2 bytes (name length)
		 * name
		 * 4 bytes (file size)
		 */
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
		if (recv(fd, buf, 2, 0) < 2)
			goto close;

		namelen = (buf[1] << 8) | buf[0];
		if ((size_t)(6 + namelen) >= sizeof c->state->filename)
			goto close;

		if (recv(fd, c->state->filename, namelen, 0) < (int)namelen)
			goto close;

		if (recv(fd, buf + 2, 4, 0) < 4)
			goto close;

		c->state->file_size = (buf[5] << 24) | (buf[4] << 16) | (buf[3] << 8) | buf[2];
		c->state->filename[namelen] = '\0';
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

		if (c->state->status[!c->recipient] == STATUS_CONNECT)
			net_connect(c->state->conn[!c->recipient]);
		c->state->status[c->recipient] = STATUS_PROXY;
		break;
	case STATUS_PROXY:
		if (!c->recipient)
			proxy_read(ctx, conn, fd);
		break;
	}

	return;

close:
	net_close(conn);
}

static void write_dcc(void *ctx, unsigned long conn, int fd)
{
	size_t namelen;
	struct ft_ctx *c = ctx;

	(void)conn;
	(void)fd;
	switch (c->state->status[c->recipient]) {
	case STATUS_SEND_DCC:
		if (!c->state->file_size)
			break;

		/* Just in case the sender sent data before we got this out */
		namelen = strlen(c->state->filename) & 0xffff;
		if (c->state->buf_len) {
			if (namelen > 512 - 6) {
				net_close(conn);
				return;
			}

			memmove(c->state->buf + 512, c->state->buf, c->state->buf_len);
		}

		memcpy(c->state->buf + 2, c->state->filename, namelen);
		c->state->buf[0]           = namelen & 0xff;
		c->state->buf[1]           = (namelen >> 8) & 0xff;
		c->state->buf[2 + namelen] = c->state->file_size & 0xff;
		c->state->buf[3 + namelen] = (c->state->file_size >> 8)  & 0xff;
		c->state->buf[4 + namelen] = (c->state->file_size >> 16) & 0xff;
		c->state->buf[5 + namelen] = (c->state->file_size >> 24) & 0xff;

		if (c->state->buf_len)
			memmove(c->state->buf + 6 + namelen, c->state->buf + 512, c->state->buf_len);
		c->state->buf_len   += 6 + namelen;
		c->state->file_size += 6 + namelen;
		c->state->status[c->recipient] = STATUS_PROXY;
		break;
	case STATUS_PROXY:
		if (c->recipient)
			proxy_write(ctx, conn, fd);
		break;
	}
}

static void read_new(void *ctx, unsigned long conn, int fd)
{
	int br;
	char buf[1024], *x, *filename;
	unsigned long namelen, sender_uid, xfer_id;
	struct ft_ctx *c = ctx;

	switch (c->state->status[c->recipient]) {
	case STATUS_CONNECTOK:
		if ((br = recv(fd, buf, sizeof buf - 1, 0)) <= 0)
			goto close;

		buf[br] = '\0';
		if (sscanf(buf, "INTRO\t%lu\t%lu\n", &sender_uid, &xfer_id) != 2)
			goto close;

		if (xfer_id != c->state->id ||
			(c->recipient  && sender_uid != c->state->r_uid) ||
			(!c->recipient && sender_uid != c->state->uid))
			goto close;

		c->state->status[c->recipient] = STATUS_AUTHOK;
		break;
	case STATUS_READ_NEW:
		/**
		 * SEND\tsender_uid\trecipient_uid\tsender_nick\tfile_size\tfilename\n
		 */
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
		if ((br = recv(fd, buf, sizeof buf - 1, 0)) <= 0 || !(x = strchr(buf, '\n')))
			goto close;
		*x = '\0';

		/* If we got more than the SEND, stick it in the buffer */
		if (br > 1 + x - buf) {
			br -= 1 + x - buf;
			memcpy(c->state->buf + c->state->buf_len, x + 1, br);
			c->state->buf_len += br;
		}

		for (filename = x; filename > buf && *filename != '\t'; filename--);
		*filename = '\0';
		if (filename == buf || !(namelen = strlen(++filename)) ||
		    namelen > sizeof c->state->filename)
			goto close;
		memcpy(c->state->filename, filename, namelen + 1);

		for (x = filename; x > buf && *x != '\t'; x--);
		c->state->file_size = strtoul(x, NULL, 10);
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

		if (c->state->status[!c->recipient] == STATUS_CONNECT)
			net_connect(c->state->conn[!c->recipient]);
		c->state->status[c->recipient] = STATUS_PROXY;
		break;
	case STATUS_PROXY:
		if (!c->recipient)
			proxy_read(ctx, conn, fd);
		break;
	}

	return;

close:
	net_close(conn);
}

static void write_new(void *ctx, unsigned long conn, int fd)
{
	size_t s;
	struct ft_ctx *c = ctx;

	switch (c->state->status[c->recipient]) {
	case STATUS_ACCEPTED:
		if (send(fd, "CONNECT\tOK\n", 11, MSG_NOSIGNAL) <= 0)
			goto close;
		c->state->status[c->recipient] = STATUS_CONNECTOK;
		break;
	case STATUS_AUTHOK:
		if (send(fd, "AUTH\tOK\n", 8, MSG_NOSIGNAL) <= 0)
			goto close;
		c->state->status[c->recipient] = STATUS_SENDOK;
		break;
	case STATUS_SENDOK:
		c->state->status[c->recipient] = c->recipient + STATUS_READ_NEW;
		if (!c->recipient && send(fd, "SEND\tOK\n", 8, MSG_NOSIGNAL) <= 0)
			goto close;
		break;
	case STATUS_SEND_NEW:
		if (!c->state->file_size)
			break;

		/* Just in case the sender sent data before we got this out */
		if (c->state->buf_len) {
			if (strlen(c->state->filename) > 512 - 73) {
				net_close(conn);
				return;
			}

			memmove(c->state->buf + 512, c->state->buf, c->state->buf_len);
		}

		s = sprintf(
			c->state->buf, "SEND\t%lu\t%lu\t%s\t%lu\t%.*s\n",
			c->state->uid,
		    c->state->r_uid,
		    c->state->nick,
		    c->state->file_size,
		    (unsigned)strlen(c->state->filename),
		    c->state->filename
		);

		if (c->state->buf_len)
			memmove(c->state->buf + s, c->state->buf + 512, c->state->buf_len);
		c->state->buf_len   += s;
		c->state->file_size += s;
		c->state->status[c->recipient] = STATUS_PROXY;
		break;
	case STATUS_PROXY:
		if (c->recipient)
			proxy_write(ctx, conn, fd);
		break;
	}

	return;

close:
	net_close(conn);
}

static const struct netconn_ops ft_ops[2] = {
{
	ft_init,
	NULL,
	ft_connect,
	ft_accept,
	read_dcc,
	write_dcc,
	ft_close,
	ft_err
},
{
	ft_init,
	NULL,
	NULL,
	ft_accept,
	read_new,
	write_new,
	ft_close,
	ft_err
}};

/**
 * Create a pipe between two sockets, serviced by the
 * general poll(2) loop.
 *
 * \return non-zero on failure
 */
static int ft_pipe(struct ft_state *state)
{
	unsigned long conn1 = ULONG_MAX, conn2 = ULONG_MAX;
	struct sockaddr_in addr1, addr2;
	struct ft_ctx *ctx[2] = { NULL, NULL };

	if (!state || !(ctx[0] = calloc(1, sizeof **ctx)) ||
	    !(ctx[1] = calloc(1, sizeof **ctx)))
		goto err;

	ctx[0]->state = state;
	ctx[1]->state = state;
	ctx[1]->recipient++;

	memset(&addr1, 0, sizeof(struct sockaddr_in));
	memset(&addr2, 0, sizeof(struct sockaddr_in));
	addr1.sin_family      = AF_INET;
	addr1.sin_port        = htons(state->port[0]);
	addr1.sin_addr.s_addr = htonl(INADDR_ANY);
	addr2.sin_family      = AF_INET;
	addr2.sin_port        = htons(state->port[1]);
	addr2.sin_addr.s_addr = state->port[1] ? state->ep[1] : htonl(INADDR_ANY);

	conn1 = net_conn(ctx[0], ft_ops + state->type[0],
	                 (struct sockaddr *)&addr1, sizeof addr1,
	                 CONN_STREAM | CONN_LISTEN);

	conn2 = net_conn(ctx[1], ft_ops + state->type[1],
	                 (struct sockaddr *)&addr2, sizeof addr2,
	                 CONN_STREAM | ((state->status[1] == STATUS_CONNECT)
	                 ? CONN_DEFER_CONNECT : CONN_LISTEN));

	state->refcnt  = (conn1 < max_conn) + (conn2 < max_conn);
	state->conn[0] = conn1;
	state->conn[1] = conn2;
	if (state->refcnt == 2)
		return 0;

err:
	if (conn1 != ULONG_MAX) net_close(conn1); else free(ctx[0]);
	if (conn2 != ULONG_MAX) net_close(conn2); else free(ctx[1]);
	return -1;
}

/**
 * Handle the initial file transfer request
 *
 * \return 0 on success
 */
int ft_xfer_init(struct pt_context *sender, struct pt_context *recipient)
{
	char buf[2048];
	size_t len;

	if (recipient->protocol_version < PROTOCOL_VERSION_70) {
		sprintf(buf, "port=0\nuid=%lu\nnickname=%s",
		       sender->uid, sender->user.nickname);
		send_packet(recipient, new_packet(PACKET_DCC_XFER_REQUEST, strlen(buf), buf, PACKET_F_COPY));
	} else {
		++sender->next_ftid;
		buf[0] = (sender->uid >> 24) & 0xff;
		buf[1] = (sender->uid >> 16) & 0xff;
		buf[2] = (sender->uid >> 8)  & 0xff;
		buf[3] = sender->uid & 0xff;
		buf[4] = (sender->next_ftid >> 24) & 0xff;
		buf[5] = (sender->next_ftid >> 16) & 0xff;
		buf[6] = (sender->next_ftid >> 8)  & 0xff;
		buf[7] = sender->next_ftid & 0xff;
		if (sender->protocol_version >= PROTOCOL_VERSION_70) {
			len = sprintf(buf + 8, "%.*s\n%s", sender->pkt_in.length - 4,
			              sender->pkt_in.data + 4, sender->user.nickname);
		} else {
			len = sprintf(buf + 8, "file.dat\n%s", sender->user.nickname);
		}

		send_packet(recipient, new_packet(
			sender->pkt_in.type == PACKET_IMG_XFER_INIT ?
			PACKET_IMG_XFER_REQUEST : PACKET_FILE_XFER_REQUEST,
			len + 8, buf, PACKET_F_COPY
		));
	}

	return 0;
}

/**
 * The recipient has accepted a file transfer request
 *
 * \return 0 on success
 */
int ft_xfer_accept(struct pt_context *sender, struct pt_context *recipient)
{
	char buf[16];
	unsigned long ftid = 0;
	struct ft_state *state;

	if (recipient->protocol_version >= PROTOCOL_VERSION_70) {
		if (!(recipient->pkt_in.data[8] | recipient->pkt_in.data[9]))
			return ft_xfer_reject(sender, recipient);

		ftid = ((recipient->pkt_in.data[4] & 0xff) << 24) |
		       ((recipient->pkt_in.data[5] & 0xff) << 16) |
		       ((recipient->pkt_in.data[6] & 0xff) <<  8) |
		        (recipient->pkt_in.data[7] & 0xff);
	}

	if (!(state = calloc(1, sizeof *state)))
		return -1;

	state->uid     = sender->uid;
	state->r_uid   = recipient->uid;
	state->id      = ftid;
	state->ep[0]   = sender->addr.sin_addr.s_addr;
	state->ep[1]   = recipient->addr.sin_addr.s_addr;
	state->type[0] = sender->protocol_version    >= PROTOCOL_VERSION_70;
	state->type[1] = recipient->protocol_version >= PROTOCOL_VERSION_70;
	memcpy(state->nick, sender->user.nickname,
	       min(strlen(sender->user.nickname), NICKNAME_MAX - 1));

	if (recipient->protocol_version < PROTOCOL_VERSION_70) {
		state->port[1]   = (recipient->pkt_in.data[4] << 8) | recipient->pkt_in.data[5];
		state->status[1] = STATUS_CONNECT;
	}

	if (ft_pipe(state)) {
		free(state);
		return -1;
	}

	if (recipient->protocol_version >= PROTOCOL_VERSION_70) {
		buf[0] = (sender->uid >> 24) & 0xff;
		buf[1] = (sender->uid >> 16) & 0xff;
		buf[2] = (sender->uid >> 8)  & 0xff;
		buf[3] = sender->uid & 0xff;
		buf[4] = (ftid >> 24) & 0xff;
		buf[5] = (ftid >> 16) & 0xff;
		buf[6] = (ftid >> 8)  & 0xff;
		buf[7] = ftid & 0xff;
		buf[8] = 0;
		buf[9] = 0;
		buf[10] = (recipient->server_ip >> 24) & 0xff;
		buf[11] = (recipient->server_ip >> 16) & 0xff;
		buf[12] = (recipient->server_ip >> 8)  & 0xff;
		buf[13] = recipient->server_ip & 0xff;
		buf[14] = (state->port[1] >> 8) & 0xff;
		buf[15] = state->port[1] & 0xff;
		send_packet(recipient, new_packet(PACKET_FILE_XFER_ACCEPTED, 16, buf, PACKET_F_COPY));
	}

	if (sender->protocol_version < PROTOCOL_VERSION_70) {
		buf[0] = (recipient->uid >> 24) & 0xff;
		buf[1] = (recipient->uid >> 16) & 0xff;
		buf[2] = (recipient->uid >> 8)  & 0xff;
		buf[3] = recipient->uid & 0xff;
		buf[4] = (sender->server_ip >> 24) & 0xff;
		buf[5] = (sender->server_ip >> 16) & 0xff;
		buf[6] = (sender->server_ip >>  8) & 0xff;
		buf[7] = sender->server_ip & 0xff;
		buf[8] = (state->port[0] >> 8) & 0xff;
		buf[9] = state->port[0] & 0xff;
		send_packet(sender, new_packet(PACKET_DCC_XFER_ACCEPTED, 10, buf, PACKET_F_COPY));
	} else {
		buf[0] = (recipient->uid >> 24) & 0xff;
		buf[1] = (recipient->uid >> 16) & 0xff;
		buf[2] = (recipient->uid >> 8)  & 0xff;
		buf[3] = recipient->uid & 0xff;
		buf[4] = (ftid >> 24) & 0xff;
		buf[5] = (ftid >> 16) & 0xff;
		buf[6] = (ftid >> 8)  & 0xff;
		buf[7] = ftid & 0xff;
		buf[8] = 0;
		buf[9] = 1;
		buf[10] = (sender->server_ip >> 24) & 0xff;
		buf[11] = (sender->server_ip >> 16) & 0xff;
		buf[12] = (sender->server_ip >> 8)  & 0xff;
		buf[13] = sender->server_ip & 0xff;
		buf[14] = (state->port[0] >> 8) & 0xff;
		buf[15] = state->port[0] & 0xff;
		send_packet(sender, new_packet(PACKET_FILE_XFER_ACCEPTED, 16, buf, PACKET_F_COPY));
	}

	return 0;
}

/**
 * The recipient has rejected a file transfer request
 *
 * \return 0 on success
 */
int ft_xfer_reject(struct pt_context *sender, struct pt_context *recipient)
{
	char buf[8];

	if (sender->protocol_version < PROTOCOL_VERSION_70) {
		buf[0] = (recipient->uid >> 24) & 0xff;
		buf[1] = (recipient->uid >> 16) & 0xff;
		buf[2] = (recipient->uid >> 8)  & 0xff;
		buf[3] = recipient->uid & 0xff;
		send_packet(sender, new_packet(PACKET_DCC_XFER_REJECTED, 4, buf, PACKET_F_COPY));
		return 0;
	}

	if (recipient->pkt_in.type == PACKET_FILE_XFER_ACCEPT) {
		memcpy(buf, recipient->pkt_in.data, 8);
		send_packet(sender, new_packet(PACKET_FILE_XFER_REJECTED, 8, buf, PACKET_F_COPY));
		return 0;
	}

	buf[0] = (recipient->uid >> 24) & 0xff;
	buf[1] = (recipient->uid >> 16) & 0xff;
	buf[2] = (recipient->uid >> 8)  & 0xff;
	buf[3] = recipient->uid & 0xff;
	buf[4] = 0;
	buf[5] = 0;
	buf[6] = 0;
	buf[7] = 0;
	send_packet(sender, new_packet(PACKET_FILE_XFER_REJECTED, 8, buf, PACKET_F_COPY));
	return 0;
}

