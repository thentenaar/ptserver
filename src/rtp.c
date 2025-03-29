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
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "net.h"
#include "hash.h"
#include "codec.h"
#include "gsm.h"
#include "service.h"
#include "packet.h"
#include "protocol.h"
#include "logging.h"
#include "room.h"
#include "rtp.h"

/* server.c */
extern volatile int got_sig;
extern unsigned short voice_port;
extern struct sockaddr_in server_addr;
extern struct ht *uid_to_context;
extern unsigned long rtp_service;

#define RTP_HEADERSZ 12
#define FRAMES_PKT   4
#define FRAME_TIME   20 /* ms */

struct rtp_ctx;
struct rtp_stream {
	unsigned long      id;          /* room id */
	unsigned char      channels;    /* simultaenous speakers */
	unsigned long      contributor; /* contributor's uid */
	short              *buf;
	const struct codec *codec;
	struct ht          *uid_to_listener;
	unsigned long      *listeners; /* connection ids */
	size_t             n_listeners;
	unsigned char      *out;       /* RTP packet out */
	size_t             outsz;
	unsigned long      ts;         /* last RTP timestamp out */
	unsigned short     seq_out;    /* last RTP sequence no. */
};

struct rtp_ctx {
	struct rtp_stream *stream;
	unsigned       mute;      /* non-zero if muted       */
	unsigned       user_mute; /* non-zero if muting room */
	unsigned       parted;    /* non-zero if parted      */
	unsigned       index;     /* index in listeners      */
	unsigned long  uid;       /* user id                 */
	unsigned long  conn;      /* connection id           */
	unsigned char  *in;       /* packet in buffer        */
	int            burn;      /* rx bytes to burn        */
};

static size_t n_streams;
static struct rtp_stream **streams;
static struct ht *rid_to_stream;

static struct rtp_stream *new_stream(unsigned long id, unsigned channels,
                                     const struct codec *factory)
{
	char buf[16];
	struct rtp_stream *s;

	if (!factory || !factory->ops || !factory->ops->init) {
		ERROR(("new_stream: invalid codec factory %p", factory));
		return NULL;
	}

	if (!(s = calloc(1, sizeof *s)))
		abort();

	if (!(s->codec = factory->ops->init())) {
		ERROR(("new_stream: failed to instantiate codec `%s'", factory->name));
		free(s);
		return NULL;
	}

	s->id       = id;
	s->channels = channels;
	s->outsz    = 4 + RTP_HEADERSZ + s->codec->frame_size * FRAMES_PKT;
	if (!(s->out = malloc(4 + s->outsz)))
		abort();

	srand(time(NULL) + rand() * rand() * time(NULL));
	s->ts      = rand();
	s->out[5]  = s->codec->pt;
	s->out[12] = (id >> 24) & 0xff;
	s->out[13] = (id >> 16) & 0xff;
	s->out[14] = (id >> 8)  & 0xff;
	s->out[15] = id & 0xff;

	if (!(s->buf = malloc(s->codec->spkt * 2)) ||
	    !(s->uid_to_listener = ht_alloc(HT_VALUE_DEFAULT, 0)) ||
	    !(streams = realloc(streams, ++n_streams * sizeof *streams)))
		abort();

	streams[n_streams - 1] = s;
	sprintf(buf, "%lu", id);
	ht_set(rid_to_stream, buf, HT_PTR, s);
	return s;
}

static void free_stream(struct rtp_stream *s)
{
	char buf[16];
	unsigned i;
	struct rtp_ctx *c;

	if (!n_streams || !s)
		return;

	if (s != streams[n_streams - 1]) {
		for (i = 0; i < n_streams; i++) {
			if (streams[i] == s) {
				memmove(streams + i, streams + i + 1, n_streams - i - 1);
				break;
			}
		}
	}

	if (!--n_streams) {
		free(streams);
		streams = NULL;
	} else if (!(streams = realloc(streams, n_streams * sizeof *streams)))
		abort();

	if (s->codec && s->codec->ops->free)
		s->codec->ops->free((void *)s->codec);

	for (i = 0; i < s->n_listeners; i++) {
		if ((c = net_get_ctx(s->listeners[i])))
			c->parted++;
		net_close(s->listeners[i--]);
	}

	sprintf(buf, "%lu", s->id);
	ht_rm(rid_to_stream, buf);
	ht_free(s->uid_to_listener);
	free(s->out);
	free(s->listeners);
	free(s->buf);
	free(s);
}

static unsigned rtp_poll_events(void *ctx, unsigned long conn, int fd)
{
	(void)ctx;
	(void)conn;
	(void)fd;
	return NET_POLL_RW;
}

static void rtp_accept(void *ctx, struct sockaddr *addr, socklen_t addrlen,
                       unsigned long new_conn, int new_fd)
{
	struct rtp_ctx *c;
	const int one = 1;

	(void)ctx;
	(void)addr;
	(void)addrlen;
	(void)new_fd;

	/* Send RTP packets as soon as they're ready */
	if (setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one))
		WARN(("Failed to set TCP_NODELAY: %d", errno));

	net_set_ctx(new_conn, NULL);
	if (!(c = calloc(1, sizeof *c))) {
		net_close(new_conn);
		return;
	}

	net_set_ctx(new_conn, c);
	net_set_timeout(new_conn, 0);
	c->conn = new_conn;
}

/**
 * Read and process one RTP packet
 */
static void rtp_read(void *ctx, unsigned long conn, int fd)
{
	int br;
	unsigned i;
	unsigned char buf[32];
	size_t pkt_size;
	unsigned long ssrc, rid;
	const struct codec *codec;
	struct rtp_ctx *c = ctx;

	if (c->burn) {
		if ((br = recv(fd, buf, c->burn, MSG_PEEK)) == 0)
			goto err;
		if (br < c->burn)
			return;
		recv(fd, buf, c->burn, 0);
		c->burn = 0;
	}

	if (!c->stream) {
		if ((br = recv(fd, buf, 8, MSG_PEEK)) <= 0)
			goto err;

		if (br < 8)
			return;

		if (recv(fd, buf, 8, 0) < 8)
			goto err;
		rid    = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
		c->uid = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
		if (c->uid >> 31)
			c->uid = ~c->uid + 1;

		/**
		 * If channels > 1 or reconnecting we get:
		 *
		 * 4 bytes: -rid
		 * 4 bytes: uid (-uid on reconnect)
		 * 2 bytes: 2   (constant 2)
		 * 2 bytes: 1   TODO: investigate this word
		 *
		 * (this seems redundant...)
		 * 4 bytes: 4
		 * 4 bytes: room_id
		 */
		if (rid >> 31) {
			rid     = ~rid + 1;
			c->burn = 4;
		}

		sprintf((char *)buf, "%lu", rid);
		if (!(c->stream = ht_get_ptr_nc(rid_to_stream, (char *)buf)))
			goto err;

		codec    = c->stream->codec;
		pkt_size = RTP_HEADERSZ + 4 + codec->frame_size * FRAMES_PKT;
		if (!(c->in = calloc(1, pkt_size)))
			goto err;
		sprintf((char *)buf, "%lu", c->uid);

		errno = 0;
		if (!ht_get_ptr(c->stream->uid_to_listener, (char *)buf)) {
			/* We didn't get a join notification? */
			if (errno == ENOENT)
				goto err;
			ht_set(c->stream->uid_to_listener, (char *)buf, HT_PTR, c);
		}

		c->stream->listeners = realloc(
			c->stream->listeners,
			++c->stream->n_listeners * sizeof *c->stream->listeners
		);

		if (!c->stream->listeners)
			abort();

		c->index = c->stream->n_listeners - 1;
		c->stream->listeners[c->index] = conn;
		return;
	}

	/* ... and now, RTP packets */
	if (c->parted || recv(fd, buf, 4, 0) < 4)
		goto err;

	/* For the case where the client still sends the rid after the -rid packet */
	pkt_size = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	if (pkt_size == 4) {
		c->burn = 4;
		return;
	}

	codec = c->stream->codec;
	net_set_timeout(conn, 0);
	if (pkt_size != RTP_HEADERSZ + 4 + codec->frame_size * FRAMES_PKT)
		goto err;

	/* Read packet + uin */
	if ((size_t)recv(fd, c->in, pkt_size, 0) != pkt_size)
		goto err;

	/* Validate v, p, x, cc */
	if (c->in[0] != 0x80)
		goto err;

	/* if muted (e.g. reddot) or someone else is speaking, return */
	if (c->mute || c->stream->contributor)
		return;

	/**
	 * Validate pt
	 *
	 * NB: The marker bit is set on the first frame where the user
	 * keys-up the mic with the non-GSM codecs.
	 */
	if ((c->in[1] & 0x7f) != codec->pt) {
		DEBUG(("Wrong payload type: %u where %u expected",
		      c->in[1] & 0x7f, codec->pt));
		goto err;
	}

	/* Validate ssrc and uin */
	ssrc = (c->in[8]  << 24) | (c->in[9] << 16) |
	       (c->in[10] << 8)  |  c->in[11];
	rid  = (c->in[pkt_size - 1] << 24) | (c->in[pkt_size - 2] << 16) |
	       (c->in[pkt_size - 3] << 8)  |  c->in[pkt_size - 4];

	if (ssrc ^ rid || c->uid ^ ssrc) {
		WARN(("uid mismatch? ssrc=%08x uid=%08x c->uid=%08x", ssrc, rid, c->uid));
		goto err;
	}

	/* decode frames into the stream buffer */
	for (i = 0; i < FRAMES_PKT; i++) {
		codec->ops->decode(
			codec,
			c->in + RTP_HEADERSZ + codec->frame_size * i,
			c->stream->buf + i * codec->spf
		);
	}

	c->stream->contributor = c->uid;
	return;

err:
	net_close(conn);
}

/**
 * Send one RTP packet over the wire
 */
static void rtp_write(void *ctx, unsigned long conn, int fd)
{
	int bs = 0;
	struct rtp_ctx *c = ctx;

	if (!c->stream || !c->uid || !c->stream->contributor || c->user_mute)
		return;

	/* Filter contributor's own audio */
	if (c->stream->contributor == c->uid)
		goto done;

	/* The packet should generally be smaller than the applicable MTU */
	bs = send(fd, c->stream->out, 4 + c->stream->outsz, 0);

done:
	if (bs < 0)
		net_close(conn);
}

static void rtp_close(void *ctx, unsigned long conn, int fd)
{
	char buf[32];
	struct rtp_ctx *c = ctx;

	(void)conn;
	(void)fd;
	if (!c || !c->stream)
		goto done;

	if (c->stream->n_listeners == 1) {
		free(c->stream->listeners);
		c->stream->listeners   = NULL;
		c->stream->n_listeners = 0;
	}

	if (c->stream->listeners) {
		if (c->index != c->stream->n_listeners - 1) {
			memmove(
				c->stream->listeners + c->index,
				c->stream->listeners + c->index + 1,
				c->stream->n_listeners - c->index - 1
			);
		}

		c->stream->listeners = realloc(
			c->stream->listeners,
			--c->stream->n_listeners * sizeof *c->stream->listeners
		);

		if (!c->stream->listeners)
			abort();
	}

	sprintf(buf, "%lu", c->uid);
	if (c->parted) ht_rm(c->stream->uid_to_listener, buf);
	else ht_set(c->stream->uid_to_listener, buf, HT_PTR, NULL);

	/* Notify the parent of the disconnection */
	if (!c->parted && c->stream && c->uid) {
		buf[0] = (c->stream->id >> 24) & 0xff;
		buf[1] = (c->stream->id >> 16) & 0xff;
		buf[2] = (c->stream->id >> 8)  & 0xff;
		buf[3] = c->stream->id & 0xff;
		buf[4] = (c->uid >> 24) & 0xff;
		buf[5] = (c->uid >> 16) & 0xff;
		buf[6] = (c->uid >> 8)  & 0xff;
		buf[7] = c->uid & 0xff;
		service_send(0, buf, 8);
	}

done:
	if (c) {
		free(c->in);
		memset(c, 0, sizeof *c);
		net_set_ctx(conn, NULL);
	}
	free(c);
}

static int rtp_err(void *ctx, unsigned long conn, int fd)
{
	(void)ctx;
	(void)conn;
	(void)fd;
	return 1;
}

static struct netconn_ops rtp_ops = {
	NULL,
	rtp_poll_events,
	NULL,
	rtp_accept,
	rtp_read,
	rtp_write,
	rtp_close,
	rtp_err
};

static void rtp_service_start(void)
{
	unsigned i, j;

	INFO(("RTP service starting"));
	rid_to_stream = ht_alloc(HT_VALUE_DEFAULT, 0);
	server_addr.sin_port = htons(voice_port);
	if (net_conn(NULL, &rtp_ops, (struct sockaddr *)&server_addr,
	             sizeof server_addr, CONN_STREAM | CONN_LISTEN) == ULONG_MAX) {
		ERROR(("rtp service: Failed to listen on %u", voice_port));
		return;
	}

	while (!got_sig) {
		service_recv(THIS_SERVICE);
		if (net_poll(NET_POLL_R, FRAME_TIME))
			return;

		/* Prepare packets for transmission */
		for (i = 0; i < n_streams; i++) {
			if (!streams[i]->contributor)
				continue;

			streams[i]->outsz   = 4 + RTP_HEADERSZ +
			                      streams[i]->codec->frame_size * FRAMES_PKT;
			streams[i]->out[0]  = (streams[i]->outsz >> 24) & 0xff;
			streams[i]->out[1]  = (streams[i]->outsz >> 16) & 0xff;
			streams[i]->out[2]  = (streams[i]->outsz >> 8)  & 0xff;
			streams[i]->out[3]  = streams[i]->outsz & 0xff;
			streams[i]->out[4]  = 0x80;
			streams[i]->out[6]  = (++streams[i]->seq_out >> 8) & 0xff;
			streams[i]->out[7]  = streams[i]->seq_out & 0xff;
			streams[i]->out[8]  = (streams[i]->ts >> 24) & 0xff;
			streams[i]->out[9]  = (streams[i]->ts >> 16) & 0xff;
			streams[i]->out[10] = (streams[i]->ts >> 8)  & 0xff;
			streams[i]->out[11] = streams[i]->ts & 0xff;
			streams[i]->ts     += streams[i]->codec->spkt;

			/**
			 * Since the client (sadly) doesn't take advantage of csrc or
			 * ssrc in the RTP header, it expectes a the sender's (singular)
			 * uid at the end of the packet, as the last four bytes;
			 * little-endian.
			 *
			 * In 9.1, it groks the headers but only to correctly find the
			 * start of the audio data, and the uid at the end; in spite
			 * of the 'channels' room parameter.
			 */
			streams[i]->out[4 + streams[i]->outsz - 1] = (streams[i]->contributor >> 24) & 0xff;
			streams[i]->out[4 + streams[i]->outsz - 2] = (streams[i]->contributor >> 16) & 0xff;
			streams[i]->out[4 + streams[i]->outsz - 3] = (streams[i]->contributor >> 8)  & 0xff;
			streams[i]->out[4 + streams[i]->outsz - 4] = streams[i]->contributor & 0xff;

			for (j = 0; j < FRAMES_PKT; j++) {
				streams[i]->codec->ops->encode(
					streams[i]->codec,
					streams[i]->buf + j * streams[i]->codec->spf,
					streams[i]->out + 16 + j * streams[i]->codec->frame_size
				);
			}
		}

		if (net_poll(NET_POLL_W, FRAME_TIME))
			return;

		/* Clear the buffer for the next round */
		for (i = 0; i < n_streams; i++) {
			streams[i]->contributor = 0;
			if (!streams[i]->codec)
				continue;
			memset(streams[i]->buf, 0, streams[i]->codec->spkt * 2);
		}
	}
}

/**
 * Send a message to the RTP service
 *
 * \param msg      Message number
 * \param rid      Room ID
 * \param uid      User ID
 * \param data     Additional data
 * \param date_len Length of \a data
 */
void rtpctl(unsigned char msg, unsigned long rid, unsigned long uid,
            char *data, size_t data_len)
{
	char *buf;

	data_len += 9;
	if (!(buf = malloc(4 + data_len)))
		abort();

	buf[0] = (data_len >> 24) & 0xff;
	buf[1] = (data_len >> 16) & 0xff;
	buf[2] = (data_len >> 8)  & 0xff;
	buf[3] = data_len & 0xff;
	buf[4] = msg;
	buf[5] = (rid >> 24) & 0xff;
	buf[6] = (rid >> 16) & 0xff;
	buf[7] = (rid >> 8)  & 0xff;
	buf[8] = rid & 0xff;
	buf[9] = (uid >> 24) & 0xff;
	buf[10] = (uid >> 16) & 0xff;
	buf[11] = (uid >> 8)  & 0xff;
	buf[12] = uid & 0xff;
	memcpy(buf + 13, data, data_len - 9);

	service_send(rtp_service, buf, 4);
	service_send(rtp_service, buf + 4, data_len);
	free(buf);
}

/**
 * Read messages from the parent process sent via rtpctl()
 */
static void rtp_child_read(int fd)
{
	char buf[32], *data = NULL, cmd, *codec;
	unsigned channels;
	unsigned long len, rid, uid;
	struct rtp_ctx *c;
	struct rtp_stream *stream;

	while (recv(fd, buf, 4, MSG_PEEK) == 4) {
		c = NULL;
		stream = NULL;
		recv(fd, buf, 4, 0);

		if (!(len = (buf[0] << 24) | (buf[1]  << 16) | (buf[2]  << 8) | buf[3]))
			goto next;

		if (!(data = calloc(1, len)))
			abort();
		recv(fd, data, len, 0);

		cmd = data[0];
		rid = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
		uid = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];

		sprintf(buf, "%lu", rid);
		stream = ht_get_ptr_nc(rid_to_stream, buf);
		if (cmd != RTP_JOIN && !stream)
			goto next;

		sprintf(buf, "%lu", uid);
		if (stream)
			c = ht_get_ptr_nc(stream->uid_to_listener, buf);

		switch (cmd) {
		case RTP_JOIN: /* User joined */
			if (!stream && data && len > 9) {
				codec    = strchr(data + 9, '\n') + 1;
				channels = strtoul(data + 9, NULL, 10);
				switch (*codec) {
				case 'g':
					stream = new_stream(rid, channels, &gsm_factory);
					break;
				default:
					ERROR(("rtp: join: unknown codec: %.*s", len - (codec - data), codec));
					goto next;
				}
			}

			if (!stream) {
				ERROR(("rtp: join: failed to create stream"));
				break;
			}

			/* Add an entry to the hash so we know it should be there */
			if (!c) {
				sprintf(buf, "%lu", uid);
				ht_set(stream->uid_to_listener, buf, HT_PTR, NULL);
			}

			break;
		case RTP_PART: /* User parted */
			if (c) {
				c->parted++;
				net_close(c->conn);
			}

			if (!stream->listeners)
				free_stream(stream);
			break;
		case RTP_CLOSED: /* Room closed */
			free_stream(stream);
			break;
		case RTP_RED:   /* User reddotted */
		case RTP_UNRED: /* User unreddoted */
			if (c) c->mute = cmd == RTP_RED;
			break;
		case RTP_USER_MUTE:
		case RTP_USER_UNMUTE:
			if (c) c->user_mute = cmd == RTP_USER_MUTE;
			break;
		}

next:
		if (len) {
			free(data);
			data   = NULL;
		}
	}
}

/**
 * Read messages from the child process signalling disconnections
 */
static void rtp_parent_read(int fd)
{
	char buf[32];
	unsigned long rid, uid;
	struct pt_context *target;

	while (recv(fd, buf, 8, MSG_PEEK) == 8) {
		recv(fd, buf, 8, 0);
		rid = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
		uid = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];

		sprintf(buf, "%lu", uid);
		if (!(target = ht_get_ptr_nc(uid_to_context, buf)))
			continue;

		if (!user_in_room(rid, uid))
			continue;

		/* There's a chance we might not have seen the part packet yet... */
		buf[0] = (rid >> 24) & 0xff;
		buf[1] = (rid >> 16) & 0xff;
		buf[2] = (rid >> 8)  & 0xff;
		buf[3] = rid & 0xff;
		buf[4] = 0;
		buf[5] = 0;
		buf[6] = (voice_port >> 8) & 0xff;
		buf[7] = voice_port & 0xff;
		send_packet(target, new_packet(PACKET_TCP_VOICE_RECON, 8, buf, PACKET_F_COPY));
	}
}

static void rtp_service_stop(void)
{
	INFO(("RTP service shutting down..."));
	got_sig++;
	ht_free(rid_to_stream);
}

struct service_ops rtp_service_ops = {
	rtp_service_start,
	rtp_parent_read,
	rtp_child_read,
	rtp_service_stop
};

