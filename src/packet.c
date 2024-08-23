/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "logging.h"
#include "packet.h"
#include "protocol.h"

void pt_context_init(struct pt_context *ctx, int fd)
{
	assert(ctx && fd >= 0);
	memset(ctx, 0, sizeof *ctx);
	if (!(ctx->hdr_in.msg_iov  = calloc(3, sizeof *ctx->hdr_in.msg_iov)) ||
	    !(ctx->data_in.msg_iov = calloc(1, sizeof *ctx->data_in.msg_iov)))
		abort();

	ctx->hdr_in.msg_iov[0].iov_base = &ctx->pkt_in.type;
	ctx->hdr_in.msg_iov[1].iov_base = &ctx->pkt_in.version;
	ctx->hdr_in.msg_iov[2].iov_base = &ctx->pkt_in.length;
	ctx->hdr_in.msg_iov[0].iov_len  = 2;
	ctx->hdr_in.msg_iov[1].iov_len  = 2;
	ctx->hdr_in.msg_iov[2].iov_len  = 2;
	ctx->hdr_in.msg_iovlen          = 3;
	ctx->data_in.msg_iovlen         = 1;
	ctx->fd                         = fd;
	ctx->uid                        = -1;
	ctx->challenge                  = 1 + (rand() % CHALLENGE_MAX);
}

void pt_context_destroy(struct pt_context *ctx)
{
	size_t i;

	assert(ctx);
	if (ctx->device_id)
		free(ctx->device_id);

	free(ctx->hdr_in.msg_iov);
	free(ctx->data_in.msg_iov);

	/* Deref any unsent packets */
	for (i = 0; i < ctx->npkts_out; i++) {
		if (!--ctx->pkts_out[i]->refcnt)
			free(ctx->pkts_out[i]);
	}

	free(ctx->pkts_out);
	free_user(&ctx->user);
}

void packet_in(struct pt_context *ctx)
{
	ssize_t br;

	assert(ctx);
	if (ctx->data_in.msg_iov[0].iov_len) {
		/* Read data */
		if ((br = recvmsg(ctx->fd, &ctx->data_in, 0)) < 0)
			return;

		if (!br) {
			ctx->disconnect++;
			return;
		}

		ctx->data_in.msg_iov[0].iov_len  -= (size_t)br;
		ctx->data_in.msg_iov[0].iov_base  = (char *)ctx->data_in.msg_iov[0].iov_base + (size_t)br;
		if (ctx->data_in.msg_iov[0].iov_len)
			return;
	} else {
		br = recvmsg(ctx->fd, &ctx->hdr_in, MSG_PEEK);
		if (br && br < 6)
			return;

		if (!br) {
			ctx->disconnect++;
			return;
		}

		(void)recvmsg(ctx->fd, &ctx->hdr_in, 0);
		ctx->pkt_in.type    = ntohs(ctx->pkt_in.type);
		ctx->pkt_in.version = ntohs(ctx->pkt_in.version);
		ctx->pkt_in.length  = ntohs(ctx->pkt_in.length);

		if (ctx->pkt_in.length) {
			if (!(ctx->pkt_in.data = calloc(ctx->pkt_in.length + 1, 1)))
				abort();

			ctx->data_in.msg_iov[0].iov_base = ctx->pkt_in.data;
			ctx->data_in.msg_iov[0].iov_len  = ctx->pkt_in.length;
			return;
		}
	}

#ifndef NDEBUG
	dump_packet(0, &ctx->pkt_in);
#endif

	if (ctx->pkt_in.type == PACKET_CLIENT_DISCONNECT)
		ctx->disconnect++;
	else if (ctx->on_packet)
		ctx->on_packet(ctx);

	if (ctx->pkt_in.length) {
		memset(ctx->pkt_in.data, 0, ctx->pkt_in.length);
		free(ctx->pkt_in.data);
		ctx->pkt_in.data = NULL;
	}

	ctx->data_in.msg_iov[0].iov_base = NULL;
	ctx->data_in.msg_iov[0].iov_len  = 0;
}

void packet_out(struct pt_context *ctx)
{
	ssize_t bs, bp;
	size_t i, freed;

	assert(ctx);
	if (!ctx->pkt_out.msg_iovlen || (bp = bs = sendmsg(ctx->fd, &ctx->pkt_out, 0)) <= 0)
		return;

	/* Update our vector list */
	for (i = 0, freed = 0; bs && i < ctx->pkt_out.msg_iovlen; i++) {
		if (ctx->pkt_out.msg_iov[i].iov_len <= (size_t)bs) {
			bs -= ctx->pkt_out.msg_iov[i].iov_len;
			++freed;
			continue;
		}

		ctx->pkt_out.msg_iov[i].iov_len  -= (size_t)bs;
		ctx->pkt_out.msg_iov[i].iov_base  = (char *)ctx->pkt_out.msg_iov[i].iov_base + (size_t)bs;
		break;
	}

	ctx->pkt_out.msg_iovlen -= freed;
	if (ctx->pkt_out.msg_iovlen) {
		memmove(ctx->pkt_out.msg_iov, ctx->pkt_out.msg_iov + freed, ctx->pkt_out.msg_iovlen * sizeof *ctx->pkt_out.msg_iov);
		ctx->pkt_out.msg_iov = realloc(ctx->pkt_out.msg_iov,        ctx->pkt_out.msg_iovlen * sizeof *ctx->pkt_out.msg_iov);
	} else {
		free(ctx->pkt_out.msg_iov);
		ctx->pkt_out.msg_iov = NULL;
	}

	/* Deref underlying packets */
	i = 0;
	do {
		if (ctx->pkts_out[i]->remaining >= (size_t)bp) {
			ctx->pkts_out[i]->remaining -= (size_t)bp;
			bp = 0;
		} else bp -= ctx->pkts_out[i]->remaining;

		if (!--ctx->pkts_out[i]->refcnt)
			free_packet(ctx->pkts_out[i]);
	} while (bp && ++i < ctx->npkts_out);

	if (!(ctx->npkts_out -= i + 1)) {
		free(ctx->pkts_out);
		ctx->pkts_out = NULL;
	} else {
		memmove(ctx->pkts_out, ctx->pkts_out + i + 1,
		       (ctx->npkts_out - i + 1) * sizeof(struct pt_packet *));
	}

	/* If this client was kicked, and we've drained pkt_out, disconnect */
	if (!ctx->on_packet && !ctx->pkts_out)
		ctx->disconnect++;
}

struct pt_packet *new_packet(unsigned short type, unsigned short len, const char *data, unsigned flags)
{
	struct pt_packet *ret;

	len = data ? len : 0;
	if (!(ret = calloc(1, sizeof *ret)))
		return NULL;

	if ((flags & PACKET_F_COPY) && len) {
		if (!(ret->data = calloc(1, len))) {
			free(ret);
			return NULL;
		}

		memcpy(ret->data, data, len);
	} else {
		/**
		 * For PACKET_F_STATIC, and cases where the data's already on
		 * the heap, we can safely discard const here. In the STATIC case,
		 * we don't modify ret->data, and in the default case, the data
		 * should be modifiable.
		 */
		ret->data = (char *)*(void **)&data;
	}

	ret->flags   = flags;
	ret->type    = type;
	ret->version = PROTOCOL_VERSION;
	ret->length  = len;
	return ret;
}

void send_packet(struct pt_context *ctx, struct pt_packet *pkt)
{
	size_t pos, newlen;

	assert(ctx);
	pos    = ctx->pkt_out.msg_iovlen;
	newlen = (pos + (pkt->length ? 4 : 3)) * sizeof(struct iovec);

	if (!pkt) {
		ERROR(("Cowardly refusing to send NULL packet"));
		return;
	}

#ifndef NDEBUG
	dump_packet(1, pkt);
#endif

	if (!(ctx->pkts_out = realloc(ctx->pkts_out, (ctx->npkts_out + 1) * sizeof(struct pt_packet *))) ||
	    !(ctx->pkt_out.msg_iov = realloc(ctx->pkt_out.msg_iov, newlen)))
		abort();

	memset(ctx->pkt_out.msg_iov + pos, 0, newlen - (pos * sizeof *ctx->pkt_out.msg_iov));
	ctx->pkts_out[ctx->npkts_out++]        = pkt;
	ctx->pkt_out.msg_iov[pos].iov_base     = &pkt->type;
	ctx->pkt_out.msg_iov[pos + 1].iov_base = &pkt->version;
	ctx->pkt_out.msg_iov[pos + 2].iov_base = &pkt->length;
	ctx->pkt_out.msg_iov[pos].iov_len      = 2;
	ctx->pkt_out.msg_iov[pos + 1].iov_len  = 2;
	ctx->pkt_out.msg_iov[pos + 2].iov_len  = 2;
	ctx->pkt_out.msg_iovlen += 3;

	if (pkt->length) {
		ctx->pkt_out.msg_iov[pos + 3].iov_base = pkt->data;
		ctx->pkt_out.msg_iov[pos + 3].iov_len  = pkt->length;
		ctx->pkt_out.msg_iovlen++;
		pkt->remaining = pkt->length;
		pkt->length = htons(pkt->length);
	}

	pkt->type      = htons(pkt->type);
	pkt->version   = htons(pkt->version);
	pkt->remaining += 6;
	pkt->refcnt++;
}

void free_packet(struct pt_packet *pkt)
{
	if (!pkt || pkt->refcnt)
		return;

	if (pkt->length && pkt->data && !(pkt->flags & PACKET_F_STATIC))
		free(pkt->data);
	free(pkt);
}

static const char *hex = "0123456789abcdef";

void dump_packet(int out, struct pt_packet *pkt)
{
	char hbuf[28], cbuf[9];
	unsigned hlen = 0, clen = 0;
	unsigned short i;

	if (!pkt) return;
	memset(hbuf, 0, 28);
	memset(cbuf, 0, 9);
	INFO(("Packet [%s]: type=%04x version=%04x length=%04x", out ? "out" : "in", pkt->type, pkt->version, pkt->length));

	for (i = 0; i < pkt->length; i++) {
		if (i && !(i & 7)) {
			hbuf[hlen] = 0;
			cbuf[clen] = 0;
			INFO(("%-24.24s%-8.8s", hbuf, cbuf));
			hlen = clen = 0;
		}

		hbuf[hlen++] = hex[(pkt->data[i] & 0xf0) >> 4];
		hbuf[hlen++] = hex[pkt->data[i] & 0x0f];
		hbuf[hlen++] = ' ';
		cbuf[clen++] = isprint(pkt->data[i]) ? pkt->data[i] : '.';
	}

	if (i && i == pkt->length) {
		hbuf[hlen] = 0;
		cbuf[clen] = 0;
		INFO(("%-24.24s%-8.8s", hbuf, cbuf));
	}
}

