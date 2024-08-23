#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "logging.h"
#include "packet.h"
#include "protocol.h"
#include "hash.h"
#include "server_handler.h"

/* from server.c */
extern struct ht *uid_to_context;

// https://web.archive.org/web/20050501000000*/http://download.paltalk.com:80/download/0.x/pal_install.exe

/**
 * Send a return code packet back to the client.
 *
 * This is used to inform the client of the status of certain requests,
 * optionally containing an error message beyond the first four bytes of
 * the data; acting as a generic error signaling mechanism.
 */
void send_return_code(struct pt_context *ctx, unsigned short code, const char *msg, size_t msglen)
{
	char *buf;

	if (msg && !msglen)
		msglen = strlen(msg);

	if (!(buf = malloc(msglen + 4)))
		abort();

	buf[0] = (char)((ctx->pkt_in.type >> 8) & 0xff);
	buf[1] = (char)(ctx->pkt_in.type & 0xff);
	buf[2] = (char)((code >> 8) & 0xff);
	buf[3] = (char)(code & 0xff);
	if (msg && msglen)
		memcpy(buf + 4, msg, msglen);

	send_packet(ctx, new_packet(PACKET_RETURN_CODE, msglen + 4, buf, 0));
}

/**
 * Kick a client, with an optional reason message.
 */
void kick(struct pt_context *ctx, const char *msg, size_t len)
{
	if (!ctx || ctx->fd < 0) return;
	ctx->on_packet = NULL;
	shutdown(ctx->fd, SHUT_RD);
	send_packet(ctx, new_packet(PACKET_SERVER_DISCONNECT, len, msg, PACKET_F_COPY));
}

/**
 * Enact a Client Control ban
 * \param level Ban level (>= 1)
 */
void ccban(struct pt_context *ctx, unsigned long level)
{
	if (!ctx || ctx->fd < 0) return;
	DEBUG(("[CC] Setting ban level for %s to %lu", ctx->uid_str, level));
	level = htonl(level);
	send_packet(ctx, new_packet(PACKET_CLIENT_CONTROL, 4, (const void *)&level, PACKET_F_STATIC));
}

/**
 * Repeal a Client Control ban
 */
void ccunban(struct pt_context *ctx)
{
	DEBUG(("[CC] Unbanning %s", ctx->uid_str));
	ccban(ctx, 0);
}

/**
 * Transition to another packet flow, sending a transitionary packet
 * if needed.
 */
void transition_to(struct pt_context *ctx, void (*flow)(struct pt_context *))
{
	ctx->prev_on_packet = ctx->on_packet;
	ctx->on_packet      = flow;

	if (flow == login_flow)          login_transition(ctx);
	if (flow == password_reset_flow) password_reset_transition(ctx);
	if (flow == registration_flow)   registration_transition(ctx);
	if (flow == general_flow)        general_transition(ctx);
}

/**
 * Transition to the previous packet flow
 */
void transition_fro(struct pt_context *ctx)
{
	if (!ctx->prev_on_packet)
		return;

	ctx->on_packet = ctx->prev_on_packet;
	ctx->prev_on_packet = NULL;
}

