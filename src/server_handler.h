/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef SERVER_HANDLER_H

#include "packet.h"
#include "server.h"

/**
 * Send a return code packet back to the client.
 *
 * This is used to inform the client of the status of certain requests,
 * optionally containing an error message beyond the first four bytes of
 * the data; acting as a generic error signaling mechanism.
 */
void send_return_code(struct pt_context *ctx, unsigned short code, const char *msg, size_t msglen);

/**
 * Kick a client, with an optional reason message.
 */
void kick(struct pt_context *ctx, const char *msg, size_t len);

/**
 * Enact a Client Control ban
 * \param level Ban level (>= 1)
 */
void ccban(struct pt_context *ctx, unsigned long level);

/**
 * Repeal a Client Control ban
 */
void ccunban(struct pt_context *ctx);

/**
 * Transition to another packet flow, sending a transitionary packet
 * if needed.
 */
void transition_to(struct pt_context *ctx, void (*)(struct pt_context *));

/**
 * Transition to the previous packet flow
 */
void transition_fro(struct pt_context *ctx);

/**
 * Packet flow transitions
 */
void general_transition(struct pt_context *ctx);
void login_transition(struct pt_context *ctx);
void password_reset_transition(struct pt_context *ctx);
void registration_transition(struct pt_context *ctx);

/**
 * Server packet flows
 */
void general_flow(struct pt_context *ctx);
void login_flow(struct pt_context *ctx);
void password_reset_flow(struct pt_context *ctx);
void registration_flow(struct pt_context *ctx);

#endif /* SERVER_HANDLER_H */
