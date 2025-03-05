/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef SERVER_H
#define SERVER_H

#include "packet.h"

/**
 * Absolute maximum number of client connections to the server
 */
#define MAX_CONNECTIONS 2048

/**
 * Send a packet to all connected users
 */
void broadcast(struct pt_packet *pkt);

#endif /* SERVER_H */
