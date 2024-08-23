/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef SERVER_H
#define SERVER_H

#include "packet.h"

/**
 * Maximum number of client connections to the server
 */
#define MAX_CONNECTIONS 10240

/**
 * Send a packet to all connected users
 */
void broadcast(struct pt_packet *pkt);

#endif /* SERVER_H */
