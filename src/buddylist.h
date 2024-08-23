/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef BUDDYLIST_H
#define BUDDYLIST_H

#include "packet.h"

/**
 * Send the buddy or block list
 */
void send_buddy_list(struct pt_context *ctx, int blocked);

/**
 * Send our status to our buddies
 */
void broadcast_status(struct pt_context *ctx);

/**
 * Receive our buddies' statuses
 */
void buddy_statuses(struct pt_context *ctx);

/**
 * Set the display name for a buddy
 */
void set_buddy_display(struct pt_context *ctx, unsigned long uid, const char *disp);

/**
 * Add a buddy to \a ctx's buddylist
 */
void add_buddy(struct pt_context *ctx, unsigned long uid);

/**
 * Remove a buddy from \a ctx's buddylist
 */
void remove_buddy(struct pt_context *ctx, unsigned long uid);

/**
 * Add a buddy to \a ctx's blocklist
 */
void block_buddy(struct pt_context *ctx, unsigned long uid);

/**
 * Remove a buddy from \a ctx's blocklist
 */
void unblock_buddy(struct pt_context *ctx, unsigned long uid);

/**
 * Non-zero if \a ctx is on the given user's blocklist
 */
int user_blocked_me(struct pt_context *ctx, unsigned long uid);

/**
 * Non-zero if the given user is on \a ctx's blocklist
 */
int i_blocked_user(struct pt_context *ctx, unsigned long uid);

#endif /* BUDDYLIST_H */
