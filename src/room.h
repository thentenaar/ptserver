/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef ROOM_H
#define ROOM_H

#include "packet.h"

/**
 * Get the room counts by category
 */
char *room_counts_by_category(void *db_r);

/**
 * Get the list of rooms for the given category
 */
char *rooms_for_category(void *db_r, unsigned long protocol_version, unsigned long catid);

/**
 * Get the list of rooms for the given category + subcategory
 */
char *rooms_for_subcategory(void *db_r, unsigned long catid, unsigned long scid);

/**
 * Non-zero if the given user is in the given room
 */
int user_in_room(void *db_w, unsigned long rid, unsigned long uid);

/**
 * Non-zero if the given user is invisble in the given room
 */
int user_is_invisible(void *db_w, unsigned long rid, unsigned long uid);

/**
 * Non-zero if the given user is a room admin and present in the room
 */
int user_is_room_admin(void *db_w, unsigned long rid, unsigned long uid);

/**
 * Broadcast a packet (i.e. PACKET_ROOM_MESSAGE_IN) to an entire room
 */
void broadcast_to_room(struct pt_context *ctx, unsigned long rid, struct pt_packet *pkt);

/**
 * Broadcast a packet (i.e. PACKET_ROOM_MESSAGE_IN) to non-admins in a room
 */
void broadcast_to_non_admins(struct pt_context *ctx, unsigned long rid, struct pt_packet *pkt);

/**
 * Search for a room by partial match on the room name
 */
char *search_rooms(void *db_w, unsigned protocol_version, const char *partial);

/**
 * Reddot/Unreddot a user in a room
 */
void reddot_user(struct pt_context *ctx, unsigned long rid, unsigned long uid, int on);

/**
 * Turn all mics on/off in a room
 */
void set_all_mics(struct pt_context *ctx, unsigned long rid, int on);

/**
 * Raise/Lower the user's hand
 */
void raise_hand(struct pt_context *ctx, unsigned long rid, int on);

/**
 * Lower all hands
 */
void lower_all_hands(struct pt_context *ctx, unsigned long rid);

/**
 * Set the room topic
 */
void room_topic(struct pt_context *ctx, unsigned long rid, const char *topic);

/**
 * Get the admin console info for a room
 */
char *get_admin_info(struct pt_context *ctx, unsigned long rid);

/**
 * Ban a user from a room
 */
void ban_user(struct pt_context *ctx, unsigned long rid, unsigned long uid);

/**
 * Unban a user from a room
 */
void unban_user(struct pt_context *ctx, unsigned long rid, unsigned long uid);

/**
 * Bounce a user from a room
 */
void bounce_user(struct pt_context *ctx, unsigned long rid, unsigned long uid, const char *reason);

/**
 * Unbounce a user from a room
 */
void unbounce_user(struct pt_context *ctx, unsigned long rid, unsigned long uid);

/**
 * Whether or not to give users mic privileges on join
 */
void new_user_mic(struct pt_context *ctx, unsigned long rid, int on);

/**
 * Reddot text for the entire room
 */
void reddot_text(struct pt_context *ctx, unsigned long rid, int on);

/**
 * Reddot video for the entire room
 */
void reddot_video(struct pt_context *ctx, unsigned long rid, int on);

/**
 * Whisper to a user in a room
 */
void whisper(struct pt_context *ctx, unsigned long rid, const char *target, const char *msg);

/**
 * Evaluate a slash command
 *
 * \return non-zero if \a buf contained a valid command
 */
int room_command(struct pt_context *ctx, unsigned long rid, const char *buf);

#endif /* ROOM_H */
