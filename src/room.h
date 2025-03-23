/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef ROOM_H
#define ROOM_H

#include <stddef.h>

struct pt_context;

/**
 * Get the room counts by category
 */
char *room_counts_by_category(void *db_r);

/**
 * Get the list of rooms for the given category
 */
char *rooms_for_category(void *db_r, unsigned long protocol_version,
                         unsigned long catid);

/**
 * Get a list of rooms, subcategories and the number of rooms they contain
 */
char *rooms_and_subcategories_for_category(void *db_r, unsigned long catid);

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
 * Non-zero if the given user is the room owner
 */
int user_is_owner(void *db_w, unsigned long rid, unsigned long uid);

/**
 * Broadcast a packet to an entire room
 */
void broadcast_to_room(struct pt_context *ctx, unsigned long rid,
                       struct pt_packet *pkt);

/**
 * Broadcast a packet to non-admins in a room
 */
void broadcast_to_non_admins(struct pt_context *ctx, unsigned long rid,
                             struct pt_packet *pkt);

/**
 * Broadcast a packet to admins in a room
 */
void broadcast_to_admins(struct pt_context *ctx, unsigned long rid,
                         struct pt_packet *pkt);

/**
 * Broadcast a packet to users in a room at or above a specific
 * protocol version
 */
void broadcast_at_or_above(struct pt_context *ctx, unsigned long rid,
                           struct pt_packet *pkt, unsigned version);

/**
 * Broadcast a packet to users in a room who are at or below a specific
 * protocol version
 */
void broadcast_at_or_below(struct pt_context *ctx, unsigned long rid,
                           struct pt_packet *pkt, unsigned version);

/**
 * Broadcast a packet to users in a room who aren't ignoring the sender
 */
void broadcast_to_unignored(struct pt_context *ctx, unsigned long rid,
                            struct pt_packet *pkt);

/**
 * Returns non-zero if being ignored by the given user in the given room
 */
int room_user_ignores_me(struct pt_context *ctx, unsigned long rid,
                         unsigned long uid);

/**
 * Deliver a message to a room (or a specific user within a room)
 */
void send_room_message(struct pt_context *ctx, struct pt_context *target,
                       unsigned long rid, unsigned long from, size_t len,
                       const char *msg);

/**
 * Get "My Room" info
 */
char *get_my_room_info(void *db_w, unsigned long uid);

/**
 * Get the first room id matching \a name
 */
unsigned long name_to_room(void *db_w, const char *name);

/**
 * Search for a room by partial match on the room name
 */
char *search_rooms(void *db_w, unsigned protocol_version, const char *partial);

/**
 * Send a room invite to a buddy
 */
void room_invite(struct pt_context *ctx, unsigned long rid, unsigned long uid);

/**
 * Create a temporary room
 */
void create_room(struct pt_context *ctx, unsigned char type,
                 unsigned short catg, unsigned short subcatg,
                 char rating, const char *name, const char *passwd);

/**
 * Get the first room id owned by the given user
 */
unsigned long owners_room(void *db_r, unsigned long uid);

/**
 * Join a room
 */
void join(struct pt_context *ctx, unsigned long rid, unsigned long code,
          const char *passwd, unsigned invis);

/**
 * Depart from a room
 */
void part(struct pt_context *ctx, unsigned long rid);

/**
 * Depart from all rooms
 */
void part_all(struct pt_context *ctx);

/**
 * Close a room
 */
void close_room(struct pt_context *ctx, unsigned long rid, const char *msg);

/**
 * User has Muted/Unmuted the room
 */
void mute_room(struct pt_context *ctx, unsigned long rid, unsigned on);

/**
 * Ignore a user in a room
 */
void ignore(struct pt_context *ctx, unsigned long rid,
            unsigned long target, int on);

/**
 * Reddot/Unreddot a user in a room
 */
void reddot_user(struct pt_context *ctx, unsigned long rid,
                 unsigned long uid, int on);

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
 * Send a room's topic to the user
 */
void send_room_topic(struct pt_context *ctx, unsigned long rid);

/**
 * Set the room topic
 */
void room_topic(struct pt_context *ctx, unsigned long rid, const char *topic);

/**
 * Send a room's banner url to the user
 */
void send_room_banner_url(struct pt_context *ctx, unsigned long rid);

/**
 * Set a room's banner url
 */
void room_banner_url(struct pt_context *ctx, unsigned long rid,
                     const char *url);

/**
 * Grant/Revoke temporary admin privileges
 */
void room_admin(struct pt_context *ctx, unsigned long rid,
                unsigned long uid, int on);

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
void bounce_user(struct pt_context *ctx, unsigned long rid,
                 unsigned long uid, const char *reason);

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
void whisper(struct pt_context *ctx, unsigned long rid,
             const char *target, const char *msg);

/**
 * Evaluate a slash command
 *
 * \return non-zero if \a buf contained a valid command
 */
int room_command(struct pt_context *ctx, unsigned long rid, const char *buf);

#endif /* ROOM_H */
