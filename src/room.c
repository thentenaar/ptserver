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

#include "database.h"
#include "protocol.h"
#include "packet.h"
#include "rtp.h"
#include "server_handler.h"
#include "hash.h"
#include "user.h"
#include "room.h"

/* from server.c */
extern void *db_w;
extern struct ht *uid_to_context;
extern unsigned short voice_port;

/* from user.c */
extern const char * const colors[];

/* Prepared queries on db_w */
static void *in_room;
static void *is_invis;
static void *is_admin;
static void *is_owner;
static void *my_room;
static void *room_by_name;
static void *search_room_queries[4];
static void *room_ignore[2];
static void *ignores_me;
static void *reddot_text_query;
static void *make_invite;
static void *make_room;
static void *get_owners_room;
static void *banned_query;
static void *join_query;
static void *join_room_users;
static void *set_mic;
static void *all_mics;
static void *set_away;
static void *set_hand;
static void *all_hands;
static void *set_topic;
static void *set_code;
static void *set_banner_url;
static void *set_admin;
static void *depart[3];
static void *do_close_room;
static void *do_ban;
static void *do_unban;
static void *do_bounce;
static void *do_unbounce;
static void *do_mic;
static void *do_text;
static void *do_video;

static const char * const empty_str = "";

#define CANT_IGNORE_ADMINS_LEN 24
#define CANT_IGNORE_SELF_LEN   38
#define WHISPER_SELF_LEN       52
#define SERVER_ERROR_LEN       12
#define INVALID_PASSWORD_LEN   16
#define CODE_RANGE_LEN         41
#define CODE_CHANGED_LEN       39
#define BANISHED_LEN           121

static const char * const cant_ignore_admins = "You cannot ignore admins";
static const char * const cant_ignore_self   = "You're free to ignore yourself unaided";
static const char * const whisper_self       = "Your whispering to yourself is beginning to worry me";
static const char * const server_error       = "Server error";
static const char * const invalid_password   = "Invalid password";
static const char * const code_range         = "The admin code must be between 1 and 9999";
static const char * const code_changed       = "The admin code was changed successfully";
static const char * const banished =
"You have been banished from this realm, nevermore to return, save for "
"the tender mercies and grace of the room admin(s)...";

static const char * const room_cmds[2] =
{
"The following slash commands are valid in this room:\n"
"\t/[i]gnore user [on]|off  - Ignore or unignore a user in a room\n"
"\t/[w]hisper user: message - Whisper to a user\n",

"The following slash commands are valid in this room:\n"
"\t/[c]ode 4-digits         - Change the room's admin code\n"
"\t/[i]gnore user [on]|off  - Ignore or unignore a user in a room\n"
"\t/[o]p [user] [on]|off    - Grant/Revoke temporary admin permission\n"
"\t/[t]opic string          - Set the room topic\n"
"\t/[w]hisper user: message - Whisper to a user\n"
};

static const char * const rooms_fmt[7] = {
	"FROM rooms WHERE p=0 AND catg=%ld ORDER BY '#' DESC, nm ASC",
	"FROM rooms WHERE p=0 ORDER BY '#' DESC, nm ASC LIMIT 5",
	"FROM rooms WHERE p=0 ORDER BY created DESC, nm ASC LIMIT 5",

	"SELECT id,r,p,v,l,c,nm,"
	"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS '#' ",

	/* PT 8.2+: New room list packet (category) */
	"SELECT 'G' AS t,id,nm AS n,r,p,v,l,c,lang,"
	"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS m "
	"FROM rooms WHERE p=0 AND catg=%ld AND subcatg IS NULL "
	"ORDER BY m DESC, n ASC",

	/* PT 8.2+: New room list packet (subcategory) */
	"SELECT 'G' AS t,id,nm AS n,r,p,v,l,c,lang,"
	"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS m "
	"FROM rooms WHERE p=0 AND catg=%ld AND subcatg=%ld "
	"ORDER BY m DESC, n ASC",

	/* PT 9+: Subcategories for category */
	"SELECT 'S' AS t, subcatg AS sc, COUNT(*) AS nm "
	"FROM rooms WHERE p=0 AND catg=%ld AND subcatg IS NOT NULL "
	"GROUP BY sc ORDER BY sc DESC"
};

/**
 * Admins can see all users in a room, even if they join as invisible
 */
static const char * const room_user_fmt[] = {
	"SELECT id AS group_id, room_users.uid AS uid, req, mic, pub, away, "
	"room_users.admin AS admin, room_users.host AS host, nickname, "
	"first, last, color "
	"FROM room_users JOIN users ON users.uid=room_users.uid "
	"WHERE room_users.id=%lu AND room_users.uid=%lu",

	"SELECT id AS group_id, room_users.uid AS uid, req, mic, pub, away, "
	"room_users.admin AS admin, room_users.host AS host, nickname, "
	"first, last, color "
	"FROM room_users JOIN users ON users.uid=room_users.uid "
	"WHERE room_users.id=%lu AND (room_users.invis=0 OR room_users.uid=%lu)",

	"SELECT id AS group_id, room_users.uid AS uid, req, mic, pub, away, "
	"room_users.admin AS admin, room_users.host AS host, nickname, "
	"first, last, color "
	"FROM room_users JOIN users ON users.uid=room_users.uid "
	"WHERE room_users.id=%lu AND room_users.uid=%lu",

	"SELECT id AS group_id, room_users.uid AS uid, req, mic, pub, away, "
	"room_users.admin AS admin, room_users.host AS host, nickname, "
	"first, last, color "
	"FROM room_users JOIN users ON users.uid=room_users.uid "
	"WHERE room_users.id=%lu",
};

/**
 * Canned room rating messages
 */
static const char * const rating_msg[4] = {
	"",
	"This is an A rated room not intended for minors and may contain "
	"offsensive language and nudity.",
	"This is an R rated room not intended for minors and may contain "
	"offsensive language.",
	"This is a G rated room intended for a General Audience including "
	"minors.  Offensive language is not permitted.",
};

/**
 * host=0|1    - [PT 5] ???
 * mic=0|1     - 1 mic icon, 0 muted mic
 * req=0|1     - 1 hand icon, 0 no hand icon
 * pub=Y|N     - Y video icon, N no video icon
 * admin=0|1   - 1 if admin
 * display=str - displayname
 * away=0|1    - [PT 7/8] 1 muted speaker icon, 0 no muted speaker icon (PACKET_ROOM_MUTE)
 * top=int     - [PT 8]  ???
 */
static char *get_room_user_info(struct pt_context *ctx, unsigned long rid,
                                unsigned long uid)
{
	char buf[512], *s = NULL;

	sprintf(buf,
	        room_user_fmt[(uid == UID_ALL) | (user_is_room_admin(rid, ctx->uid) << 1)],
	        rid, (uid == UID_ALL) ? ctx->uid : uid);
	db_exec(db_w, &s, buf, db_row_to_record);
	return s;
}

/**
 * Get the room counts by category
 */
char *room_counts_by_category(void *db_w)
{
	char buf[384], *s = NULL;

	sprintf(buf, /* The two virtual categories will have up to 5 entries */
			"SELECT %d AS id, (SELECT MIN(5, COUNT(DISTINCT id)) FROM rooms WHERE p=0) AS '#' UNION "
			"SELECT %d AS id, (SELECT MIN(5, COUNT(DISTINCT id)) FROM rooms WHERE p=0) AS '#' UNION "
			"SELECT catg AS id, COUNT(*) AS '#' FROM rooms WHERE p=0 AND catg NOT IN (%d,%d) GROUP BY catg",
			CATEGORY_TOP, CATEGORY_FEATURED, CATEGORY_TOP, CATEGORY_FEATURED);

	if (!db_exec(db_w, &s, buf, db_row_to_record) && s)
		return s;

	free(s);
	return NULL;
}

/**
 * Get the list of rooms for the given category
 */
char *rooms_for_category(void *db_r, unsigned long protocol_version,
                         unsigned long catid)
{
	char buf[256], *s = NULL;
	unsigned idx = ((catid == CATEGORY_FEATURED) << 1) | (catid == CATEGORY_TOP);

	if (protocol_version >= PROTOCOL_VERSION_82 && !idx) {
		sprintf(buf, rooms_fmt[4], catid);
	} else {
		memcpy(buf, rooms_fmt[3], strlen(rooms_fmt[3]) + 1);
		sprintf(buf + strlen(buf), rooms_fmt[idx], catid);
	}

	if (db_exec(db_r, &s, buf, db_row_to_record)) {
		free(s);
		return NULL;
	}

	sprintf(buf, "catg=%ld\n", catid);
	s = prepend_record(s, buf);
	return s;
}

/**
 * Get a list of rooms, subcategories and the number of rooms they contain
 */
char *rooms_and_subcategories_for_category(void *db_w, unsigned long catid)
{
	char buf[256], *s = NULL;

	sprintf(buf, rooms_fmt[6], catid);
	if (db_exec(db_w, &s, buf, db_row_to_record)) {
		free(s);
		return NULL;
	}

	sprintf(buf, rooms_fmt[4], catid);
	if (db_exec(db_w, &s, buf, db_row_to_record)) {
		free(s);
		return NULL;
	}

	sprintf(buf, "catg=%ld\n", catid);
	s = prepend_record(s, buf);
	return s;
}

/**
 * Get the list of rooms for the given category + subcategory
 */
char *rooms_for_subcategory(void *db_w, unsigned long catid, unsigned long scid)
{
	char buf[256], *s = NULL;

	sprintf(buf, rooms_fmt[5], catid, scid);
	if (db_exec(db_w, &s, buf, db_row_to_record)) {
		free(s);
		return NULL;
	}

	sprintf(buf, "catg=%ld\nsubcatg=%ld\n", catid, scid);
	if ((s = prepend_record(s, buf))) {
		s[strlen(s)] = '\0';
		return append_record(s, "eof=Y\n");
	}

	return s;
}

static int broadcast_to_room_cb(void *userdata, int cols, char *val[], char *col[])
{
	struct pt_context *ctx;
	struct pt_packet *pkt = userdata;
	(void)col;

	if (!userdata || cols != 1)
		return 0;

	if (!(ctx = ht_get_ptr_nc(uid_to_context, val[0])))
		return 0;

	/* Added in 8.x, 9.0 removed this option from the room */
	if (pkt->type == PACKET_NUDGE_IN && ctx->protocol_version != PROTOCOL_VERSION_82)
		return 0;

	send_packet(ctx, pkt);
	return 0;
}

/**
 * Non-zero if the given user is in the given room
 */
int user_in_room(unsigned long rid, unsigned long uid)
{
	if (!in_room) {
		in_room = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM room_users WHERE id=? AND uid=?"
		);
	}

	if (!in_room)
		return 0;

	db_reset_prepared(in_room);
	db_bind(in_room, "ii", rid, uid);
	return !!db_get_count(in_room);
}

/**
 * Non-zero if the given user is invisble in the given room
 */
int user_is_invisible(unsigned long rid, unsigned long uid)
{
	if (!is_invis) {
		is_invis = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM room_users WHERE id=? AND uid=? AND invis=1"
		);
	}

	if (!is_invis)
		return 0;

	db_reset_prepared(is_invis);
	db_bind(is_invis, "ii", rid, uid);
	return !!db_get_count(is_invis);
}

/**
 * Non-zero if the given user is the room owner
 */
int user_is_owner(unsigned long rid, unsigned long uid)
{
	if (!is_owner) {
		is_owner = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM rooms WHERE id=? AND owner=?"
		);
	}

	if (!is_owner)
		return 0;

	db_reset_prepared(is_owner);
	db_bind(is_owner, "ii", rid, uid);
	return !!db_get_count(is_owner);
}

/**
 * Non-zero if the given user is a room admin and present in the room
 */
int user_is_room_admin(unsigned long rid, unsigned long uid)
{
	if (!is_admin) {
		is_admin = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM room_users WHERE id=? AND uid=? AND admin=1"
		);
	}

	if (!is_admin)
		return 0;
	db_reset_prepared(is_admin);
	db_bind(is_admin, "ii", rid, uid);
	return !!db_get_count(is_admin);
}

/**
 * Broadcast a packet to an entire room
 */
void broadcast_to_room(struct pt_context *ctx, unsigned long rid,
                       struct pt_packet *pkt)
{
	char buf[64];

	if (!pkt || !user_in_room(rid, ctx->uid)) {
		free_packet(pkt);
		return;
	}

	sprintf(buf, "SELECT uid FROM room_users WHERE id=%lu AND uid<>%lu", rid, ctx->uid);
	db_exec(db_w, pkt, buf, broadcast_to_room_cb);
	if (!pkt->refcnt) free_packet(pkt);
}

/**
 * Broadcast a packet to admins in a room
 */
void broadcast_to_admins(struct pt_context *ctx, unsigned long rid,
                         struct pt_packet *pkt)
{
	char buf[128];

	if (!user_in_room(rid, ctx->uid))
		goto ret;

	sprintf(buf, "SELECT uid FROM room_users WHERE id=%lu AND uid<>%lu AND admin=1", rid, ctx->uid);
	db_exec(db_w, pkt, buf, broadcast_to_room_cb);

ret:
	if (!pkt->refcnt) free_packet(pkt);
}

/**
 * Broadcast a packet to non-admins in a room
 */
void broadcast_to_non_admins(struct pt_context *ctx, unsigned long rid,
                             struct pt_packet *pkt)
{
	char buf[128];

	if (!user_in_room(rid, ctx->uid))
		goto ret;

	sprintf(buf, "SELECT uid FROM room_users WHERE id=%lu AND uid<>%lu AND admin=0", rid, ctx->uid);
	db_exec(db_w, pkt, buf, broadcast_to_room_cb);

ret:
	if (!pkt->refcnt) free_packet(pkt);
}

/**
 * Broadcast a packet to users in a room who are at or above a specific
 * protocol version
 */
void broadcast_at_or_above(struct pt_context *ctx, unsigned long rid,
                           struct pt_packet *pkt, unsigned version)
{
	char buf[128];

	if (!user_in_room(rid, ctx->uid))
		goto ret;

	sprintf(buf,
	        "SELECT uid FROM room_users WHERE id=%lu AND uid<>%lu AND pv>=%u",
	        rid, ctx->uid, version);
	db_exec(db_w, pkt, buf, broadcast_to_room_cb);

ret:
	if (!pkt->refcnt) free_packet(pkt);
}

/**
 * Broadcast a packet to users in a room who are at or below a specific
 * protocol version
 */
void broadcast_at_or_below(struct pt_context *ctx, unsigned long rid,
                           struct pt_packet *pkt, unsigned version)
{
	char buf[128];

	if (!user_in_room(rid, ctx->uid))
		goto ret;

	sprintf(buf,
	        "SELECT uid FROM room_users WHERE id=%lu AND uid<>%lu AND pv<%u",
	        rid, ctx->uid, version);
	db_exec(db_w, pkt, buf, broadcast_to_room_cb);

ret:
	if (!pkt->refcnt) free_packet(pkt);
}


/**
 * Broadcast a packet to users in a room who aren't ignoring the sender
 */
void broadcast_to_unignored(struct pt_context *ctx, unsigned long rid,
                            struct pt_packet *pkt)
{
	char buf[128];

	if (!user_in_room(rid, ctx->uid))
		goto ret;

	sprintf(buf, "SELECT uid FROM room_users WHERE id=%lu AND uid<>%lu "
	             "EXCEPT SELECT uid FROM room_ignore WHERE id=%lu AND "
	             "target=%lu", rid, ctx->uid, rid, ctx->uid);
	db_exec(db_w, pkt, buf, broadcast_to_room_cb);

ret:
	if (!pkt->refcnt) free_packet(pkt);
}

/**
 * Returns non-zero if being ignored by the given user in the given room
 */
int room_user_ignores_me(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	if (!ignores_me) {
		reddot_text_query = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM room_ignore WHERE id=? AND uid=? AND target=?"
		);
	}

	if (!ignores_me)
		return 0;

	db_reset_prepared(ignores_me);
	db_bind(ignores_me, "iii", rid, uid, ctx->uid);
	return !!db_get_int(ignores_me);
}

/**
 * Deliver a message to a room (or a specific user within a room)
 */
void send_room_message(struct pt_context *ctx, struct pt_context *target,
                       unsigned long rid, unsigned long from, size_t len,
                       const char *msg)
{
	int admin;
	char *buf;
	struct pt_packet *pkt;

	if (!reddot_text_query) {
		reddot_text_query = db_prepare(
			db_w,
			"SELECT text FROM rooms WHERE id=?"
		);
	}

	if (!msg || !len || !reddot_text_query)
		return;

	db_reset_prepared(reddot_text_query);
	db_bind(reddot_text_query, "i", rid);

	/**
	 * If text is reddotted at the room level, ignore any messages from
	 * non-admins
	 */
	admin = from && (from == UID_PALTALK_NOTIFIER || user_is_room_admin(rid, from));
	if (from && !admin && !db_get_int(reddot_text_query))
		return;

	if (!(buf = malloc(len + 8)))
		abort();

	buf[0]  = (rid >> 24) & 0xff;
	buf[1]  = (rid >> 16) & 0xff;
	buf[2]  = (rid >> 8)  & 0xff;
	buf[3]  = rid & 0xff;
	buf[4]  = (from >> 24) & 0xff;
	buf[5]  = (from >> 16) & 0xff;
	buf[6]  = (from >> 8)  & 0xff;
	buf[7]  = from & 0xff;
	memcpy(buf + 8, msg, len);

	pkt = new_packet(PACKET_ROOM_MESSAGE_IN, len + 8, buf, 0);
	if (target) {
		if (!from || admin || (target == ctx) || !room_user_ignores_me(ctx, rid, target->uid))
			send_packet(target, pkt);
		else free_packet(pkt);
	} else broadcast_to_unignored(ctx, rid, pkt);
}

/**
 * Get "My Room" info
 */
char *get_my_room_info(unsigned long uid)
{
	char *sql, *s = NULL;

	if (!my_room) {
		my_room = db_prepare(
			db_w,
			"SELECT nm AS name, r AS rating, catg, "
			"COALESCE(subcatg, 0) AS subcatg, max, "
			"(CASE lock WHEN 0 THEN 'N' ELSE 'Y' END) AS lock, "
			"intro FROM rooms WHERE owner=? AND p=0 ORDER BY id LIMIT 1"
		);
	}

	if (!my_room)
		return NULL;

	db_reset_prepared(my_room);
	db_bind(my_room, "i", uid);
	sql = db_get_prepared_sql(my_room);
	db_exec(db_w, &s, sql, db_row_to_record_per_field);
	db_free(sql);
	return s;
}

/**
 * Get the first room id matching \a name
 */
unsigned long name_to_room(const char *name)
{
	unsigned i;

	if (!room_by_name) {
		room_by_name = db_prepare(
			db_w,
			"SELECT id FROM rooms WHERE nm=? ORDER BY id LIMIT 1"
		);
	}

	if (!room_by_name)
		return UID_NOT_FOUND;

	db_reset_prepared(room_by_name);
	db_bind(room_by_name, "t", name);
	i = db_get_int(room_by_name);
	return i ? i : UID_NOT_FOUND;
}

/**
 * Search for a room by partial match on the room name
 */
char *search_rooms(unsigned protocol_version, const char *partial)
{
	char *sql = NULL, *s = NULL;
	void *sr;

	if (!db_w || !partial)
		return NULL;

	if (!search_room_queries[0]) {
		search_room_queries[0] = db_prepare(
			db_w,
			"SELECT r,nm,id,v,l FROM rooms WHERE p=0 AND nm LIKE ?"
		);
	}

	/**
	 * PT 8 added the category, presumably.
	 */
	if (!search_room_queries[1]) {
		search_room_queries[1] = db_prepare(
			db_w,
			"SELECT r,nm,id,v,l,catg,"
			"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS '#' "
			"FROM rooms WHERE p=0 AND nm LIKE ?"
		);
	}

	/**
	 * PT 8.2+ added subcategories after 8.2 beta, so the 8.2 beta
	 * builds will break. PT 9 adds lang, but 8.2 ignores it.
	 *
	 * TODO: WTF is the 6 digit number for?
	 */
	if (!search_room_queries[2]) {
		search_room_queries[2] = db_prepare(
			db_w,
			"SELECT r,nm,id,v,l,catg,"
			"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS '#',"
			"'001000', COALESCE(subcatg, 0) AS subcatg, lang "
			"FROM rooms WHERE p=0 AND nm LIKE ?"
		);
	}


	if (!search_room_queries[0] || !search_room_queries[1] || !search_room_queries[2])
		return NULL;

	sr = search_room_queries[((protocol_version >= PROTOCOL_VERSION_82) << 1) | (protocol_version == PROTOCOL_VERSION_80)];
	db_reset_prepared(sr);
	db_bind(sr, "t", partial);
	sql = db_get_prepared_sql(sr);
	db_exec(db_w, &s, sql, db_values_to_record);
	db_free(sql);
	return s;
}

/**
 * Send a room invite to a buddy
 */
void room_invite(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	char buf[256], *s = NULL, *sql;
	struct pt_context *target;

	sprintf(buf, "%lu", uid);
	if (!make_invite) {
		make_invite = db_prepare(
			db_w,
			"SELECT ? AS uid, ? AS nickname, COALESCE(?, CHAR(0x20)) AS first,"
			"COALESCE(?, CHAR(0x20)) AS last, id AS group_id, "
			"nm AS group_name, type, l AS lock FROM rooms WHERE id=?"
		);
	}

	if (!make_invite || !(target = ht_get_ptr_nc(uid_to_context, buf)))
		return;

	db_reset_prepared(make_invite);
	db_bind(make_invite, "ittti", ctx->uid, ctx->user.nickname, ctx->user.first, ctx->user.last, rid);
	sql = db_get_prepared_sql(make_invite);
	db_exec(db_w, &s, sql, db_row_to_record);
	db_free(sql);

	if ((sql = strstr(s, "lock=0"))) {
		*sql++ = (char)0xc8;
		*sql   = 0;
	}

	send_packet(target, new_packet(PACKET_ROOM_INVITE_IN, strlen(s), s, 0));
}

/**
 * Create a temporary room
 */
void create_room(struct pt_context *ctx, unsigned char type,
                 unsigned short catg, unsigned short subcatg,
                 char rating, const char *name, const char *passwd)
{
	char buf[2];
	unsigned id;

	if (!make_room) {
		make_room = db_prepare(
			db_w,
			"INSERT INTO rooms(type, catg, subcatg, r, v, p, mike, nm, l, "
			"password, owner, premium, c, created) VALUES(?, ?, ?, ?, ?, "
			"?, ?, ?, ?, ?, ?, ?, ?, datetime('now','subsec')) "
			"RETURNING id"
		);
	}

	if (!ctx || type > ROOM_TYPE_MAX || !name || !*name || subcatg == ALL_CATEGORIES)
		return;

	if (catg == ALL_CATEGORIES || catg == CATEGORY_TOP || catg == CATEGORY_FEATURED)
		return;

	if (rating != 'G' && rating != 'R' && rating != 'A')
		return;

	buf[0] = rating;
	buf[1] = 0;
	db_reset_prepared(make_room);
	db_bind(make_room, subcatg ? "iiitiiititiit" : "iintiiititiit",
	        type, catg, subcatg, buf,
	        type == ROOM_TYPE_PRIVATE_VOICE || type == ROOM_TYPE_VOICE,
	        type == ROOM_TYPE_PRIVATE_VOICE || type == ROOM_TYPE_PRIVATE_TEXT,
	        type == ROOM_TYPE_PRIVATE_VOICE || type == ROOM_TYPE_VOICE,
	        name, passwd && *passwd, (passwd && *passwd) ? passwd : NULL,
	        ctx->uid, *ctx->user.paid1 != 'N',
	        colors[ctx->user.admin ? 0 :
	              (!!(*ctx->user.paid1 & 4) << 1 | !!(*ctx->user.paid1 & 5))]
	);

	if (!(id = db_get_int(make_room))) {
		send_return_code(ctx, 1, server_error, SERVER_ERROR_LEN);
		return;
	}

	join(ctx, id, 0, passwd, 0);
}

/**
 * Get the first room id owned by the given user
 */
unsigned long owners_room(unsigned long uid) {
	if (!get_owners_room) {
		get_owners_room = db_prepare(
			db_w,
			"SELECT id FROM rooms WHERE p=0 AND owner=?"
		);
	}

	if (!get_owners_room)
		return 0;

	db_reset_prepared(get_owners_room);
	db_bind(get_owners_room, "i", uid);
	return db_get_int(get_owners_room);
}

/**
 * Send PACKET_ROOM_JOINED if the user joins the room successfully
 */
static int join_room_cb(void *userdata, int cols, char *val[], char *col[])
{
	int admin;
	size_t len;
	char *buf, r;
	unsigned long rid;
	unsigned short type, catg, subcatg;
	struct pt_context *ctx = userdata;

	(void)col;
	if (!ctx)
		return -1;

	if (!join_room_users) {
		join_room_users = db_prepare(
			db_w,
			"INSERT INTO room_users(id, uid, mic, invis, admin, host, pv) "
			"VALUES(?,?,(SELECT mike FROM rooms WHERE id=?),?,?,?,?)"
		);
	}

	if (!join_room_users || cols != 12 || !val[7] || !*val[7]) {
		send_return_code(ctx, 1, server_error, SERVER_ERROR_LEN);
		return -1;
	}

	/* Admins / Owners can bypass the lock password */
	admin = ctx->user.admin || (val[5] && ctx->uid == strtoul(val[5], NULL, 10))
	                        || (val[8] && *val[8] == '1');
	if (!admin && val[9] && *val[9] == '1' && !strtoul(val[4], NULL, 10)) {
		send_return_code(ctx, 1, invalid_password, INVALID_PASSWORD_LEN);
		return -1;
	}

	/* 5.0 doesn't support the extra fields */
	if (ctx->protocol_version < PROTOCOL_VERSION_51)
		*strchr(val[7], '\n') = '\0';

	len = strlen(val[7]);
	if (!(buf = calloc(22 + len, 1))) {
		send_return_code(ctx, 1, server_error, SERVER_ERROR_LEN);
		return -1;
	}

	rid     = strtoul(val[0], NULL, 10);
	type    = strtoul(val[1], NULL, 10) & 0xffff;
	catg    = strtoul(val[2], NULL, 10) & 0xffff;
	subcatg = strtoul(val[3], NULL, 10) & 0xffff;
	r       = *val[7];

	buf[0]  = (rid >> 24) & 0xff;
	buf[1]  = (rid >> 16) & 0xff;
	buf[2]  = (rid >> 8)  & 0xff;
	buf[3]  = rid & 0xff;
	buf[4]  = (type >> 8) & 0xff;
	buf[5]  = type & 0xff;
	buf[7]  = admin;
	buf[9]  = strtoul(val[4], NULL, 10) & 1;
	buf[11] = admin && val[10] && *val[10] == '1';
	buf[12] = (catg >> 8) & 0xff;
	buf[13] = catg & 0xff;
	buf[14] = (subcatg >> 8) & 0xff;
	buf[15] = subcatg & 0xff;

	/**
	 * Unless 2, fires an timer after 60 seconds which increments
	 * a global counter. Once it hits 10, packet 0xe7fa is sent.
	 */
	buf[17] = 2;

	db_reset_prepared(join_room_users);
	db_bind(join_room_users, "iiiiiii", rid, ctx->uid, rid, buf[11],
	        admin, user_is_owner(rid, ctx->uid),
	        ctx->protocol_version);
	db_do_prepared(join_room_users);

	memcpy(buf + 22, val[7], len);
	send_packet(ctx, new_packet(PACKET_ROOM_JOINED, 22 + len, buf, 0));

	/* Send the canned rating message and intro (if we have one) */
	send_room_message(ctx, ctx, rid, 0, strlen(rating_msg[r & 3]),
	                  rating_msg[r & 3]);
	if (val[6] && *val[6])
		send_room_message(ctx, ctx, rid, 0, strlen(val[6]), val[6]);

	if (type == ROOM_TYPE_PRIVATE_VOICE || type == ROOM_TYPE_VOICE)
		rtpctl(RTP_JOIN, rid, ctx->uid, val[11], strlen(val[11]));
	return 0;
}

/**
 * Join a room
 */
void join(struct pt_context *ctx, unsigned long rid, unsigned long code,
          const char *passwd, unsigned invis)
{
	char buf[16], *s;

	if (!banned_query) {
		banned_query = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM room_bans WHERE id=? AND uid=?"
		);
	}

	/**
	 * TODO: Determine the purpose of field2, field3, and Y
	 */
	if (!join_query) {
		join_query = db_prepare(
			db_w,
			"SELECT id, type, catg, COALESCE(subcatg, 0) AS subcatg, "
			"l, owner, intro, "
			"replace(format('%c%s\\nfield2\\nfield3\\nY\\nsize=%u\\n"
			"premium=%u\\ncodec=%s\\nqual=%u\\nchannels=%u\\nowner=%s\\n"
			"', r, nm, size, premium, codec, qual, channels, "
			"(SELECT nickname FROM users WHERE uid=owner)), '\\n', "
			"CHAR(10)) AS data, (code == ?), "
			"(password IS NULL OR password == ?), ?, "
			"CONCAT(channels & 0xf, CHAR(10), codec) "
			"FROM rooms WHERE id=?"
		);
	}

	if (user_in_room(rid, ctx->uid) || !banned_query || !join_query || !rid)
		return;

	db_reset_prepared(banned_query);
	db_bind(banned_query, "ii", rid, ctx->uid);
	if (db_get_count(banned_query)) {
		send_return_code(ctx, 1, banished, BANISHED_LEN);
		return;
	}

	db_reset_prepared(join_query);
	db_bind(join_query, "itii", code, passwd, !!invis, rid);
	s = db_get_prepared_sql(join_query);
	if (db_exec(db_w, ctx, s, join_room_cb)) {
		db_free(s);
		return;
	}

	db_free(s);
	send_room_topic(ctx, rid);
	send_room_banner_url(ctx, rid);
	if ((s = get_room_user_info(ctx, rid, UID_ALL)))
		send_packet(ctx, new_packet(PACKET_ROOM_USERLIST, strlen(s), s, 0));

	if ((s = get_room_user_info(ctx, rid, ctx->uid)))
		broadcast_to_room(ctx, rid, new_packet(PACKET_ROOM_USER_JOINED, strlen(s), s, 0));

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	buf[4]  = (ctx->server_ip >> 24) & 0xff;
	buf[5]  = (ctx->server_ip >> 16) & 0xff;
	buf[6]  = (ctx->server_ip >> 8)  & 0xff;
	buf[7]  = ctx->server_ip & 0xff;
	buf[8]  = 0;
	buf[9]  = 1;
	buf[10] = 0; /* This entry (udp tx port) isn't used by default. */
	buf[11] = 0;
	buf[12] = 0;
	buf[13] = 0;
	buf[14] = (voice_port >> 8) & 0xff;
	buf[15] = voice_port & 0xff;
	send_packet(ctx, new_packet(PACKET_ROOM_VOICE_CONN_INFO, 16, buf, PACKET_F_COPY));
}

/**
 * Depart from a room
 */
void part(struct pt_context *ctx, unsigned long rid)
{
	char buf[8];

	if (!depart[0]) {
		depart[0] = db_prepare(
			db_w,
			"DELETE FROM room_users WHERE id=? AND uid=?"
		);
	}

	if (!depart[1]) {
		depart[1] = db_prepare(
			db_w,
			"DELETE FROM room_ignore WHERE id=? AND uid=?"
		);
	}

	if (!depart[2]) { /* Clean up temp rooms as folks part */
		depart[2] = db_prepare(
			db_w,
			"DELETE FROM rooms WHERE id=? AND code=0 AND "
			"owner IS NOT NULL AND (SELECT COUNT(*) FROM "
			"room_users WHERE id=?)=0"
		);
	}

	if (!depart[0] || !depart[1] || !depart[2])
		return;

	if (user_in_room(rid, ctx->uid)) {
		buf[0] = (rid >> 24) & 0xff;
		buf[1] = (rid >> 16) & 0xff;
		buf[2] = (rid >> 8)  & 0xff;
		buf[3] = rid & 0xff;
		buf[4] = (ctx->uid >> 24) & 0xff;
		buf[5] = (ctx->uid >> 16) & 0xff;
		buf[6] = (ctx->uid >> 8)  & 0xff;
		buf[7] = ctx->uid & 0xff;
		broadcast_to_room(ctx, rid, new_packet(PACKET_ROOM_USER_LEFT, 8, buf, PACKET_F_COPY));
		rtpctl(RTP_PART, rid, ctx->uid, NULL, 0);
	}

	db_reset_prepared(depart[0]);
	db_bind(depart[0], "ii", rid, ctx->uid);
	db_do_prepared(depart[0]);

	db_reset_prepared(depart[1]);
	db_bind(depart[1], "ii", rid, ctx->uid);
	db_do_prepared(depart[1]);

	db_reset_prepared(depart[2]);
	db_bind(depart[2], "ii", rid, rid);
	db_do_prepared(depart[2]);
}

static int part_all_cb(void *ud, int cols, char *val[], char *col[])
{
	struct pt_context *ctx = ud;

	(void)cols;
	(void)col;
	if (cols && val[0])
		part(ctx, strtoul(val[0], NULL, 10));
	return 0;
}

/**
 * Depart from all rooms
 */
void part_all(struct pt_context *ctx)
{
	char buf[64];

	if (!ctx)
		return;

	sprintf(buf, "SELECT id FROM room_users WHERE uid=%lu", ctx->uid);
	db_exec(db_w, ctx, buf, part_all_cb);
}

/**
 * Close a room
 */
void close_room(struct pt_context *ctx, unsigned long rid, const char *msg)
{
	char *buf;
	size_t size;

	if (!do_close_room) {
		do_close_room = db_prepare(
			db_w,
			"DELETE FROM room_users WHERE id=?"
		);
	}

	if (!do_close_room)
		return;

	if (!(user_is_owner(rid, ctx->uid)      ||
	      user_is_room_admin(rid, ctx->uid) ||
	      ctx->user.admin))
		return;

	size = 8 + (msg ? strlen(msg) : 0);
	if (!(buf = malloc(size)))
		return;

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (ctx->uid >> 24) & 0xff;
	buf[5] = (ctx->uid>> 16) & 0xff;
	buf[6] = (ctx->uid >> 8)  & 0xff;
	buf[7] = ctx->uid & 0xff;
	if (msg) memcpy(buf + 8, msg, size - 8);
	broadcast_to_room(ctx, rid, new_packet(PACKET_ROOM_CLOSED, size, buf, 0));
	rtpctl(RTP_CLOSED, rid, 0, NULL, 0);

	db_reset_prepared(do_close_room);
	db_bind(do_close_room, "i", rid);
	db_do_prepared(do_close_room);
}

/**
 * User has Muted/Unmuted the room
 */
void mute_room(struct pt_context *ctx, unsigned long rid, unsigned on)
{
	char buf[80];
	struct pt_packet *pkt;

	if (!set_away) {
		set_away = db_prepare(
			db_w,
			"UPDATE room_users SET away=? WHERE id=? AND uid=?"
		);
	}

	if (!set_away || !user_in_room(rid, ctx->uid))
		return;

	db_reset_prepared(set_away);
	db_bind(set_away, "iii", !!on, rid, ctx->uid);
	db_do_prepared(set_away);

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (ctx->uid >> 24) & 0xff;
	buf[5] = (ctx->uid >> 16) & 0xff;
	buf[6] = (ctx->uid >> 8)  & 0xff;
	buf[7] = ctx->uid & 0xff;
	buf[8] = 0;
	buf[9] = !!on;

	pkt = new_packet(PACKET_ROOM_USER_MUTE, 10, buf, PACKET_F_COPY);
	broadcast_to_room(ctx, rid, pkt);
	rtpctl(!!on ? RTP_USER_UNMUTE : RTP_USER_MUTE, rid, ctx->uid, NULL, 0);
}

/**
 * Ignore a user in a room
 */
void ignore(struct pt_context *ctx, unsigned long rid,
            unsigned long target, int on)
{
	char buf[10];

	if (!room_ignore[0]) {
		room_ignore[0] = db_prepare(
			db_w,
			"DELETE FROM room_ignore WHERE id=? AND uid=? AND target=?"
		);
	}

	if (!room_ignore[1]) {
		room_ignore[1] = db_prepare(
			db_w,
			"INSERT INTO room_ignore(id, uid, target) VALUES(?, ?, ?) "
			"ON CONFLICT DO NOTHING"
		);
	}

	if (!room_ignore[0] || !room_ignore[1])
		return;

	if (ctx->uid == target) {
		if (on) send_return_code(ctx, 1, cant_ignore_self, CANT_IGNORE_SELF_LEN);
		on = 0;
		goto done;
	}

	if (!user_in_room(rid, ctx->uid) || !user_in_room(rid, target))
		return;

	if (user_is_room_admin(rid, target)) {
		if (on) send_return_code(ctx, 1, cant_ignore_admins, CANT_IGNORE_ADMINS_LEN);
		on = 0;
	}

done:
	/**
	 * XXX: This doesn't actually do anything, other than cause a
	 * debug string to get printed, at least up till 9.1.
	 *
	 * TODO: Check 10 and 11.
	 */
	if (ctx->protocol_version >= PROTOCOL_VERSION_70) {
		buf[0] = (rid >> 24) & 0xff;
		buf[1] = (rid >> 16) & 0xff;
		buf[2] = (rid >>  8) & 0xff;
		buf[3] = rid & 0xff;
		buf[4] = (target >> 24) & 0xff;
		buf[5] = (target >> 16) & 0xff;
		buf[6] = (target >>  8) & 0xff;
		buf[7] = target & 0xff;
		buf[8] = 0;
		buf[9] = !!on;
		send_packet(ctx, new_packet(PACKET_ROOM_IGNORE, 10, buf, PACKET_F_COPY));
	}

	/* Just in case they had their hand up */
	if (on) {
		buf[0] = (rid >> 24) & 0xff;
		buf[1] = (rid >> 16) & 0xff;
		buf[2] = (rid >>  8) & 0xff;
		buf[3] = rid & 0xff;
		buf[4] = (target >> 24) & 0xff;
		buf[5] = (target >> 16) & 0xff;
		buf[6] = (target >> 8)  & 0xff;
		buf[7] = target & 0xff;
		send_packet(ctx, new_packet(PACKET_ROOM_USER_HAND_DOWN, 8, buf, PACKET_F_COPY));
	}

	db_reset_prepared(room_ignore[!!on]);
	db_bind(room_ignore[!!on], "iii", rid, ctx->uid, target);
	db_do_prepared(room_ignore[!!on]);
}

/**
 * Reddot/Unreddot a user in a room
 */
void reddot_user(struct pt_context *ctx, unsigned long rid,
                 unsigned long uid, int on)
{
	char buf[8];
	struct pt_packet *pkt;

	if (!user_is_room_admin(rid, ctx->uid))
		return;

	if (!set_mic) {
		set_away = db_prepare(
			db_w,
			"UPDATE room_users SET mic=? WHERE id=? AND uid=?"
		);
	}

	if (!set_mic)
		return;
	db_reset_prepared(set_mic);
	db_bind(set_mic, "iii", !!on, rid, uid);
	db_do_prepared(set_mic);

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (uid >> 24) & 0xff;
	buf[5] = (uid >> 16) & 0xff;
	buf[6] = (uid >>  8) & 0xff;
	buf[7] = uid & 0xff;

	pkt = new_packet(
		on ? PACKET_ROOM_USER_REDDOT_ON : PACKET_ROOM_USER_REDDOT_OFF,
		8, buf, PACKET_F_COPY
	);

	send_packet(ctx, pkt);
	broadcast_to_room(ctx, rid, pkt);
	rtpctl(on ? RTP_RED : RTP_UNRED, rid, ctx->uid, NULL, 0);
}

/**
 * Turn all mics on/off in a room
 */
void set_all_mics(struct pt_context *ctx, unsigned long rid, int on)
{
	char buf[10];
	struct pt_packet *pkt;

	if (!all_mics) {
		all_mics = db_prepare(
			db_w,
			"UPDATE room_users SET mic=? WHERE id=?"
		);
	}

	if (!all_mics || !user_is_room_admin(rid, ctx->uid))
		return;

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = '\0';
	buf[5] = !!on;
	buf[6] = (ctx->uid >> 24) & 0xff;
	buf[7] = (ctx->uid >> 16) & 0xff;
	buf[8] = (ctx->uid >> 8)  & 0xff;
	buf[9] = ctx->uid & 0xff;

	db_reset_prepared(all_mics);
	db_bind(all_mics, "ii", !!on, rid);
	db_do_prepared(all_mics);

	pkt = new_packet(PACKET_ROOM_SET_MIC, 10, buf, PACKET_F_COPY);
	send_packet(ctx, pkt);
	broadcast_to_room(ctx, rid, pkt);
	rtpctl(on ? RTP_RED : RTP_UNRED, rid, 0, NULL, 0);
}

/**
 * Raise/Lower the user's hand
 */
void raise_hand(struct pt_context *ctx, unsigned long rid, int on)
{
	char buf[8];
	struct pt_packet *pkt;

	if (!set_hand) {
		set_hand = db_prepare(
			db_w,
			"UPDATE room_users SET req=? WHERE id=? AND uid=?"
		);
	}

	if (!set_hand || !user_in_room(rid, ctx->uid))
		return;

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (ctx->uid >> 24) & 0xff;
	buf[5] = (ctx->uid >> 16) & 0xff;
	buf[6] = (ctx->uid >> 8)  & 0xff;
	buf[7] = ctx->uid & 0xff;

	db_reset_prepared(set_hand);
	db_bind(set_hand, "iii", !!on, rid, ctx->uid);
	db_do_prepared(set_hand);

	pkt = new_packet(
		on ? PACKET_ROOM_USER_HAND_UP : PACKET_ROOM_USER_HAND_DOWN,
		8, buf, PACKET_F_COPY
	);

	/**
	 * PT 7.0.4 has a bug where upon receiving this packet for its user,
	 * it will resend the ROOM_HAND_DOWN request ad infinitum.
	 */
	if (on || ctx->protocol_version != PROTOCOL_VERSION_70)
		send_packet(ctx, pkt);
	broadcast_to_unignored(ctx, rid, pkt);
}

/**
 * Lower all hands
 */
void lower_all_hands(struct pt_context *ctx, unsigned long rid)
{
	char buf[8];

	if (!all_hands) {
		all_hands = db_prepare(
			db_w,
			"UPDATE room_users SET req=? WHERE id=?"
		);
	}

	if (!all_hands || !user_is_room_admin(rid, ctx->uid))
		return;

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (char)((UID_ALL >> 24) & 0xff);
	buf[5] = (char)((UID_ALL >> 16) & 0xff);
	buf[6] = (char)((UID_ALL >> 8)  & 0xff);
	buf[7] = UID_ALL & 0xff;

	db_reset_prepared(all_hands);
	db_bind(all_hands, "ii", 0, rid);
	db_do_prepared(all_hands);

	broadcast_to_room(ctx, rid,
		new_packet(PACKET_ROOM_USER_HAND_DOWN, 8, buf, PACKET_F_COPY)
	);
}

/**
 * Get the admin console info for a room
 */
char *get_admin_info(unsigned long rid)
{
	char buf[256];
	char *s = NULL;

	sprintf(
		buf,
		"SELECT id AS 'group', mike, text, video, "
		"COALESCE((SELECT string_agg(uid, char(10)) FROM room_bounces "
		"WHERE id=%ld), char(10)) AS bounce FROM rooms WHERE id=%ld",
		 rid, rid
	);
	if (db_exec(db_w, &s, buf, db_row_to_record) || !s)
		return s;

	sprintf(
		buf,
		"SELECT COALESCE((SELECT string_agg(uid, char(10)) FROM room_bans "
		"WHERE id=%ld), char(10)) AS ban",
		 rid
	);
	db_exec(db_w, &s, buf, db_row_to_record);
	return s;
}

static int send_room_topic_cb(void *userdata, int cols, char *val[], char *col[])
{
	char *buf;
	long rid, setter;
	struct pt_context *ctx = userdata;

	(void)col;
	if (!ctx || cols != 3 || !val[2] || !(buf = malloc(strlen(val[2]) + 8)))
		return 0;

	rid    = atol(val[0]);
	setter = atol(val[1]);
	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (setter >> 24) & 0xff;
	buf[5] = (setter >> 16) & 0xff;
	buf[6] = (setter >> 8)  & 0xff;
	buf[7] = setter & 0xff;
	memcpy(buf + 8, val[2], strlen(val[2]));
	send_packet(ctx, new_packet(PACKET_ROOM_TOPIC, strlen(val[2]) + 8, buf, 0));
	return 0;
}

/**
 * Send a room's topic to the user
 */
void send_room_topic(struct pt_context *ctx, unsigned long rid)
{
	char buf[72];

	sprintf(buf, "SELECT id, topic_setter, topic FROM rooms WHERE id=%lu", rid);
	db_exec(ctx->db_r, ctx, buf, send_room_topic_cb);
}

/**
 * Set the room topic
 */
void room_topic(struct pt_context *ctx, unsigned long rid, const char *topic)
{
	char *buf;
	struct pt_packet *pkt;

	if (!set_topic) {
		set_topic = db_prepare(
			db_w,
			"UPDATE rooms SET topic=?,topic_setter=? WHERE id=?"
		);
	}

	if (!set_topic || !user_is_room_admin(rid, ctx->uid))
		return;

	if (!topic) topic = empty_str;
	if (!(buf = malloc(9 + strlen(topic))))
		abort();

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (ctx->uid >> 24) & 0xff;
	buf[5] = (ctx->uid >> 16) & 0xff;
	buf[6] = (ctx->uid >> 8)  & 0xff;
	buf[7] = ctx->uid & 0xff;

	db_reset_prepared(set_topic);
	db_bind(set_topic, "tii", topic, ctx->uid, rid);
	db_do_prepared(set_topic);

	memcpy(buf + 8, topic, strlen(topic) + 1);
	pkt = new_packet(PACKET_ROOM_TOPIC, 8 + strlen(topic), buf, 0);
	send_packet(ctx, pkt);
	broadcast_to_room(ctx, rid, pkt);
}

static int send_room_banner_cb(void *userdata, int cols, char *val[], char *col[])
{
	char *buf;
	long rid;
	struct pt_context *ctx = userdata;

	(void)col;
	if (!ctx || cols != 2 || !val[1] || !strlen(val[1]) || !(buf = malloc(strlen(val[1]) + 4)))
		return 0;

	rid = atol(val[0]);
	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	memcpy(buf + 4, val[1], strlen(val[1]));
	send_packet(ctx, new_packet(PACKET_ROOM_BANNER_URL, strlen(val[1]) + 4, buf, 0));
	return 0;
}

/**
 * Send a room's banner_url to the user
 */
void send_room_banner_url(struct pt_context *ctx, unsigned long rid)
{
	char buf[64];

	sprintf(buf, "SELECT id, banner_url FROM rooms WHERE id=%lu", rid);
	db_exec(ctx->db_r, ctx, buf, send_room_banner_cb);
}

/**
 * Set a room's banner url
 */
void room_banner_url(struct pt_context *ctx, unsigned long rid,
                     const char *url)
{
	char *buf;

	if (!set_banner_url) {
		set_banner_url = db_prepare(
			db_w,
			"UPDATE rooms SET banner_url=? WHERE id=?"
		);
	}

	if (!set_banner_url || !user_is_room_admin(rid, ctx->uid))
		return;

	if (!url) url = empty_str;
	if (!(buf = malloc(4 + strlen(url))))
		abort();

	db_reset_prepared(set_banner_url);
	db_bind(set_banner_url, "tii", url, ctx->uid, rid);
	db_do_prepared(set_banner_url);

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	memcpy(buf + 4, url, strlen(url));
	broadcast_to_room(ctx, rid, new_packet(
		PACKET_ROOM_BANNER_URL, strlen(url) + 4, buf, 0)
	);
}

/**
 * Grant/Revoke temporary admin privileges
 */
void room_admin(struct pt_context *ctx, unsigned long rid,
                unsigned long uid, int on)
{
	char buf[128], *s;
	struct pt_context *target;
	struct pt_packet *pkt;

	if (!set_admin) {
		set_admin = db_prepare(
			db_w,
			"UPDATE room_users SET admin=? WHERE id=? AND uid=?"
		);
	}

	sprintf(buf, "%lu", uid);
	if (!set_admin || !(target = ht_get_ptr_nc(uid_to_context, buf)))
		return;

	/* Can't de-op owner or global admins, can de-op others, can de-op self */
	if (uid != ctx->uid && (
	    !user_in_room(rid, uid) ||
	    target->user.admin      ||
	    user_is_owner(rid, uid)))
		return;

	if (!(user_is_room_admin(rid, uid) ^ !!on))
		return;

	/* Let fellow admins know someone's been given special powers */
	buf[0]  = (rid >> 24) & 0xff;
	buf[1]  = (rid >> 16) & 0xff;
	buf[2]  = (rid >> 8)  & 0xff;
	buf[3]  = rid & 0xff;
	buf[4]  = 0;
	buf[5]  = 0;
	buf[6]  = 0;
	buf[7]  = 0;

	sprintf(buf + 8, "%s has %s %s %s mysterious power",
	        ctx->user.nickname, on ? "invested" : "divested",
	        (ctx == target) ? "themself" : target->user.nickname,
	        on ? "with a" : "of their");
	broadcast_to_admins(
		ctx, rid,
		new_packet(PACKET_ROOM_MESSAGE_IN, 8 + strlen(buf + 8), buf, PACKET_F_COPY)
	);

	sprintf(buf + 8, "You have %s %s %s mysterious power",
	        on ? "invested" : "divested",
	        ctx == target ? "yourself" : target->user.nickname,
	        on ? "with a" : ctx == target ? "of your" : "of their");
	send_packet(ctx, new_packet(PACKET_ROOM_MESSAGE_IN, 8 + strlen(buf + 8), buf, PACKET_F_COPY));

	db_reset_prepared(set_admin);
	db_bind(set_admin, "iii", !!on, rid, uid);
	db_do_prepared(set_admin);

	s      = get_room_user_info(ctx, rid, uid);
	pkt    = new_packet(PACKET_ROOM_USERLIST, strlen(s), s, 0);
	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >> 8)  & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (uid >> 24) & 0xff;
	buf[5] = (uid >> 16) & 0xff;
	buf[6] = (uid >> 8)  & 0xff;
	buf[7] = uid & 0xff;
	buf[8] = 0;
	buf[9] = !!on;
	if (ctx->protocol_version < PROTOCOL_VERSION_70) {
		if (on)
			send_packet(target, new_packet(PACKET_PT5_ROOM_ADMIN_GRANTED, 4, buf, PACKET_F_COPY));
		else send_packet(target, new_packet(PACKET_PT5_ROOM_ADMIN_STATUS, 10, buf, PACKET_F_COPY));
	} else {
		/* TODO: Do 7 - 9.x update their own admin status? (they do for other users) */
		/* Newer version look for the user's own info as a singular entry */
		send_packet(ctx, pkt);
	}

	broadcast_at_or_below(
		target, rid,
		new_packet(PACKET_PT5_ROOM_ADMIN_STATUS, 10, buf, PACKET_F_COPY),
		PROTOCOL_VERSION_51
	);

	/* Newer versions ignore the simple admin status update packet :( */
	broadcast_at_or_above(target, rid, pkt, PROTOCOL_VERSION_70);
}

/**
 * Ban a user from a room
 */
void ban_user(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	char buf[256];
	struct pt_context *target;

	if (!do_ban) {
		do_ban = db_prepare(
			db_w,
			"INSERT INTO room_bans(id,uid,banner,ts) VALUES("
			"?,?,?,datetime('now','subsec')) ON CONFLICT DO NOTHING"
		);
	}

	if (!do_ban || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_ban);
	db_bind(do_ban, "iii", rid, uid, ctx->uid);
	db_do_prepared(do_ban);

	if (!user_in_room(rid, ctx->uid))
		return;

	sprintf(buf, "%ld", uid);
	if (!(target = ht_get_ptr_nc(uid_to_context, buf)))
		return;

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (ctx->uid >> 24) & 0xff;
	buf[5] = (ctx->uid >> 16) & 0xff;
	buf[6] = (ctx->uid >> 8)  & 0xff;
	buf[7] = ctx->uid & 0xff;
	memcpy(buf + 8, banished, BANISHED_LEN);
	send_packet(target, new_packet(PACKET_ROOM_CLOSED, 45, buf, PACKET_F_COPY));
}

/**
 * Unban a user from a room
 */
void unban_user(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	if (!do_unban) {
		do_unban = db_prepare(
			db_w,
			"DELETE FROM room_bans WHERE id=? AND uid=?"
		);
	}

	if (!do_unban || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_unban);
	db_bind(do_unban, "ii", rid, uid);
	db_do_prepared(do_unban);
}

/**
 * Bounce a user from a room
 */
void bounce_user(struct pt_context *ctx, unsigned long rid,
                 unsigned long uid, const char *reason)
{
	char buf[64];
	struct pt_context *target;

	if (!do_bounce) {
		do_bounce = db_prepare(
			db_w,
			"INSERT INTO room_bounces(id,uid,bouncer,reason,ts) VALUES("
			"?,?,?,?,datetime('now','subsec')) ON CONFLICT DO NOTHING"
		);
	}

	if (!do_bounce || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_bounce);
	db_bind(do_bounce, "iiit", 0, rid, uid, ctx->uid, reason ? reason : empty_str);
	db_do_prepared(do_bounce);

	if (!user_in_room(rid, ctx->uid))
		return;

	sprintf(buf, "%ld", uid);
	if (!(target = ht_get_ptr_nc(uid_to_context, buf)))
		return;

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = (ctx->uid >> 24) & 0xff;
	buf[5] = (ctx->uid >> 16) & 0xff;
	buf[6] = (ctx->uid >> 8)  & 0xff;
	buf[7] = ctx->uid & 0xff;
	memcpy(buf + 8, "You have been bounced from this room.", 36);
	send_packet(target, new_packet(PACKET_ROOM_CLOSED, 44, buf, PACKET_F_COPY));
}

/**
 * Unbounce a user from a room
 */
void unbounce_user(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	if (!do_unbounce) {
		do_unbounce = db_prepare(
			db_w,
			"DELETE FROM room_bounces WHERE id=? AND uid=?"
		);
	}

	if (!do_unbounce || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_unbounce);
	db_bind(do_unbounce, "ii", rid, uid);
	db_do_prepared(do_unbounce);
}

/**
 * Whether or not to give users mic privileges on join
 */
void new_user_mic(struct pt_context *ctx, unsigned long rid, int on)
{
	if (!do_mic) {
		do_mic = db_prepare(
			db_w,
			"UPDATE rooms SET mike=? WHERE id=?"
		);
	}

	if (!do_mic || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_mic);
	db_bind(do_mic, "ii", !!on, rid);
	db_do_prepared(do_mic);
}

/**
 * Reddot text for the entire room
 */
void reddot_text(struct pt_context *ctx, unsigned long rid, int on)
{
	if (!do_text) {
		do_text = db_prepare(
			db_w,
			"UPDATE rooms SET text=? WHERE id=?"
		);
	}

	if (!do_text || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_text);
	db_bind(do_text, "ii", !!on, rid);
	db_do_prepared(do_text);
}

/**
 * Reddot video for the entire room
 */
void reddot_video(struct pt_context *ctx, unsigned long rid, int on)
{
	if (!do_video) {
		do_video = db_prepare(
			db_w,
			"UPDATE rooms SET video=? WHERE id=?"
		);
	}

	if (!do_video || !user_is_room_admin(rid, ctx->uid))
		return;

	db_reset_prepared(do_video);
	db_bind(do_video, "ii", !!on, rid);
	db_do_prepared(do_video);
}

/**
 * Whisper to a user in a room
 */
void whisper(struct pt_context *ctx, unsigned long rid,
             const char *target, const char *msg)
{
	char *buf;
	unsigned long target_uid;
	struct pt_context *tctx;

	if (!ctx || !rid || !msg)
		return;

	target_uid = lookup_uid(ctx->db_r, target);
	if (UID_IS_ERROR(target_uid) || !user_in_room(rid, target_uid))
		return;

	/* TODO: Check for anonymous room and bail */
	if (user_is_invisible(rid, target_uid) ||
	    user_is_invisible(rid, ctx->uid))
		return;

	if (!(buf = malloc(32)))
		abort();

	sprintf(buf, "%ld", target_uid);
	if (!(tctx = ht_get_ptr_nc(uid_to_context, buf))) {
		free(buf);
		return;
	}

	if (tctx == ctx) {
		free(buf);
		send_room_message(ctx, tctx, rid, 0, WHISPER_SELF_LEN, whisper_self);
		return;
	}

	if (!(buf = realloc(buf, 128 + strlen(msg))))
		abort();

	sprintf(
		buf,
		"<pb><pi>***** Start Whisper</pi></pb>\n"
		"<pfont color=\"#16711680\">%s</pfont>\n"
		"<pi><pb>***** End Whisper</pi></pb>",
		msg
	);
	send_room_message(ctx, tctx, rid, ctx->uid, strlen(buf), buf);

	/**
	 * According to my old code, the server just returns "Whisper sent" here.
	 * This is far more useful, so we'll go with it.
	 */
	sprintf(
		buf,
		"<pfont color=\"#128\"><pi><pb>(Whispered to %s)</pb> %s"
		"</pi></pfont>",
		target, msg
	);
	send_room_message(ctx, ctx, rid, ctx->uid, strlen(buf), buf);
	free(buf);
}

/**
 * Set the admin code for the room
 */
static void admin_code(struct pt_context *ctx, unsigned long rid, unsigned code)
{
	if (!set_code) {
		set_code = db_prepare(
			db_w,
			"UPDATE rooms SET code=? WHERE id=?"
		);
	}

	if (!ctx || !rid || !user_is_owner(rid, ctx->uid))
		return;

	if (!code || code > 9999) {
		send_room_message(ctx, ctx, rid, 0, CODE_RANGE_LEN, code_range);
		return;
	}

	db_reset_prepared(set_code);
	db_bind(set_code, "ii", code, rid);
	db_do_prepared(set_code);
	send_room_message(ctx, ctx, rid, 0, CODE_CHANGED_LEN, code_changed);
}

static const char *skip_phtml(const char *buf)
{

	while (*buf && *buf == '<') {
		while (*buf && *buf != '>')
			++buf;
		++buf;
	}

	return buf;
}

/**
 * Evaluate a slash command
 *
 * \return non-zero if \a buf contained a valid command
 */
int room_command(struct pt_context *ctx, unsigned long rid, const char *buf)
{
	int ret = 0, on;
	unsigned long id;
	const char *msg;
	char *s = NULL, *cmd, *args;

	if (!ctx || !rid || !buf)
		goto ret;

	buf = skip_phtml(buf);
	if (*buf != '/')
		goto ret;

	/* We should have one command, and one argument string */
	if (!(s = strdup(buf + 1)))
		abort();
	cmd  = strtok(s, " ");
	args = strtok(NULL, "<");
	if (!cmd) goto ret;

	switch (*cmd) {
	case 'c': /* [c]ode 0000 */
		if (!args) break;
		admin_code(ctx, rid, strtoul(args, NULL, 10));
		++ret;
		break;
	case 'i': /* [i]gnore user [on]|off */
		if (!args || !(cmd = strtok(args, " ")))
			break;

		if ((on = !strcmp(cmd, "on")) || !strcmp(cmd, "off"))
			id = ctx->uid;
		else {
			if (*cmd >= '0' && *cmd <= '9')
				id = strtoul(cmd, 0, 10);
			else id = lookup_uid(ctx->db_r, cmd);
			cmd = strtok(NULL, " ");
			on = !cmd || !strcmp(cmd, "on");
		}

		if (!UID_IS_ERROR(id))
			ignore(ctx, rid, id, on);
		++ret;
		break;
	case 'o': /* [o]p [user] [on]|off */
		if (!args || !(cmd = strtok(args, " "))) {
			room_admin(ctx, rid, ctx->uid, 1);
			break;
		}

		if ((on = !strcmp(cmd, "on")) || !strcmp(cmd, "off"))
			id = ctx->uid;
		else {
			if (*cmd >= '0' && *cmd <= '9')
				id = strtoul(cmd, 0, 10);
			else id = lookup_uid(ctx->db_r, cmd);
			cmd = strtok(NULL, " ");
			on  = !cmd || !strcmp(cmd, "on");
		}

		if (!UID_IS_ERROR(id))
			room_admin(ctx, rid, id, on);
		++ret;
		break;
	case 't': /* [t]opic str */
		if (!args) break;
		room_topic(ctx, rid, args);
		++ret;
		break;
	case 'w': /* [w]hisper target: msg */
		if (!args) break;
		cmd = strtok(args, ": ");
		whisper(ctx, rid, cmd, strtok(NULL, "<"));
		++ret;
		break;
	}

	if (!ret) {
		msg = room_cmds[user_is_room_admin(rid, ctx->uid)];
		send_room_message(ctx, ctx, rid, 0, strlen(msg), msg);
	}

ret:
	free(s);
	return ret;
}

