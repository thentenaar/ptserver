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

#include "logging.h"
#include "database.h"
#include "protocol.h"
#include "packet.h"
#include "hash.h"
#include "user.h"
#include "room.h"

/* from server.c */
extern struct ht *uid_to_context;

/* Prepared queries on db_w */
static void *in_room;
static void *is_invis;
static void *is_admin;
static void *search_room_queries[4];
static void *set_mic;
static void *set_hand;
static void *all_hands;
static void *set_topic;
static void *do_ban;
static void *do_unban;
static void *do_bounce;
static void *do_unbounce;
static void *do_mic;
static void *do_text;
static void *do_video;

static const char * const empty_str = "";

static const char * const rooms_fmt[5] = {
	"FROM rooms WHERE catg=%ld ORDER BY '#' DESC, nm ASC",
	"FROM rooms ORDER BY '#' DESC, nm ASC LIMIT 5",
	"FROM rooms ORDER BY created DESC, nm ASC LIMIT 5",

	"SELECT id,r,p,v,l,c,nm,"
	"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS '#' ",

	/* PT 8.2+: Uses the new room list packet (t=S is for subcategories) */
	"SELECT 'G' AS t,id,nm AS n,r,p,v,l,c,'Y' AS eof,lang,"
	"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS m "
	"FROM rooms WHERE catg=%ld AND subcatg IS NULL ORDER BY m DESC, n ASC",
};

/**
 * Get the room counts by category
 */
char *room_counts_by_category(void *db_r)
{
	char buf[512], *s = NULL;

	sprintf(buf, /* The two virtual categories will have up to 5 entries */
			"SELECT %d AS id, (SELECT MIN(5, COUNT(DISTINCT id)) FROM rooms) AS '#' UNION "
			"SELECT %d AS id, (SELECT MIN(5, COUNT(DISTINCT id)) FROM rooms) AS '#' UNION "
			"SELECT catg AS id, COUNT(*) AS '#' FROM rooms WHERE catg NOT IN (%d,%d) GROUP BY catg",
			CATEGORY_TOP, CATEGORY_FEATURED, CATEGORY_TOP, CATEGORY_FEATURED);

	if (!db_exec(db_r, &s, buf, db_row_to_record) && s)
		return s;

	free(s);
	return NULL;
}

/**
 * Get the list of rooms for the given category
 */
char *rooms_for_category(void *db_r, unsigned long protocol_version, unsigned long catid)
{
	char buf[256], *s = NULL;
	unsigned idx = ((catid == CATEGORY_FEATURED) << 1) | (catid == CATEGORY_TOP);

	if (protocol_version >= PROTOCOL_VERSION_82 && !idx) {
		sprintf(buf, rooms_fmt[4], catid);
		if (db_exec(db_r, &s, buf, db_row_to_record)) {
			free(s);
			return NULL;
		}
	} else {
		memcpy(buf, rooms_fmt[3], strlen(rooms_fmt[3]) + 1);
		sprintf(buf + strlen(buf), rooms_fmt[idx], catid);
		if (db_exec(db_r, &s, buf, db_row_to_record)) {
			free(s);
			return NULL;
		}
	}

	sprintf(buf, "catg=%ld\n", catid);
	s = prepend_record(s, buf);
	return s;
}

/**
 * Get the list of rooms for the given category + subcategory
 */
char *rooms_for_subcategory(void *db_r, unsigned long catid, unsigned long scid)
{
	char buf[512], *s = NULL;

	sprintf(
		buf,
		"SELECT 'G' AS t, subcatg AS sc,id,nm AS n,r,p,v,l,c,"
		"(SELECT COUNT(uid) FROM room_users WHERE id=rooms.id) AS m,"
		"'Y' AS eof, lang FROM rooms WHERE catg=%ld AND subcatg=%ld ORDER BY nm DESC, n ASC",
		catid, scid);

	if (db_exec(db_r, &s, buf, db_row_to_record)) {
		free(s);
		return NULL;
	}

	sprintf(buf, "catg=%ld\nsubcatg=%ld\n", catid, scid);
	s = prepend_record(s, buf);
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
int user_in_room(void *db_w, unsigned long rid, unsigned long uid)
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
	return 1 || !!db_get_count(in_room);
}

/**
 * Non-zero if the given user is invisble in the given room
 */
int user_is_invisible(void *db_w, unsigned long rid, unsigned long uid)
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
 * Non-zero if the given user is a room admin and present in the room
 */
int user_is_room_admin(void *db_w, unsigned long rid, unsigned long uid)
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
 * Broadcast a packet (i.e. PACKET_ROOM_MESSAGE_IN) to an entire room
 */
void broadcast_to_room(struct pt_context *ctx, unsigned long rid, struct pt_packet *pkt)
{
	char buf[128];

	if (!user_in_room(ctx->db_w, rid, ctx->uid))
		return;

	sprintf(buf, "SELECT uid FROM room_users WHERE id=%ld AND uid<>%ld", rid, ctx->uid);
	db_exec(ctx->db_w, pkt, buf, broadcast_to_room_cb);
}

/**
 * Broadcast a packet (i.e. PACKET_ROOM_MESSAGE_IN) to non-admins in a room
 */
void broadcast_to_non_admins(struct pt_context *ctx, unsigned long rid, struct pt_packet *pkt)
{
	char buf[128];

	if (!user_in_room(ctx->db_w, rid, ctx->uid))
		return;

	sprintf(buf, "SELECT uid FROM room_users WHERE id=%ld AND uid<>%ld AND admin=0", rid, ctx->uid);
	db_exec(ctx->db_w, pkt, buf, broadcast_to_room_cb);
}

/**
 * Search for a room by partial match on the room name
 */
char *search_rooms(void *db_w, unsigned protocol_version, const char *partial)
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
			"'001000',subcatg,lang "
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
 * Reddot/Unreddot a user in a room
 */
void reddot_user(struct pt_context *ctx, unsigned long rid, unsigned long uid, int on)
{
	char buf[8];
	struct pt_packet *pkt;

	if (!user_is_room_admin(ctx->db_w, rid, ctx->uid))
		return;

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

	broadcast_to_room(ctx, rid, pkt);
	send_packet(ctx, pkt);
}

/**
 * Turn all mics on/off in a room
 */
void set_all_mics(struct pt_context *ctx, unsigned long rid, int on)
{
	char buf[10];
	struct pt_packet *pkt;

	if (!set_mic) {
		set_mic = db_prepare(
			ctx->db_w,
			"UPDATE room_users SET mic=? WHERE id=?"
		);
	}

	if (!set_mic || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
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

	db_reset_prepared(set_mic);
	db_bind(set_mic, "ii", !!on, rid);
	db_do_prepared(set_mic);

	pkt = new_packet(PACKET_ROOM_SET_MIC, 10, buf, PACKET_F_COPY);
	broadcast_to_room(ctx, rid, pkt);
	send_packet(ctx, pkt);
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
			ctx->db_w,
			"UPDATE room_users SET req=? WHERE id=? AND uid=?"
		);
	}

	if (!set_hand || !user_in_room(ctx->db_w, rid, ctx->uid))
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

	broadcast_to_room(ctx, rid, pkt);
	send_packet(ctx, pkt);
}

/**
 * Lower all hands
 */
void lower_all_hands(struct pt_context *ctx, unsigned long rid)
{
	char buf[8];

	if (!all_hands) {
		all_hands = db_prepare(
			ctx->db_w,
			"UPDATE room_users SET req=? WHERE id=?"
		);
	}

	if (!all_hands || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
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
char *get_admin_info(struct pt_context *ctx, unsigned long rid)
{
	char buf[256];
	char *s = NULL;

	sprintf(
		buf,
		"SELECT id AS 'group', mike, text, video, "
		"coalesce((SELECT string_agg(uid, char(10)) FROM room_bounces "
		"WHERE id=%ld), char(10)) AS bounce FROM rooms WHERE id=%ld",
		 rid, rid
	);
	if (db_exec(ctx->db_w, &s, buf, db_row_to_record) || !s)
		return s;

	sprintf(
		buf,
		"SELECT coalesce((SELECT string_agg(uid, char(10)) FROM room_bans "
		"WHERE id=%ld), char(10)) AS ban",
		 rid
	);
	db_exec(ctx->db_w, &s, buf, db_row_to_record);
	return s;
}

/**
 * Set the room topic
 */
void room_topic(struct pt_context *ctx, unsigned long rid, const char *topic)
{
	char *buf;

	if (!set_topic) {
		set_topic = db_prepare(
			ctx->db_w,
			"UPDATE rooms SET topic=?,topic_setter=? WHERE id=?"
		);
	}

	if (!set_topic || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
		return;

	if (!topic) topic = empty_str;
	if (!(buf = malloc(8 + strlen(topic))))
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
	broadcast_to_room(ctx, rid,
		new_packet(PACKET_ROOM_TOPIC, 8 + strlen(topic), buf, 0)
	);
}

/**
 * Ban a user from a room
 */
void ban_user(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	char buf[64];
	struct pt_context *target;

	if (!do_ban) {
		do_ban = db_prepare(
			ctx->db_w,
			"INSERT INTO room_bans(id,uid,banner,ts) VALUES("
			"?,?,?,datetime('now','subsec')) ON CONFLICT DO NOTHING"
		);
	}

	if (!do_ban || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
		return;

	db_reset_prepared(do_ban);
	db_bind(do_ban, "iii", rid, uid, ctx->uid);
	db_do_prepared(do_ban);

	if (!user_in_room(ctx->db_w, rid, ctx->uid))
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
	memcpy(buf + 8, "You have been banned from this room.", 35);
	send_packet(target, new_packet(PACKET_ROOM_CLOSED, 43, buf, PACKET_F_COPY));
}

/**
 * Unban a user from a room
 */
void unban_user(struct pt_context *ctx, unsigned long rid, unsigned long uid)
{
	if (!do_unban) {
		do_unban = db_prepare(
			ctx->db_w,
			"DELETE FROM room_bans WHERE id=? AND uid=?"
		);
	}

	if (!do_unban || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
		return;

	db_reset_prepared(do_unban);
	db_bind(do_unban, "ii", rid, uid);
	db_do_prepared(do_unban);
}

/**
 * Bounce a user from a room
 */
void bounce_user(struct pt_context *ctx, unsigned long rid, unsigned long uid, const char *reason)
{
	char buf[64];
	struct pt_context *target;

	if (!do_bounce) {
		do_bounce = db_prepare(
			ctx->db_w,
			"INSERT INTO room_bounces(id,uid,bouncer,reason,ts) VALUES("
			"?,?,?,?,datetime('now','subsec')) ON CONFLICT DO NOTHING"
		);
	}

	if (!do_bounce || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
		return;

	db_reset_prepared(do_bounce);
	db_bind(do_bounce, "iiit", 0, rid, uid, ctx->uid, reason ? reason : empty_str);
	db_do_prepared(do_bounce);

	if (!user_in_room(ctx->db_w, rid, ctx->uid))
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
			ctx->db_w,
			"DELETE FROM room_bounces WHERE id=? AND uid=?"
		);
	}

	if (!do_unbounce || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
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
			ctx->db_w,
			"UPDATE rooms SET mike=? WHERE id=?"
		);
	}

	if (!do_mic || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
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
			ctx->db_w,
			"UPDATE rooms SET text=? WHERE id=?"
		);
	}

	if (!do_text || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
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
			ctx->db_w,
			"UPDATE rooms SET video=? WHERE id=?"
		);
	}

	if (!do_video || !user_is_room_admin(ctx->db_w, rid, ctx->uid))
		return;

	db_reset_prepared(do_video);
	db_bind(do_video, "ii", !!on, rid);
	db_do_prepared(do_video);
}

/**
 * Whisper to a user in a room
 */
void whisper(struct pt_context *ctx, unsigned long rid, const char *target, const char *msg)
{
	char *buf;
	unsigned long target_uid;
	struct pt_context *tctx;

	if (!ctx || !rid || !msg)
		return;

	target_uid = lookup_uid(ctx->db_r, target);
	if (UID_IS_ERROR(target_uid) || !user_in_room(ctx->db_w, rid, target_uid))
		return;

	/* TODO: Check for anonymous room and bail */
	if (user_is_invisible(ctx->db_w, rid, target_uid) ||
	    user_is_invisible(ctx->db_w, rid, ctx->uid))
		return;

	if (!(buf = malloc(32)))
		abort();

	sprintf(buf, "%ld", target_uid);
	if (!(tctx = ht_get_ptr_nc(uid_to_context, buf)) || tctx == ctx) {
		free(buf);
		return;
	}

	if (!(buf = realloc(buf, 128 + strlen(msg))))
		abort();

	buf[0] = (rid >> 24) & 0xff;
	buf[1] = (rid >> 16) & 0xff;
	buf[2] = (rid >>  8) & 0xff;
	buf[3] = rid & 0xff;
	buf[4] = ((ctx->uid >> 24) & 0xff);
	buf[5] = ((ctx->uid >> 16) & 0xff);
	buf[6] = ((ctx->uid >> 8)  & 0xff);
	buf[7] = ctx->uid & 0xff;
	sprintf(
		buf + 8,
		"<pb><pi>***** Start Whisper</pi></pb>\n"
		"<pfont color=\"#16711680\">%s</pfont>\n"
		"<pi><pb>***** End Whisper</pi></pb>",
		msg
	);
	send_packet(tctx, new_packet(PACKET_ROOM_MESSAGE_IN, 8 + strlen(buf + 8), buf, PACKET_F_COPY));

	/**
	 * According to my old code, the server just returns "Whisper sent" here.
	 * This is far more useful, so we'll go with it.
	 */
	memset(buf + 4, 0, 4);
	sprintf(
		buf + 8,
		"<pfont color=\"#128\"><pi><pb>(Whispered to %s)</pb> %s"
		"</pi></pfont>",
		target, msg
	);
	send_packet(ctx, new_packet(PACKET_ROOM_MESSAGE_IN, 8 + strlen(buf + 8), buf, 0));
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
	int ret = 0;
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
	if (!cmd || !args)
		goto ret;

	switch (*cmd) {
	case 't': /* [t]opic str */
		room_topic(ctx, rid, args);
		++ret;
		break;
	case 'w': /* [w]hisper target: msg */
		cmd = strtok(args, ": ");
		whisper(ctx, rid, cmd, strtok(NULL, "<"));
		++ret;
		break;
	}

ret:
	free(s);
	return ret;
}

