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

#include "macros.h"
#include "hash.h"
#include "database.h"
#include "protocol.h"
#include "packet.h"
#include "buddylist.h"

/* Prepared queries on db_w */
static void *q_add_buddy;
static void *q_remove_buddy;
static void *q_block_buddy;
static void *q_unblock_buddy;
static void *blocked_user;
static void *user_is_buddy;
static void *set_disp_name;

/* from server.c */
extern void *db_w;
extern struct ht *uid_to_context;

/**
 * Get the buffer size needed to hold the escaped version of \a s
 *
 * Here, we assume that \a s is null-terminated, and that everything in
 * \a s represents a valid JSON string aside from the usual escapes.
 */
static size_t jsonesc_len(const char *s)
{
	size_t len = 0;

	while (s && *s) {
		switch (*s++) {
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\\':
			++len;
		default:
			++len;
		}
	}

	return len;
}

/**
 * Perform the usual basic escapes on \a s
 */
static char *jsonesc(const char *s)
{
	char *buf, c;
	size_t len, i = 0;

	if (!(len = jsonesc_len(s)) || !(buf = malloc(len + 1)))
		return NULL;

	while (*s) {
		switch ((c = *s++)) {
		case '\b':
			buf[i++] = '\\';
			buf[i++] = 'b';
			break;
		case '\f':
			buf[i++] = '\\';
			buf[i++] = 'f';
			break;
		case '\n':
			buf[i++] = '\\';
			buf[i++] = 'n';
			break;
		case '\r':
			buf[i++] = '\\';
			buf[i++] = 'r';
			break;
		case '\t':
			buf[i++] = '\\';
			buf[i++] = 't';
			break;
		default:
			buf[i++] = c;
		}
	}

	buf[i++] = '\0';
	return buf;
}

static struct pt_packet *mk_statuschange_json(unsigned long uid, unsigned long status, unsigned crown, const char *msg)
{
	int len;
	char *buf, *mbuf = NULL;

	if (!(buf = malloc(jsonesc_len(msg) + 100)))
		abort();

	if (msg && *msg && !(mbuf = jsonesc(msg))) {
		free(buf);
		abort();
	}

	len = sprintf(buf,
	             "{\"user_id\":%lu,\"state\":%lu,\",away_mesg\":\"%s\",\"crown_level\":%u}",
	             uid, status, mbuf ? mbuf : "", crown);
	if (mbuf) free(mbuf);
	return new_packet(PACKET_BUDDY_STATUSCHANGE, len, buf, 0);
}

/**
 * Construct a BUDDY_STATUSCHANGE packet based on the recipient's protocol
 * version
 */
static struct pt_packet *mk_statuschange(struct pt_context *ctx, unsigned long uid, unsigned long status, unsigned crown, const char *msg)
{
	char buf[18 + STATUSMSG_MAX];
	size_t msglen, len = 8;

	if (ctx->uid != uid) {
		if (status == STATUS_INVISIBLE)
			status = STATUS_OFFLINE;

		/* 11.7+ uses JSON for this... :/ */
		if (ctx->protocol_version >= PROTOCOL_VERSION_117)
			return mk_statuschange_json(uid, status, crown, msg);

		/* TODO: PT 9.1 needs this extra bit... Not sure what these signify */
		if (ctx->protocol_version >= PROTOCOL_VERSION_91) {
			buf[8]  = 0x00;
			buf[9]  = 0x5d;
			len    += 2;
		}

		/* TODO: 10.2 needs an additional word, long, and word */
		if (ctx->protocol_version >= PROTOCOL_VERSION_102) {
			buf[10] = 0x00;
			buf[11] = 0x00;
			buf[12] = 0x00;
			buf[13] = 0x00;
			buf[14] = 0x00;
			buf[15] = 0x00;
			buf[16] = 0x00;
			buf[17] = 0x00;
			len    += 8;
		}
	} else if (status == STATUS_OFFLINE)
		return NULL;

	buf[0] = (uid >> 24) & 0xff;
	buf[1] = (uid >> 16) & 0xff;
	buf[2] = (uid >> 8)  & 0xff;
	buf[3] = uid & 0xff;
	buf[4] = (status >> 24) & 0xff;
	buf[5] = (status >> 16) & 0xff;
	buf[6] = (status >> 8) & 0xff;
	buf[7] = status & 0xff;

	if (((status != STATUS_ONLINE && ctx->protocol_version >= PROTOCOL_VERSION_82) ||
	    ctx->protocol_version >= PROTOCOL_VERSION_102) && msg) {
		msglen = min(STATUSMSG_MAX, strlen(msg));
		memcpy(buf + len, msg, msglen);
		len += msglen;
	}

	if (ctx->uid == uid)
		return new_packet(PACKET_USER_STATUS, len - 4, buf + 4, PACKET_F_COPY);
	return new_packet(PACKET_BUDDY_STATUSCHANGE, len, buf, PACKET_F_COPY);
}

/**
 * Send our status out to our buddies
 */
static int do_broadcast_status(void *userdata, int cols, char *val[], char *col[])
{
	char buf[64];
	struct pt_context *ctx = userdata, *buddy;
	unsigned long uid;
	(void)cols;
	(void)col;

	uid = strtoul(val[0], NULL, 10);
	sprintf(buf, "%ld", uid);
	if (!(buddy = ht_get_ptr_nc(uid_to_context, buf)) ||
	    user_blocked_me(ctx, uid))
		return 0;

	send_packet(buddy, mk_statuschange(buddy, ctx->uid, ctx->status, ctx->user.crown_level, ctx->status_msg));
	return 0;
}

/**
 * Send our buddies' statuses out to us
 */
static int send_buddy_status(void *userdata, int cols, char *val[], char *col[])
{
	unsigned long uid;
	struct pt_packet *pkt = NULL;
	struct pt_context *ctx = userdata, *buddy;
	(void)cols;
	(void)col;

	if ((buddy = ht_get_ptr_nc(uid_to_context, val[0])))
		pkt = mk_statuschange(ctx, buddy->uid, buddy->status, buddy->user.crown_level, buddy->status_msg);
	else {
		uid = strtoul(val[0], NULL, 10);
		pkt = mk_statuschange(
			ctx, uid,
			i_blocked_user(ctx, uid) ? STATUS_BLOCKED : STATUS_OFFLINE,
			0, NULL
		);
	}

	send_packet(ctx, pkt);
	return 0;
}

/**
 * Send the buddy or block list
 */
void send_buddy_list(struct pt_context *ctx, int blocked)
{
	char *s = NULL, buf[256];
	static const char * const lists[2] = { "buddylist", "blocklist" };

	/* Buddy List  */
	sprintf(buf,
	        "SELECT users.uid,%s,first,last,email,"
	        "verified,paid1,admin,sup FROM %s JOIN users ON "
	         "users.uid=%s.buddy WHERE %s.uid=%ld",
	         blocked ? "nickname" : "display,nickname",
	         lists[blocked & 1], lists[blocked & 1], lists[blocked & 1],
	         ctx->uid);
	if (!db_exec(db_w, &s, buf, db_row_to_record) && s) {
		send_packet(ctx, new_packet(
			blocked ? PACKET_BLOCKED_BUDDIES : PACKET_BUDDY_LIST,
			strlen(s), s, 0)
		);
	} else free(s);

	/* Buddy statuses (in/out) */
	if (!blocked) {
		buddy_statuses(ctx);
		broadcast_status(ctx);
	}
}

/**
 * Send our status to our buddies
 */
void broadcast_status(struct pt_context *ctx)
{
	char buf[64];
	sprintf(buf, "SELECT buddy FROM buddylist WHERE uid=%ld", ctx->uid);
	db_exec(ctx->db_r, ctx, buf, do_broadcast_status);
	send_packet(ctx, mk_statuschange(ctx, ctx->uid, ctx->status, ctx->user.crown_level, ctx->status_msg));
}

/**
 * Recieve our buddies' statuses
 */
void buddy_statuses(struct pt_context *ctx)
{
	char buf[64];
	sprintf(buf, "SELECT buddy FROM buddylist WHERE uid=%ld", ctx->uid);
	db_exec(ctx->db_r, ctx, buf, send_buddy_status);
}

/**
 * Set the display name for a buddy
 */
void set_buddy_display(struct pt_context *ctx, unsigned long uid, const char *disp)
{
	if (!set_disp_name) {
		set_disp_name = db_prepare(
			db_w,
			"UPDATE buddylist SET display=? WHERE uid=? AND buddy=?"
		);

		if (!set_disp_name)
			return;
	}

	if (disp && !strcmp(disp, "*default*"))
		disp = NULL;

	db_reset_prepared(set_disp_name);
	db_bind(set_disp_name, "tii", disp, ctx->uid, uid);
	db_do_prepared(set_disp_name);
}

/**
 * Add a buddy to \a ctx's buddylist
 */
void add_buddy(struct pt_context *ctx, unsigned long uid)
{
	if (!q_add_buddy) {
		q_add_buddy = db_prepare(
			db_w,
			"INSERT INTO buddylist(uid, buddy) VALUES(?, ?) "
			"ON CONFLICT DO NOTHING"
		);

		if (!q_add_buddy)
			return;
	}

	db_reset_prepared(q_add_buddy);
	db_bind(q_add_buddy, "ii", ctx->uid, uid);
	db_do_prepared(q_add_buddy);
}

/**
 * Remove a buddy from \a ctx's buddy list
 */
void remove_buddy(struct pt_context *ctx, unsigned long uid)
{
	if (!q_remove_buddy) {
		q_remove_buddy = db_prepare(
			db_w,
			"DELETE FROM buddylist WHERE uid=? AND buddy=?"
		);

		if (!q_remove_buddy)
			return;
	}

	db_reset_prepared(q_remove_buddy);
	db_bind(q_remove_buddy, "ii", ctx->uid, uid);
	db_do_prepared(q_remove_buddy);
}

/**
 * Add a buddy to \a ctx's blocklist
 */
void block_buddy(struct pt_context *ctx, unsigned long uid)
{
	if (!q_block_buddy) {
		q_block_buddy = db_prepare(
			db_w,
			"INSERT INTO blocklist(uid, buddy) VALUES(?, ?) "
			"ON CONFLICT DO NOTHING"
		);

		if (!q_block_buddy)
			return;
	}

	db_reset_prepared(q_block_buddy);
	db_bind(q_block_buddy, "ii", ctx->uid, uid);
	db_do_prepared(q_block_buddy);
}

/**
 * Remove a buddy from \a ctx's blocklist
 */
void unblock_buddy(struct pt_context *ctx, unsigned long uid)
{
	if (!q_unblock_buddy) {
		q_unblock_buddy = db_prepare(
			db_w,
			"DELETE FROM blocklist WHERE uid=? AND buddy=?"
		);

		if (!q_unblock_buddy)
			return;
	}

	db_reset_prepared(q_unblock_buddy);
	db_bind(q_unblock_buddy, "ii", ctx->uid, uid);
	db_do_prepared(q_unblock_buddy);
}

/**
 * Non-zero if \a ctx is on the given user's blocklist
 */
int user_blocked_me(struct pt_context *ctx, unsigned long uid)
{
	if (!blocked_user) {
		blocked_user = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM blocklist WHERE uid=? AND buddy=?"
		);

		if (!blocked_user)
			return 0;
	}

	db_reset_prepared(blocked_user);
	db_bind(blocked_user, "ii", uid, ctx->uid);
	return !!db_get_count(blocked_user);
}

/**
 * Non-zero if the given user is on \a ctx's blocklist
 */
int i_blocked_user(struct pt_context *ctx, unsigned long uid)
{
	if (!blocked_user) {
		blocked_user = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM blocklist WHERE uid=? AND buddy=?"
		);

		if (!blocked_user)
			return 0;
	}

	db_reset_prepared(blocked_user);
	db_bind(blocked_user, "ii", ctx->uid, uid);
	return !!db_get_count(blocked_user);
}

/**
 * Non-zero if the given user in on \a ctx's buddylist
 */
int is_buddy(struct pt_context *ctx, unsigned long uid)
{
	if (!user_is_buddy) {
		user_is_buddy = db_prepare(
			db_w,
			"SELECT COUNT(*) FROM buddylist WHERE uid=? AND buddy=?"
		);

		if (!user_is_buddy)
			return 0;
	}

	db_reset_prepared(user_is_buddy);
	db_bind(user_is_buddy, "ii", ctx->uid, uid);
	return !!db_get_count(user_is_buddy);
}

