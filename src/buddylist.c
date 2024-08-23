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

#include "macros.h"
#include "hash.h"
#include "database.h"
#include "protocol.h"
#include "packet.h"
#include "logging.h"
#include "buddylist.h"

/* Prepared queries on db_w */
static void *q_add_buddy;
static void *q_remove_buddy;
static void *q_block_buddy;
static void *q_unblock_buddy;
static void *blocked_user;
static void *set_disp_name;

/* from server.c */
extern struct ht *uid_to_context;

/**
 * Send our status out to our buddies
 */
static int do_broadcast_status(void *userdata, int cols, char *val[], char *col[])
{
	char buf[64];
	void **ud = (void **)userdata;
	unsigned long uid;
	struct pt_context *ctx, *buddy;
	(void)cols;
	(void)col;

	if (!ud || !ud[0] || !ud[1])
		return 0;

	ctx = ud[0];
	uid = atol(val[0]);
	sprintf(buf, "%ld", uid);
	if (!(buddy = ht_get_ptr_nc(uid_to_context, buf)) ||
	    user_blocked_me(ctx, uid))
		return 0;

	send_packet(buddy, ud[1 + (buddy->protocol_version >= PROTOCOL_VERSION_82)]);
	return 0;
}

/**
 * Send our buddies' statuses out to us
 */
static int send_buddy_status(void *userdata, int cols, char *val[], char *col[])
{
	char buf[64], uid_str[12];
	size_t len = 8;
	unsigned long uid;
	struct pt_packet *pkt;
	struct pt_context *ctx = userdata, *buddy;
	(void)cols;
	(void)col;

	uid = atol(val[0]);
	sprintf(uid_str, "%ld", uid);
	buf[0] = (uid >> 24) & 0xff;
	buf[1] = (uid >> 16) & 0xff;
	buf[2] = (uid >> 8)  & 0xff;
	buf[3] = uid & 0xff;
	buf[4] = (char)((STATUS_OFFLINE >> 24) & 0xff);
	buf[5] = (char)((STATUS_OFFLINE >> 16) & 0xff);
	buf[6] = (char)((STATUS_OFFLINE >> 8) & 0xff);
	buf[7] = (char)(STATUS_OFFLINE & 0xff);

	if (i_blocked_user(ctx, uid)) {
		buf[4] = (char)((STATUS_BLOCKED >> 24) & 0xff);
		buf[5] = (char)((STATUS_BLOCKED >> 16) & 0xff);
		buf[6] = (char)((STATUS_BLOCKED >> 8) & 0xff);
		buf[7] = (char)(STATUS_BLOCKED & 0xff);
	} else if ((buddy = ht_get_ptr_nc(uid_to_context, uid_str))) {
		buf[4] = (char)((buddy->status >> 24) & 0xff);
		buf[5] = (char)((buddy->status >> 16) & 0xff);
		buf[6] = (char)((buddy->status >> 8) & 0xff);
		buf[7] = (char)(buddy->status & 0xff);

		if (buddy->status != STATUS_ONLINE &&
		    ctx->pkt_in.version >= PROTOCOL_VERSION_82 &&
		    buddy->status_msg) {
			len += min(STATUSMSG_MAX, strlen(buddy->status_msg));
			memcpy(buf + 8, buddy->status_msg, len - 8);
		}
	}

	pkt = new_packet(PACKET_BUDDY_STATUSCHANGE, len, buf, PACKET_F_COPY);
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
	if (!db_exec(ctx->db_w, &s, buf, db_row_to_record) && s) {
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
	char buf[max(64, 8 + STATUSMSG_MAX)];
	void *ud[3];
	size_t len = 8;

	buf[0] = (ctx->uid >> 24) & 0xff;
	buf[1] = (ctx->uid >> 16) & 0xff;
	buf[2] = (ctx->uid >> 8)  & 0xff;
	buf[3] = ctx->uid & 0xff;
	buf[4] = (ctx->status >> 24) & 0xff;
	buf[5] = (ctx->status >> 16) & 0xff;
	buf[6] = (ctx->status >> 8) & 0xff;
	buf[7] = ctx->status & 0xff;

	if (ctx->status != STATUS_ONLINE && ctx->status_msg) {
		len += min(STATUSMSG_MAX, strlen(ctx->status_msg));
		memcpy(buf + 8, ctx->status_msg, len - 8);
	}

	ud[0] = ctx;
	ud[1] = new_packet(PACKET_BUDDY_STATUSCHANGE, 8, buf, PACKET_F_COPY);
	ud[2] = new_packet(PACKET_BUDDY_STATUSCHANGE, len, buf, PACKET_F_COPY);
	sprintf(buf, "SELECT buddy FROM buddylist WHERE uid=%ld", ctx->uid);
	db_exec(ctx->db_r, ud, buf, do_broadcast_status);

	/* If these weren't used, free them instantly */
	free_packet(ud[1]);
	free_packet(ud[2]);
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
			ctx->db_w,
			"UPDATE buddylist SET display=? WHERE uid=? AND buddy=?"
		);

		if (!set_disp_name) {
			ERROR(("set_buddy_display: Failed to prepare query"));
			return;
		}
	}

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
			ctx->db_w,
			"INSERT INTO buddylist(uid, buddy) VALUES(?, ?) "
			"ON CONFLICT DO NOTHING"
		);

		if (!q_add_buddy) {
			ERROR(("add_buddy: Failed to prepare query"));
			return;
		}
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
			ctx->db_w,
			"DELETE FROM buddylist WHERE uid=? AND buddy=?"
		);

		if (!q_remove_buddy) {
			ERROR(("remove_buddy: Failed to prepare query"));
			return;
		}
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
			ctx->db_w,
			"INSERT INTO blocklist(uid, buddy) VALUES(?, ?) "
			"ON CONFLICT DO NOTHING"
		);

		if (!q_block_buddy) {
			ERROR(("block_buddy: Failed to prepare query"));
			return;
		}
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
			ctx->db_w,
			"DELETE FROM blocklist WHERE uid=? AND buddy=?"
		);

		if (!q_unblock_buddy) {
			ERROR(("unblock_buddy: Failed to prepare query"));
			return;
		}
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
	int ret = 0;

	if (!blocked_user) {
		blocked_user = db_prepare(
			ctx->db_w,
			"SELECT COUNT(*) FROM blocklist WHERE uid=? AND buddy=?"
		);

		if (!blocked_user) {
			ERROR(("user_blocked_me: Failed to prepare query"));
			return 0;
		}
	}

	db_reset_prepared(blocked_user);
	db_bind(blocked_user, "ii", uid, ctx->uid);
	ret = db_get_count(blocked_user);
	return !!ret;
}

/**
 * Non-zero if the given user is on \a ctx's blocklist
 */
int i_blocked_user(struct pt_context *ctx, unsigned long uid)
{
	int ret = 0;

	if (!blocked_user) {
		blocked_user = db_prepare(
			ctx->db_w,
			"SELECT COUNT(*) FROM blocklist WHERE uid=? AND buddy=?"
		);

		if (!blocked_user) {
			ERROR(("i_blocked_user: Failed to prepare query"));
			return 0;
		}
	}

	db_reset_prepared(blocked_user);
	db_bind(blocked_user, "ii", ctx->uid, uid);
	ret = db_get_count(blocked_user);
	return !!ret;
}

