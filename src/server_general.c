#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "logging.h"
#include "encode.h"
#include "hash.h"
#include "packet.h"
#include "protocol.h"
#include "database.h"
#include "room.h"
#include "buddylist.h"
#include "server_handler.h"

/* from server.c */
extern struct ht *uid_to_context;

/* Prepared queries on db_w */
static void *offline_msg;

#define SUCCESS_LEN            7
#define NXUSER_LEN            12
#define CANT_BLOCK_ADMINS_LEN 40
static const char * const success           = "Success";
static const char * const nxuser            = "No such user";
static const char * const cant_block_admins = "You can't block staff or administrators";

/**
 * Non-zero if the given user exists, and isn't blocking us, or blocked by us
 */
static int can_send_to_user(struct pt_context *ctx, unsigned long uid)
{
	if (!user_exists(ctx->db_r, uid)) {
		send_return_code(ctx, 0x63, nxuser, NXUSER_LEN);
		return 0;
	}

	return !(i_blocked_user(ctx, uid) | user_blocked_me(ctx, uid));
}

static void store_offline_message(struct pt_context *ctx, unsigned long uid, const char *msg)
{
	if (!offline_msg) {
		offline_msg = db_prepare(
			ctx->db_w,
			"INSERT INTO offline_messages(from_uid, to_uid, "
			"tstamp, msg) VALUES(?, ?, datetime('now','subsec'), "
			"?) ON CONFLICT DO NOTHING"
		);

		if (!offline_msg) {
			ERROR(("store_offline_message: Failed to prepare query"));
			return;
		}
	}

	db_reset_prepared(offline_msg);
	db_bind(offline_msg, "iit", ctx->uid, uid, msg);
	db_do_prepared(offline_msg);
}

/**
 * Send offline messages to the connected user
 */
static int relay_offline_message(void *userdata, int cols, char *val[], char *col[])
{
	char *s;
	size_t slen;
	unsigned long from_uid;
	struct pt_context *ctx = userdata;
	(void)col;

	if (!userdata || cols != 3 || !val[0] || !val[1] || !val[2])
		return 0;

	/* If we've blocked them, ignore offline messages */
	if (i_blocked_user(ctx, atol(val[0])))
		return 0;

	slen = 14 + strlen(val[1]) + strlen(val[2]);
	if (!(s = calloc(slen + 1, 1)))
		return 0;

	from_uid = atol(val[0]);
	s[0] = (from_uid >> 24) & 0xff;
	s[1] = (from_uid >> 16) & 0xff;
	s[2] = (from_uid >> 8)  & 0xff;
	s[3] = from_uid & 0xff;
	sprintf(s + 4, "<<(%s UTC)>>%s", val[1], val[2]);
	send_packet(ctx, new_packet(PACKET_IM_IN, slen, s, 0));
	return 0;
}

/**
 * PT 7+: Send globals statistics about the number of users/rooms
 */
static int send_global_numbers(void *userdata, int cols, char *val[], char *col[])
{
	char buf[8];
	long users = 0, rooms = 0;
	struct pt_context *ctx = userdata;
	(void)col;

	if (!ctx || cols != 2)
		return 0;

	users = atol(val[0]);
	rooms = atol(val[1]);
	buf[0] = (users >> 24) & 0xff;
	buf[1] = (users >> 16) & 0xff;
	buf[2] = (users >> 8)  & 0xff;
	buf[3] = users & 0xff;
	buf[4] = (rooms >> 24) & 0xff;
	buf[5] = (rooms >> 16) & 0xff;
	buf[6] = (rooms >> 8)  & 0xff;
	buf[7] = rooms & 0xff;
	send_packet(ctx, new_packet(PACKET_GLOBAL_NUMBERS, 8, buf, PACKET_F_COPY));
	return 0;
}

/**
 * Transition from another flow to the general flow
 */
void general_transition(struct pt_context *ctx)
{
	char buf[1024]/*256] */, *s, *s2;

	/****
	 * Send USER_DATA
	 *
	 * PT5 requires: ei, get_offers_from_affiliates, privacy, random, smtp
	 */
	sprintf(buf, "%u", ctx->server_ip);
	s = pt_encode(ctx, 1, buf);

	/* Add ei= */
	s2 = append_field(user_to_record(&ctx->user, ctx->pkt_in.version), "ei", s);
	free(s);

	/* Add smtp= */
	/* TODO: smtp support */
	s = pt_encode_with_challenge(ctx, 2, 0x19, "127.0.0.1:25:user:pass");
	s2 = append_field(s2, "smtp", s);
	free(s);
	send_packet(ctx, new_packet(PACKET_USER_DATA, strlen(s2), s2, 0));

	/* Max out the banner refresh interval */
	buf[0] = (char)0x7f;
	buf[1] = (char)0xff;
	buf[2] = 'C'; /* IM Windows */
	send_packet(ctx, new_packet(PACKET_BANNER_INTERVAL, 3, buf, PACKET_F_COPY));
	buf[2] = 'G'; /* Room Windows */
	send_packet(ctx, new_packet(PACKET_BANNER_INTERVAL, 3, buf, PACKET_F_COPY));

	/**
	 * Category list
	 */
	/* 5.1 assumes these don't change once given, and needs list=2  */
	s = NULL;
	buf[0] = '\0';
	strcpy(buf, "SELECT * FROM categories JOIN (SELECT 2 AS list)");

	/**
	 * We include these so that the theoretical 5.x user can view them
	 * also.
	 */
	if (ctx->protocol_version >= PROTOCOL_VERSION_70) {
		sprintf(buf + strlen(buf),
	        " WHERE code NOT IN (%d,%d)", CATEGORY_TOP, CATEGORY_FEATURED);
	}

	if (!db_exec(ctx->db_r, &s, buf, db_row_to_record) && s)
		send_packet(ctx, new_packet(PACKET_CATEGORY_LIST, strlen(s), s, 0));
	else free(s);

	/**
	 * Subcategory list
	 */
	if (ctx->protocol_version >= PROTOCOL_VERSION_82) {
		strcpy(buf, "SELECT catg, subcatg, disp, name FROM subcategories "
		            "ORDER BY name ASC");
		if (!db_exec(ctx->db_r, &s, buf, db_row_to_record) && s)
			send_packet(ctx, new_packet(PACKET_SUBCATEGORY_LIST, strlen(s), s, 0));
	}

	/**
	 * Buddylist and Blocklist (TODO: 9.1 crashes when getting STATUSCHANGE)
	 */
	send_buddy_list(ctx, 0);
	send_buddy_list(ctx, 1);

	/**
	 * Relay offline messages
	 */
	sprintf(buf, "SELECT from_uid, tstamp, msg FROM offline_messages WHERE to_uid=%ld", ctx->uid);
	if (!db_exec(ctx->db_r, ctx, buf, relay_offline_message)) {
		sprintf(buf, "DELETE FROM offline_messages WHERE to_uid=%ld", ctx->uid);
		db_exec(ctx->db_w, NULL, buf, NULL);
	}
}

void general_flow(struct pt_context *ctx)
{
	char buf[256], *s, *s2;
	size_t len;
	unsigned long uid = 0, rid;
	struct pt_context *target;
	struct pt_packet *pkt;

	if (ctx->pkt_in.length >= 4) {
		uid = ((ctx->pkt_in.data[0] & 0xff) << 24) |
			  ((ctx->pkt_in.data[1] & 0xff) << 16) |
			  ((ctx->pkt_in.data[2] & 0xff) <<  8) |
			   (ctx->pkt_in.data[3] & 0xff);
	}

	switch (ctx->pkt_in.type) {
	case PACKET_PING:
		/**
		 * [PT 9.1] Data contains a 32-bit timestamp [from time(NULL)]
		 *
		 * The client uses this to detect whether or not it can still
		 * send on the socket.
		 */
		ctx->time = uid;
		break;
	case PACKET_SET_PRIVACY:
		/**
		 * Set the user's privacy setting
		 *
		 * 'A' - All users can contact me
		 * 'T' - Only buddies can send me file transfers
		 * 'P' - Only buddies can contact me
		 */
		buf[1] = '\0';
		buf[0] = ctx->pkt_in.data[0];
		if (buf[0] != 'A' && buf[0] != 'T' && buf[0] != 'P')
			break;
		free(ctx->user.privacy);
		ctx->user.privacy = strdup(buf);
		user_set_privacy(ctx->db_w, ctx->uid, buf[0]);
		/* FALLTHRU */
	case PACKET_GET_PRIVACY:
		buf[0] = *ctx->user.privacy;
		send_packet(ctx, new_packet(PACKET_VERIFY_PRIVACY, 1, buf, PACKET_F_COPY));
		break;
	case PACKET_LIST_CATEGORY:
		/**
		 * Data:
		 *   0 - 3: PT5: 00 00 00 01, PT7: value from a stackframe or two ago.
		 *   4 - 7: PT5: 00 00 00 00 [1 if a category id is given], PT 7/8: 00 00 00 01
		 *   8 - 11: category id (or 00000000 / ffffffff)
		 */
	case PACKET_NEW_LIST_CATEGORY:
		/**
		 * PT8+: Simplification of LIST_CATEGORY
		 *
		 * Data:
		 *   0 - 4: category_id (or ffffffff)
		 */
		s = NULL;
		*buf = '\0';
		if (ctx->pkt_in.type == PACKET_LIST_CATEGORY) {
			rid = ((ctx->pkt_in.data[8]  & 0xff) << 24) |
			      ((ctx->pkt_in.data[9]  & 0xff) << 16) |
			      ((ctx->pkt_in.data[10] & 0xff) <<  8) |
			       (ctx->pkt_in.data[11] & 0xff);
		} else rid = uid;

		if (!rid || rid == ALL_CATEGORIES) {
			if ((s = room_counts_by_category(ctx->db_r))) {
				pkt = new_packet(PACKET_CATEGORY_COUNTS, strlen(s), s, 0);
				send_packet(ctx, pkt);
			}

			break;
		}

		if ((s = rooms_for_category(ctx->db_r, ctx->protocol_version, rid))) {
			send_packet(ctx, new_packet(
				(ctx->protocol_version >= PROTOCOL_VERSION_82 &&
				 rid != CATEGORY_FEATURED && rid != CATEGORY_TOP) ?
				PACKET_NEW_ROOM_LIST : PACKET_ROOM_LIST,
				strlen(s), s, 0
			));
		}
		break;
	case PACKET_LIST_SUBCATEGORY:
		/**
		 * PT 8.2+: List rooms for a subcategory
		 *
		 * Data:
		 *   0 - 3: Category id
		 *   4 - 7: Subcategory id
		 */
		rid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);
		if ((s = rooms_for_subcategory(ctx->db_r, uid, rid)))
			send_packet(ctx, new_packet(PACKET_SUBCATEGORY_ROOM_LIST, strlen(s), s, 0));
		break;
	case PACKET_SEND_GLOBAL_NUMBERS:
		/**
	 	 * PT7+ Global stats: "x users are now in y groups!"
	 	 */
		db_exec(
			ctx->db_w, ctx,
			"SELECT COUNT(DISTINCT uid), COUNT(DISTINCT id) FROM room_users",
			send_global_numbers
		);
		break;
	case PACKET_CHANGE_STATUS:
		/**
		 * Data: status (32 bits)
		 *
		 * PT 8.2 has an optional status message following the status.
		 * PT 9.1 always includes the status message, with a preceeding byte.
		 *        TODO: figure out what that preceeding byte is.
		 */
		ctx->status = uid;
		if (ctx->pkt_in.version >= PROTOCOL_VERSION_82) {
			if (ctx->status_msg) {
				free(ctx->status_msg);
				ctx->status_msg = NULL;
			}

			rid = 4 + (ctx->pkt_in.version >= PROTOCOL_VERSION_91);
			if (ctx->pkt_in.length > rid) {
				len = min(STATUSMSG_MAX, ctx->pkt_in.length - rid);
				if (!(ctx->status_msg = calloc(len + 1, 1)))
					abort();
				memcpy(ctx->status_msg, ctx->pkt_in.data + rid, len);
			}
		}

		broadcast_status(ctx);
		break;
	case PACKET_SET_DISPLAYNAME:
		/**
		 * Data:
		 *   0 - 3: uid (32 bits)
		 *   4 - *: Display name
		 *
		 * I'm surprised the length isn't limited client-side.
		 */
		ctx->pkt_in.data[4 + min(NICKNAME_MAX, ctx->pkt_in.length - 4)] = '\0';
		set_buddy_display(ctx, uid, ctx->pkt_in.data + 4);
		break;
	case PACKET_ADD_BUDDY:
		/**
		 * Data: uid (32 bits)
		 *
		 * Response:
		 *   (entire buddy list)
		 */
		if (!can_send_to_user(ctx, uid))
			break;
		add_buddy(ctx, uid);
		send_buddy_list(ctx, 0);
		break;
	case PACKET_REMOVE_BUDDY:
		/**
		 * Data: uid (32 bits)
		 *
		 * Response:
		 *   0 - 4: UID of removed buddy
		 */
		remove_buddy(ctx, uid);
		uid = htonl(uid);
		pkt = new_packet(PACKET_BUDDY_REMOVED, 4, (void *)&uid, PACKET_F_COPY);
		send_packet(ctx, pkt);
		break;
	case PACKET_BLOCK_BUDDY:
		/**
		 * Data: uid (32 bits)
		 *
		 * Response:
		 *   0 - 4: UID of blocked user
		 *   5 - 6: Disposition (0 = unblocked, 1 = blocked)
		 *   7 - *: Message ("Success" or error message)
		 */
		memset(buf, 0, 14);
		memcpy(buf, ctx->pkt_in.data, 4);
		buf[5] = 1;

		if (!user_exists(ctx->db_r, uid)) {
			memcpy(buf + 6, nxuser, NXUSER_LEN);
			pkt = new_packet(PACKET_BLOCK_RESPONSE, 6 + NXUSER_LEN,
			                 buf, PACKET_F_COPY);
			send_packet(ctx, pkt);
			break;
		}

		if (user_is_staff(ctx->db_r, uid)) {
			memcpy(buf + 6, cant_block_admins, CANT_BLOCK_ADMINS_LEN);
			pkt = new_packet(PACKET_BLOCK_RESPONSE,
			                 6 + CANT_BLOCK_ADMINS_LEN, buf, PACKET_F_COPY);
			send_packet(ctx, pkt);
			break;
		}

		block_buddy(ctx, uid);
		memcpy(buf + 6, success, SUCCESS_LEN);
		pkt = new_packet(PACKET_BLOCK_RESPONSE,
		                 6 + SUCCESS_LEN, buf, PACKET_F_COPY);
		send_packet(ctx, pkt);

		/* In case they're still in the buddylist */
		buf[0] = (uid >> 24) & 0xff;
		buf[1] = (uid >> 16) & 0xff;
		buf[2] = (uid >> 8)  & 0xff;
		buf[3] = uid & 0xff;
		buf[4] = (char)((STATUS_BLOCKED >> 24) & 0xff);
		buf[5] = (char)((STATUS_BLOCKED >> 16) & 0xff);
		buf[6] = (char)((STATUS_BLOCKED >> 8) & 0xff);
		buf[7] = (char)(STATUS_BLOCKED & 0xff);

		pkt = new_packet(PACKET_BUDDY_STATUSCHANGE, 8, buf, PACKET_F_COPY);
		send_packet(ctx, pkt);
		break;
	case PACKET_UNBLOCK_BUDDY:
		/**
		 * Data: uid (32 bits)
		 *
		 * Response:
		 *   0 - 4: UID of unblocked user
		 *   5 - 6: Disposition (0 = unblocked, 1 = blocked)
		 *   7 - *: Message ("Success" or error message)
		 */
		unblock_buddy(ctx, uid);
		memset(buf, 0, 14);
		memcpy(buf, ctx->pkt_in.data, 4);
		memcpy(buf + 6, success, SUCCESS_LEN);
		send_packet(ctx, new_packet(PACKET_BLOCK_RESPONSE, 6 + SUCCESS_LEN, buf, PACKET_F_COPY));
		send_buddy_list(ctx, 0);
		break;
	case PACKET_SEARCH_USER:
		/**
		 * Data:
		 *   PT5: Only nickname/exnick is used by the form.
		 *     uid=(my uid)
		 *     first=
		 *     last=
		 *     nickname=
		 *     exnick=
		 *     email=
		 *
		 *   PT7: search term (i.e. nickname=... or email=...)
		 */
		if (ctx->protocol_version < PROTOCOL_VERSION_70) {
			if ((s = strstr(ctx->pkt_in.data, "exnick="))) /* nickname (exact) */
				s = search_users(ctx->db_r, "xnickname", strtok(s + 7, "\n"));
			else if ((s = strstr(ctx->pkt_in.data, "nickname="))) /* nickname starts with */
				s = search_users(ctx->db_r, "pnickname", strtok(s + 9, "\n"));
		} else {
			if (!(s = strtok(ctx->pkt_in.data, "=")))
				break;

			if (strcmp(s, "nickname") && strcmp(s, "email")) {
				WARN(("Unknown user search term: %s", s));
				break;
			}

			sprintf(buf, "p%s", s);
			s = search_users(ctx->db_r, buf, strtok(NULL, "\n"));
		}

		if (s) {
			send_packet(ctx, new_packet(
				PACKET_SEARCH_RESULTS, strlen(s), s, 0
			));
		}

		break;
	case PACKET_SEARCH_ROOM:
		/**
		 * PT 7+: Search for partial matches in room names
		 *
		 * Data:
		 *   Search term (text)
		 *
		 * Response:
		 *   0 - 1: Count of records + 1
		 *   2 - *: Records of: rating, nm, id, v, l
		 */
		if (!(s = calloc(ctx->pkt_in.length + 3, 1)))
			abort();

		s[0] = '%';
		memcpy(s + 1, ctx->pkt_in.data, ctx->pkt_in.length);
		s[ctx->pkt_in.length + 1] = '%';
		if (!(s2 = search_rooms(ctx->db_w, ctx->protocol_version, s))) {
			free(s);
			if (!(s = calloc(2, 1)))
				abort();
			send_packet(ctx, new_packet(PACKET_ROOM_SEARCH_RESULTS, 2, s, 0));
			break;
		}

		free(s);
		for (len = 0, s = s2; *s; s++)
			len += *(unsigned char *)s == 0xc8;

		s = malloc(3 + strlen(s2));
		memcpy(s + 2, s2, strlen(s2));
		s[0] = (len >> 8) & 0xff;
		s[1] = len & 0xff;
		send_packet(ctx, new_packet(PACKET_ROOM_SEARCH_RESULTS, strlen(s2) + 2, s, 0));
		free(s2);
		break;
	case PACKET_IM_OUT:
		/**
		 * Data:
		 *   0 - 3: Recipient UID (32 bits)
		 *   4 - *: Message
		 */

		if (!can_send_to_user(ctx, uid))
			break;

		if (!(target = ht_get_ptr_nc(uid_to_context, buf))) {
			store_offline_message(ctx, uid, ctx->pkt_in.data + 4);
			break;
		}

		ctx->pkt_in.data[0] = (ctx->uid >> 24) & 0xff;
		ctx->pkt_in.data[1] = (ctx->uid >> 16) & 0xff;
		ctx->pkt_in.data[2] = (ctx->uid >> 8)  & 0xff;
		ctx->pkt_in.data[3] = ctx->uid & 0xff;
		send_packet(target, new_packet(
			PACKET_IM_IN, ctx->pkt_in.length, ctx->pkt_in.data, 0
		));
		ctx->pkt_in.length = 0;
		break;
	case PACKET_ROOM_MESSAGE_OUT:
		/**
		 * Data:
		 *   0 - 3: Room id (32 bits)
		 *   4 - *: Message
		 *
		 * Response:
		 *   0 - 3: Room id (32 bits)
		 *   4 - 7: Sender uid (32 bits)
		 *   8 - *: Message
		 */
		if (room_command(ctx, uid, ctx->pkt_in.data + 4)) break;
		if (user_is_invisible(ctx, uid, ctx->uid))        break;

		/**
		 * TODO: if text is reddotted at the room level, ignore any
		 * messages from non-admins
		 */

		if (!(s = malloc(ctx->pkt_in.length + 4)))
			abort();

		memcpy(s, ctx->pkt_in.data, 4);
		s[4] = (ctx->uid >> 24) & 0xff;
		s[5] = (ctx->uid >> 16) & 0xff;
		s[6] = (ctx->uid >> 8)  & 0xff;
		s[7] = ctx->uid & 0xff;

		memcpy(s + 8, ctx->pkt_in.data + 4, ctx->pkt_in.length - 4);
		broadcast_to_room(ctx, uid, new_packet(
			PACKET_ROOM_MESSAGE_IN, ctx->pkt_in.length + 4, s, 0
		));
		break;
	case PACKET_NUDGE_OUT:
		/**
		 * [PT 8] Seems like a terribly annoying feature...
		 * [PT 9] Room nudges were removed from the UI, understandably.
		 *
		 * Data:
		 *   0 - 3: uid (32 bits) [IM] or 00 00 00 00 [Room]
		 *   4 - 7: room id (32 bits) [Room] or 00 00 00 00 [IM]
		 *   8 - 11: Nudge type (1=car horn, 2=fog horn, 3=monkey)
		 */
		rid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);

		/* The first three dwords mirror the input packet */
		memcpy(buf, ctx->pkt_in.data, 12);
		memset(buf + 4, 0, 4);

		/* 4th dword: Sender uid */
		buf[12] = (ctx->uid >> 24) & 0xff;
		buf[13] = (ctx->uid >> 16) & 0xff;
		buf[14] = (ctx->uid >> 8)  & 0xff;
		buf[15] = ctx->uid & 0xff;

		if (uid) {
			if (!can_send_to_user(ctx, uid))
				break;

			sprintf(buf, "%ld", uid);
			if (!(target = ht_get_ptr_nc(uid_to_context, buf)))
				break;

			if (target == ctx || target->protocol_version < PROTOCOL_VERSION_82)
				break;

			send_packet(target, new_packet(PACKET_NUDGE_IN, 16, buf, PACKET_F_COPY));
		} else if (rid) {
			/* TODO: Make sure the target room user isn't ignoring the sender */
			broadcast_to_room(ctx, rid, new_packet(PACKET_NUDGE_IN, 16, buf, PACKET_F_COPY));
		}
		break;
	case PACKET_ROOM_CREATE:
		break;
	case PACKET_ROOM_CLOSE:
		break;
	case PACKET_ROOM_JOIN:
	case PACKET_ROOM_JOIN_AS_ADMIN:
		/**
		 * Data:
		 *   0 - 3: room id
		 *   4 - 7: admin code (0 if none)
		 *   8 - 9: 0x082a (default incoming udp voice port)
		 */
		break;
	case PACKET_ROOM_LEAVE:
		/**
		 * Data: room id
		 *
		 * Response:
		 *   0 - 3: room id
		 *   4 - 7: user id
		 */
		memcpy(buf, ctx->pkt_in.data, 4);
		buf[4] = (ctx->uid >> 24) & 0xff;
		buf[5] = (ctx->uid >> 16) & 0xff;
		buf[6] = (ctx->uid >> 8)  & 0xff;
		buf[7] = ctx->uid & 0xff;
		broadcast_to_room(ctx, uid, new_packet(PACKET_ROOM_USER_LEFT, 8, buf, PACKET_F_COPY));
		sprintf(buf, "DELETE FROM room_users WHERE id=%ld AND uid=%ld", uid, ctx->uid);
		db_exec(ctx->db_w, NULL, buf, NULL);
		break;
	case PACKET_ROOM_GET_ADMIN_INFO:
		/**
		 * Data: room id
		 *
		 * Response:
		 *   group=int\n
		 *   mike=int\n   -- 1 if new users get mic privs, 0 otherwise
		 *   text=int\n   -- 1 if text is reddotted, 0 otherwise
		 *   video=int\n  -- 1 if video is reddotted, 0 otherwise
		 *   bounce=\n \n \n \n \xc8 -- list of user ids, \n delimited
		 *   ban=\n \n \n \n \n \xc8 -- list of user ids, \n delimited
		 */
		if ((s = get_admin_info(ctx, uid)))
			send_packet(ctx, new_packet(PACKET_ROOM_ADMIN_INFO, strlen(s), s, 0));
		break;
	case PACKET_ROOM_MUTE:
		/**
		 * Data:
		 *   0 - 3: room id
		 *   4 - 5: 00 00 - off, 00 01 - on
		 *
		 * Response:
		 *   0 - 3: room id
		 *   4 - 7: uid
		 *   8 - 9: 00 00 - off, 00 01 - on
		 */
		memcpy(buf, ctx->pkt_in.data, 4);
		buf[4] = (ctx->uid >> 24) & 0xff;
		buf[5] = (ctx->uid >> 16) & 0xff;
		buf[6] = (ctx->uid >> 8)  & 0xff;
		buf[7] = ctx->uid & 0xff;
		buf[8] = '\0';
		buf[9] = !!(ctx->pkt_in.data[4] | ctx->pkt_in.data[5]);
		pkt = new_packet(PACKET_ROOM_USER_MUTE, 10, buf, PACKET_F_COPY);
		broadcast_to_room(ctx, uid, pkt);
		break;
	case PACKET_ROOM_REDDOT_USER:
	case PACKET_ROOM_UNREDDOT_USER:
		/**
		 * Data:
		 *   0 - 4: room id
		 *   5 - 8: target user id
		 *
		 * Response: room id, uid
		 */
		rid = uid;
		uid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);

		reddot_user(ctx, rid, uid, ctx->pkt_in.type == PACKET_ROOM_REDDOT_USER);
		break;
	case PACKET_ROOM_HAND_UP:
	case PACKET_ROOM_HAND_DOWN:
		/**
		 * Data: room id
		 *
		 * Response: room id, uid
		 */
		raise_hand(ctx, uid, ctx->pkt_in.type == PACKET_ROOM_HAND_UP);
		break;
	case PACKET_ROOM_SET_ALL_MICS:
		/**
		 * Data:
		 *   0 - 3: room id
		 *   4 - 5: 00 00 - off, 00 01 - on
		 *
		 * Response:
		 *   Appends the sender's uid
		 */
		set_all_mics(ctx, uid, ctx->pkt_in.data[4] | ctx->pkt_in.data[5]);
		break;
	case PACKET_ROOM_LOWER_ALL_HANDS:
		/**
		 * Data: room id
		 */
		lower_all_hands(ctx, uid);
		break;
	case PACKET_ROOM_SET_TOPIC:
		/**
		 * Data: room id, topic
		 */
		room_topic(ctx, uid, ctx->pkt_in.data + 4);
		break;
	case PACKET_ROOM_BAN_USER:
		/**
		 * Data: room id, uid
		 */
		rid = uid;
		uid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);

		ban_user(ctx, rid, uid);
		break;
	case PACKET_ROOM_UNBAN_USER:
		/**
		 * Data: room id, uid
		 */
		rid = uid;
		uid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);

		unban_user(ctx, rid, uid);
		break;
	case PACKET_ROOM_BOUNCE_USER:
	case PACKET_ROOM_BOUNCE_REASON:
		/**
		 * Data: room id, uid, [reason]
		 */
		rid = uid;
		uid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);

		s = ctx->pkt_in.length > 8 ? ctx->pkt_in.data + 8 : NULL;
		bounce_user(ctx, rid, uid, s);
		break;
	case PACKET_ROOM_UNBOUNCE_USER:
		rid = uid;
		uid = ((ctx->pkt_in.data[4] & 0xff) << 24) |
			  ((ctx->pkt_in.data[5] & 0xff) << 16) |
			  ((ctx->pkt_in.data[6] & 0xff) <<  8) |
			   (ctx->pkt_in.data[7] & 0xff);

		unbounce_user(ctx, rid, uid);
		break;
	case PACKET_ROOM_NEW_USER_MIC:
		/**
		 * Data:
		 *   0 - 3: room id
		 *   4 - 5: 00 00 - off, 00 01 - on
		 */
		new_user_mic(ctx, uid, ctx->pkt_in.data[4] | ctx->pkt_in.data[5]);
		break;
	case PACKET_ROOM_REDDOT_TEXT:
		/**
		 * Data:
		 *   0 - 3: room id
		 *   4 - 5: 00 00 - off, 00 01 - on
		 */
		reddot_text(ctx, uid, ctx->pkt_in.data[4] | ctx->pkt_in.data[5]);
		break;
	case PACKET_ROOM_REDDOT_VIDEO:
		/**
		 * Data:
		 *   0 - 3: room id
		 *   4 - 5: 00 00 - off, 00 01 - on
		 */
		reddot_video(ctx, uid, ctx->pkt_in.data[4] | ctx->pkt_in.data[5]);
		break;

	/**
	 * Ignored packets - placed here in this manner to document their
	 * contents.
	 */
	case PACKET_COMMENCING_AUTOJOIN:
		/**
		 * [PT 7/8] 0-length, sent in response to LOGIN_SUCCESS, after
		 * UID_FONTDEPTH_ETC and immediately before doing the initial
		 * room autojoin.
		 */
	case PACKET_NEW_CHECKSUMS:
	case PACKET_CHECKSUMS:
		/**
		 * Sent in response to PACKET_USER_DATA
		 *
		 * Data:
		 *   \n delimited list of checksums for certain core PT files.
		 *   PT 5 and 7 send 6 of these, PT 8 sends 14.
		 *   PT 5 encodes these with variant 1 with a challenge key of 42,
		 *   PT 7 and 8 use variant 1.
		 */
	case PACKET_VERSION_INFO:
		/**
		 * PT 8: Sent in response to PACKET_USER_DATA
		 *
		 * Data:
		 *   A single COM-style number, hardcoded.
		 */
	case PACKET_PT5_BANNER_COUNTERS:
		/**
		 * Data:
		 *   0  -  3: 00 00 00 01 (constant)
		 *   4  -  7: counter 1
		 *   8  - 11: counter 2
		 *   12 - 15: counter 3
		 */
	case PACKET_INCOMPATIBLE_3P_APP:
		/**
		 * Data:
		 *   Pattern matched (from bep/bwp in USER_DATA)
		 */
	case PACKET_USER_FUCKER_STATUS:
		/**
		 * Data:
		 *   Status code (16 bits)
		 *
		 * After getting PREPARE_USER_FUCKER, the client must receive
		 * FUCK_USER within 60 seconds in order for the client to
		 * carry on with its malicious designs.
		 *
		 * 0 - Mission complete
		 * 1 - [Forced Shutdown mode] Haven't received PEPARE_USER_FUCKER
		 * 2 - [Forced Shutdown mode] More than 60 seconds elapsed
		 * 3 - [Forced Shutdown mode] Target uid doesn't match ours
		 * 4 - [Heap Exhaustion mode] Haven't received PREPARE_USER_FUCKER
		 * 5 - [Heap Exhaustion mode] More than 60 seconds elapsed
		 * 6 - [Heap Exhaustion mode] Target uid doesn't match ours
		 */
	case PACKET_CLIENT_HELLO:
		break;
	default:
		ERROR(("general: unexpected packet"));
#ifdef NDEBUG
		dump_packet(0, &ctx->pkt_in);
#endif
	}
}
