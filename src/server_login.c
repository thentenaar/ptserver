#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "logging.h"
#include "packet.h"
#include "protocol.h"
#include "encode.h"
#include "hash.h"
#include "user.h"
#include "devicelist.h"
#include "server_handler.h"

#define HELLO_LEN        18
#define UNKNOWN_USER_LEN 12
#define MULTI_LOGIN_LEN  84
#define BAD_PASSWORD_LEN 38
static const char * const hello        = "Hello-From:PaLTaLK";
static const char * const unknown_user = "Unknown user";
static const char * const multi_login  = "You've logged in from another client, if it wasn't you, please change your password.";
static const char * const bad_password = "The password you entered is incorrect.";

/* from server.c */
extern struct ht *uid_to_context;

void login_transition(struct pt_context *ctx)
{
	send_packet(ctx, new_packet(PACKET_HELLO, 0, NULL, 0));
}

void login_flow(struct pt_context *ctx)
{
	char *buf = NULL;
	char *s;
	unsigned pass_ok;
	unsigned long uid = 0;
	size_t len;

	if (ctx->pkt_in.length >= 4) {
		uid = ((ctx->pkt_in.data[0] & 0xff) << 24) |
	  	  	  ((ctx->pkt_in.data[1] & 0xff) << 16) |
	  	  	  ((ctx->pkt_in.data[2] & 0xff) << 8)  |
	   	   	   (ctx->pkt_in.data[3] & 0xff);
	}

	switch (ctx->pkt_in.type) {
	case PACKET_OLD_CLIENT_HELLO:
		/**
		 * OBSOLETE: Data is simply the uid in network byte order, but
		 * 5.x sends GET_UID anyway and reconnects after UID_RESPONSE.
		 */
		ctx->uid = uid;
		ctx->protocol_version = ctx->pkt_in.version;
		break;
	case PACKET_CLIENT_HELLO:
		send_packet(ctx, new_packet(PACKET_HELLO, HELLO_LEN, hello, PACKET_F_STATIC));
		break;
	case PACKET_REGISTRATION:
	case PACKET_PT5_REGISTRATION:
		/**
		 * 5.1 reconnects before sending PT5_REGISTRATION, so
		 * we'll pretend we never left the registration flow.
		 */
		transition_to(ctx, registration_flow);
		if (ctx->pkt_in.type == PACKET_PT5_REGISTRATION)
			registration_flow(ctx);
		break;
	case PACKET_GET_UID:
		/**
		 * Data:
		 *   0 - 3: 00 00 00 01
		 *   4 - *: nickname
		 */
		ctx->protocol_version = ctx->pkt_in.version;

		/* Attempts to login as "newuser" trigger the registration flow */
		if (ctx->pkt_in.length == 11 && !memcmp(ctx->pkt_in.data + 4, "newuser", 7))
			ctx->uid = UID_NEWUSER;
		else ctx->uid = lookup_uid(ctx->db_r, ctx->pkt_in.data + 4);

		/* send PACKET_UID_RESPONSE */
		if (!(buf = malloc(20 + ctx->pkt_in.length)))
			goto oom;

		len = sprintf(buf, "uid=%ld\nnickname=", (long)ctx->uid);
		memcpy(buf + len, ctx->pkt_in.data + 4, ctx->pkt_in.length - 4);
		send_packet(ctx, new_packet(PACKET_UID_RESPONSE, len + ctx->pkt_in.length - 4, buf, 0));
		break;
	case PACKET_INITIAL_STATUS_2:
		/**
		 * [PT 7/8] Alternative to INITIAL_STATUS.
		 * Maybe as a guest user? Not sure how this gets triggered,
	 	 * so we'll otherwise ignore this until more is known about
	 	 * its intent.
	 	 *
	 	 * Data:
	 	 *   0 - 3: uid (32 bits)
	 	 *   4 - 7: status? (32-bits)
	 	 *   8 - 11: 00 00 00 01 (constant)
	 	 *   12 - *: unknown file checksum (v1 encoded)
	 	 */
	case PACKET_INITIAL_STATUS:
		/**
		 * Data:
		 *   0  -  3: uid (32 bits)
		 *   4  -  7: 00 00 00 01 (constant)
		 *   8  -  9: 00 00 [PT 7/8: 00 02] (5.1: value of notANewUser reg. entry)
		 *   10 - 13: 00 00 00 1e (Initial Status: Online/Away/DND/Invisible)
		 *   14 -  *: encoded fs serial (v1, challenge of uid % 0x37)
		 *
		 * This may also send a return_code.
		 */
		len = (ctx->pkt_in.type == PACKET_INITIAL_STATUS) ? 6 : 0;
		ctx->status = ((ctx->pkt_in.data[10 - len] & 0xff) << 24) |
	  	  	          ((ctx->pkt_in.data[11 - len] & 0xff) << 16) |
	  	  	          ((ctx->pkt_in.data[12 - len] & 0xff) << 8)  |
	   	   	           (ctx->pkt_in.data[13 - len] & 0xff);

		if (ctx->pkt_in.type == PACKET_INITIAL_STATUS)
			ctx->device_id = pt_decode_with_challenge(ctx, 1, ctx->uid % 0x37, ctx->pkt_in.data + 14);
		ctx->uid = uid;
		ctx->protocol_version = ctx->pkt_in.version;

		/* An error on INITIAL_STATUS causes 5.1 to exit (intentionally.) */
		if (lookup_user(ctx->db_r, ctx->uid, &ctx->user)) {
			ctx->pkt_in.type = PACKET_INITIAL_STATUS;
			send_return_code(ctx, 0, unknown_user, UNKNOWN_USER_LEN);
			break;
		}

		s = NULL;
		if (ctx->uid != UID_NEWUSER && !device_in_list(ctx))
			user_get_secret_question(ctx->db_r, ctx->uid, &s);

		if (ctx->pkt_in.version < PROTOCOL_VERSION_82) {
			/**
		 	 * Data [out]: PT 5.1 / 7.0
		 	 *   0 - 3  : ignored [PT7: these cannot be null bytes]
		 	 *   4 - x  : challenge (only first three digits used)
		 	 * Optional:
		 	 *   x+1    : "\n"
		 	 *   x+2 - *: Secret question prompt
		 	 */

		 	if (!(buf = malloc(8 + (s ? strlen(s) : 0))))
		 		goto oom;

		 	buf[0] = '0' + rand() % 10;
		 	buf[1] = '0' + rand() % 10;
		 	buf[2] = '0' + rand() % 10;
		 	buf[3] = '0' + rand() % 10;
		 	buf[7] = '\n';
		 	ustoa((unsigned char *)(buf + 4), ctx->challenge + 0x01fd, 3);

			if (s) memcpy(buf + 8, s, strlen(s));
			send_packet(ctx, new_packet(PACKET_CHALLENGE, 8 + (s ? strlen(s) : 0), buf, 0));
		} else {
			/**
			 * PT 8.2 adds the new codebook stuff
			 */
			pt_encode_cook_codebook(ctx);
			buf = calloc(21 + (s ? strlen(s) + 2 : 0), 1);

			buf[0] = (ctx->cb1_offset >> 8) & 0xff;
			buf[1] = ctx->cb1_offset & 0xff;
			buf[2] = (ctx->cb2_step >> 8) & 0xff;
			buf[3] = ctx->cb2_step & 0xff;
			buf[4] = (ctx->cb3_step >> 8) & 0xff;
			buf[5] = ctx->cb3_step & 0xff;

		 	buf[14] = '0' + rand() % 10;
		 	buf[15] = '0' + rand() % 10;
		 	buf[16] = '0' + rand() % 10;
		 	buf[17] = '0' + rand() % 10;
			ustoa((unsigned char *)(buf + 18), ctx->challenge + 0x1fd, 3);

			if (s) memcpy(buf + 21, s, strlen(s));
			send_packet(ctx, new_packet(PACKET_CHALLENGE, 21 + (s ? strlen(s) : 0), buf, 0));
		}

		free(s);
		break;
	case PACKET_LOGIN:
		/**
		 * Data:
		 *   0 - 3: uid (32 bits)
		 *   4 - *: encoded password
		 *          \n encoded server ip (numbers-and-dots, variant 2 encoded)
		 *          [ \n encoded secret question response (variant 1 encoded)
		 *            \n flags ]
		 *
		 * Flags:
		 *   add:   "This is my computer"
		 *   noadd: "You are a guest on someone else's computer"
		 */
		if (uid != ctx->uid || !ctx->uid || UID_IS_ERROR(ctx->uid)) {
			send_return_code(ctx, 0x63, unknown_user, 0);
			break;
		}

		/**
		 * Trigger the resgistration flow when logging in as "newuser."
		 * We do this here, mainly for 5.x, because we know the client
		 * has already received PACKET_CHALLENGE, otherwise we might not
		 * be able to properly decode the encoded password in the
		 * registration packet.
		 */
		if (ctx->uid == UID_NEWUSER) {
			transition_to(ctx, registration_flow);
			break;
		}

		/* Check the password */
		pass_ok = 0;
		if ((buf = pt_decode(ctx, 1, strtok(ctx->pkt_in.data + 4, "\n")))) {
			pass_ok += user_check_password(ctx->db_r, ctx->uid, buf);
			memset(buf, 0, strlen(buf));
			free(buf);
		}

		if (!pass_ok) {
			send_return_code(ctx, 0x63, bad_password, BAD_PASSWORD_LEN);
			break;
		}

		/**
		 * Save the ip the client believes it's connecting to.
		 *
		 * We'll need to keep this little endian for the ei field
		 * in USER_DATA (since we only have a little endian "official"
		 * client.)
		 */
		if ((buf = pt_decode(ctx, 2, strtok(NULL, "\n")))) {
			ctx->server_ip = inet_addr(buf);
			ctx->server_ip = ((ctx->server_ip << 24) & 0xff000000) |
			                 ((ctx->server_ip << 8)  & 0x00ff0000) |
			                 ((ctx->server_ip >> 8)  & 0x0000ff00) |
			                 ((ctx->server_ip >> 24) & 0x000000ff);
			free(buf);
		}

		/* Check the question response if we have one */
		if ((buf = pt_decode(ctx, 1, strtok(NULL, "\n")))) {
			if (!user_check_question_response(ctx->db_r, ctx->uid, buf)) {
				send_return_code(ctx, 0x63, bad_password, BAD_PASSWORD_LEN);
				free(buf);
				break;
			}

			/* Add this device to the user's device list */
			free(buf);
			if ((buf = strtok(NULL, "\n")) && !strcmp(buf, "add"))
				device_add(ctx);
		}

		/* Success */
		device_inc_logins(ctx);
		sprintf(ctx->uid_str, "%lu", ctx->uid);
		kick(ht_get_ptr_nc(uid_to_context, ctx->uid_str), multi_login, MULTI_LOGIN_LEN);
		ht_set(uid_to_context, ctx->uid_str, HT_PTR, ctx);
		send_packet(ctx, new_packet(PACKET_LOGIN_SUCCESS, 0, NULL, 0));
		user_logged_in(ctx->db_w, ctx->uid);
		break;
	case PACKET_UID_FONTDEPTH_ETC:
		/**
		 * Sent in response to LOGIN_SUCCESS, after VERSIONS.
		 *
		 * Data:
		 *   0   -   3: Client control ban level (non-zero if banned)
		 *   4   -   5: Number of PalTalk accounts (Subkeys of HKCU\Software\PalTalk)
		 *   6   -   *: Each account uid (32 bits)
		 *   *+1 - *+4: HKCU\Microsoft\Telnet\FontDepth (32-bits)
		 *   *+5      : '0' + (timestamp % 7)
		 *   *+6      : '0' + (timestamp % 3)
		 *   *+7 - ***: Munged IE Product ID digits The algo is:
		 * 		j = 7
		 *   	for i = 0 to len(IE_PRODUCT_ID)
		 *   		out[j] = '0' + IE_PRODUCT_ID[i] + ((((j - 7) % 5) + 1 - '0') % 10)
		 */
		if (uid && !ctx->ccban_level)     ccunban(ctx);
		else if (uid != ctx->ccban_level) ccban(ctx, ctx->ccban_level);
		transition_to(ctx, general_flow);
		break;

	/**
	 * Ignored packets
	 */
	case PACKET_VERSIONS:
		/**
		 * Sent in response to LOGIN_SUCCESS, before UID_FONTEPTH_ETC.
		 *
		 * Data:
		 *   0   -   3: Client control ban level (non-zero if banned)
		 *   4   -   5: Number of PalTalk accounts (Subkeys of HKCU\Software\PalTalk)
		 *   6   -   *: Each account uid (32 bits)
		 *   *+1 - *+4: server ip address
		 *   *+5 - *+6: server port
		 *   *+7 - ***: Comma-separated list of:
		 *   	- challenge for the encoded data below
		 *   	- Current directory FS serial number or "????????" (variant 2 encoded)
		 *   	- Drive FS serial number or "????????" (variant 2 encoded)
		 *   	- Winblows Version (variant 2 encoded) ["5.0.2195.2.208"]
		 *   		Major.Minor.BuildNumber.PlatformId
		 *   	- MAC Address or UUID (variant 2 encoded) ["0123456789AB"]
		 *   	- 0 -- Related to the files in your favorites path
		 *   	- 0 -- Related to the mod time of some files in the root of C:\
		 *   	- MSN Messenger ID (or "-1") (variant 2 encoded)
		 *   	- Yahoo User ID (or "-1") (variant 2 encoded)
		 *   	- IE Product ID (variant 2 encoded) ["51873-335-9659427-09862"]
		 */
		break;
	case PACKET_REGISTRATION_ADINFO:
		/**
		 * PT8 sends this right before continuing with login after
		 * registration, so we need to ignore it here.
		 */
		break;
	default:
		ERROR(("login: unexpected packet"));
#ifdef NDEBUG
		dump_packet(0, &ctx->pkt_in);
#endif
	}

	return;

oom:
	ERROR(("login: out of memory"));
	kick(ctx, NULL, 0);
}

