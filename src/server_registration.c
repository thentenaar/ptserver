#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

#include "logging.h"
#include "packet.h"
#include "protocol.h"
#include "encode.h"
#include "server_handler.h"
#include "user.h"

#define REGISTRATION_FAILED_LEN 20
static const char * const registration_failed = "Registration failed!";


/**
 * Ordered field names for PT 7/8
 */
static const char * const field_names[] = {
	"nickname", "password", "email", NULL, NULL, "first", "last", NULL,
	"get_offers_from_us", "get_offers_from_affiliates", NULL, NULL, NULL,
	NULL, NULL, NULL
};

static const int field_encoded[] = {
	2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0
};

void registration_transition(struct pt_context *ctx)
{
	char buf[32];

	ctx->protocol_version = ctx->pkt_in.version;
	if (ctx->pkt_in.version < PROTOCOL_VERSION_70) {
		if (ctx->pkt_in.version != PROTOCOL_VERSION_51) {
			WARN(("Registration hasn't been tested with version 0x%04x",
				 ctx->pkt_in.version))
		}

		if (ctx->pkt_in.type != PACKET_PT5_REGISTRATION) {
			/**
		 	 * Pretend there was a registration error, so that PT 5.1
		 	 * shows the dialog. The dialog seems to have been
		 	 * intentionally disabled in the program, and can be
		 	 * properly re-enabled by patching offset 71213h from
		 	 * 0 to 2.
		 	 */
		 	ctx->pkt_in.type = PACKET_PT5_REGISTRATION;
			send_return_code(
				ctx, 1,
				"Press `Ok' to begin New User registration.", 0
			);
		}
	} else {
		memset(buf, 0, 16);
		buf[0] = (ctx->challenge >> 8) & 0xff;
		buf[1] = ctx->challenge & 0xff;

		if (ctx->pkt_in.version >= PROTOCOL_VERSION_82) {
			pt_encode_cook_codebook(ctx);
			buf[2] = (ctx->cb1_offset >> 8) & 0xff;
			buf[3] = ctx->cb1_offset & 0xff;
			buf[4] = (ctx->cb2_step >> 8) & 0xff;
			buf[5] = ctx->cb2_step & 0xff;
			buf[6] = (ctx->cb3_step >> 8) & 0xff;
			buf[7] = ctx->cb3_step & 0xff;
		}

		send_packet(ctx, new_packet(PACKET_DO_REGISTRATION, 16, buf, PACKET_F_COPY));
	}
}

void registration_flow(struct pt_context *ctx)
{
	int i;
	unsigned id = 0;
	char buf[8], *s, *dec, *q = NULL;

	switch (ctx->pkt_in.type) {
	case PACKET_PT5_REGISTRATION:
		/**
		 * Data:
		 *   fields, separated by "\n":
		 *
		 *   first=
		 *   last=
		 *   nickname=
		 *   email=
		 *   uid=0
		 *   password=(variant 1 encoded // 0 challenge)
		 *   state=
		 *   country=(2-letter country code)
		 *   street=
		 *   zip=int
		 *   sex=M|F
		 *   age=int
		 *   get_offers_from_affiliates=Y|N
		 *   show_email=Y|N
		 *   show_first=Y|N
		 *   show_last=Y|N
		 *   interests=16,26,27 (interest category checkboxes)
		 *   jobi=int
		 *   jobf=int
		 *   jobt=int
		 *   income=int
		 *   login=2
		 *
		 *   NAME_IN_USE is acheived with send_return_code(ctx, 0x63, "Suggested Nick")
		 *   FAILED      is acheived with send_return_code(ctx, non-zero, "Message")
		 *   SUCCESS     is acheived with send_return_code(ctx, 0, uid);
		 */
		each_field_kv(ctx->pkt_in.data, &ctx->user, user_from_named_field);
		ctx->user.banners = 0;
		ctx->user.random  = 1;

		if (ctx->user.nickname && !isalnum(ctx->user.nickname[0])) {
			send_return_code(ctx, 1, registration_failed, REGISTRATION_FAILED_LEN);
			break;
		}

		if (ctx->user.nickname && strlen(ctx->user.nickname) > NICKNAME_MAX) {
			if (!(s = malloc(NICKNAME_MAX + 1)))
				abort();

			s[NICKNAME_MAX] = '\0';
			memcpy(s, ctx->user.nickname, NICKNAME_MAX);
			free(ctx->user.nickname);
			ctx->user.nickname = s;
		}

		if (nickname_in_use(ctx->db_r, ctx->user.nickname)) {
			if (!(s = suggest_nickname(ctx->db_r, ctx->user.nickname)))
				abort();

			send_return_code(ctx, 0x63, s, strlen(s));
			break;
		}

		if (!ctx->user.nickname || register_user(ctx->db_w, &ctx->user)) {
			send_return_code(ctx, 2, registration_failed, REGISTRATION_FAILED_LEN);
			break;
		}

		if (!(dec = pt_decode_with_challenge(ctx, 1, 0, ctx->user.password))) {
			send_return_code(ctx, 3, registration_failed, REGISTRATION_FAILED_LEN);
			break;
		}

		ctx->uid = ctx->user.uid;
		user_set_password(ctx->db_w, ctx->uid, dec);
		free(dec);

		/* PT 5 will reply with the password hint */
		ctx->on_packet = password_reset_flow;
		buf[0] = (ctx->uid >> 24) & 0xff;
		buf[1] = (ctx->uid >> 16) & 0xff;
		buf[2] = (ctx->uid >> 8)  & 0xff;
		buf[3] = ctx->uid & 0xff;
		send_return_code(ctx, 0, buf, 4);

		/* Prompt to send LOGIN just like PT 7/8 */
		buf[0] = '0' + rand() % 10;
		buf[1] = '0' + rand() % 10;
		buf[2] = '0' + rand() % 10;
		buf[3] = '0' + rand() % 10;
		ctx->challenge = 1 + (rand() % CHALLENGE_MAX);
		ustoa((unsigned char *)(buf + 4), ctx->challenge + 0x01fd, 3);
		send_packet(ctx, new_packet(PACKET_PT5_SEND_LOGIN, 7, buf, PACKET_F_COPY));
		break;
	case PACKET_REGISTRATION_CHALLENGE:
		/**
		 * Data:
		 *   Data from PACKET_DO_REGISTRATION, Variant 1 encoded with the
		 *   challenge from PACKET_REGISTRATION
		 *
		 * Note: I'd expect them to have generated a new challenge here,
		 * but it seems this is just the challenge we sent, decremented.
		 */
		if ((dec = pt_decode(ctx, 1, ctx->pkt_in.data))) {
			ctx->challenge = 1 + atoi(dec);
			free(dec);
		} else {
			ERROR(("Failed to decode registration challenge"));
			send_packet(ctx, new_packet(PACKET_REGISTRATION_FAILED, 0, NULL, 0));
			kick(ctx, NULL, 0);
		}
		break;
	case PACKET_REGISTRATION_INFO:
		/**
		 * 	Fields: (most fields v2 encoded)
		 *  	PT 7:                               PT 8.2
		 * 		- nickname
		 * 		- password
		 * 		- email
		 * 		- secret question number
		 *      - secret question response
		 * 		- first name                    "none"
		 * 		- last name                     "none"
		 * 		- zip code                      "00000"
		 * 		- get paltalk newletters? (Y/N)
		 * 		- get affiliate info? (Y/N)
		 * 		- 0
		 * 		- 0
		 * 		- 0
		 * 	PT 8.2 adds:
		 * 		- int (TODO: investigate this)
		 * 		- exe name
		 * 		- promo code
		 *
		 *  PACKET_REGISTRATION_SUCCESS
		 *  	data: uid (32 bits)
		 *  PACKET_REGISTRATION_FAILED
		 *  	n bytes: error message
		 *  PACKET_REGISTRATION_NAME_IN_USE
		 *  	n bytes: suggested nick
		 */
		i = -1;
		if ((s = strtok(ctx->pkt_in.data, "\n"))) {
			do {
				/* Grab the question and response while we're in here */
				if (i == 2) id = atoi(s);
				if (i == 3) q  = pt_decode(ctx, field_encoded[i + 1], s);

				/* noname == ignore */
				if (!field_names[++i])
					continue;

				if (field_encoded[i]) {
					if (!(dec = pt_decode(ctx, field_encoded[i], s))) {
						ERROR(("Failed to decode %s", field_names[i]));
						break;
					}

					user_from_named_field(&ctx->user, field_names[i], dec);
					free(dec);
				} else user_from_named_field(&ctx->user, field_names[i], s);
			} while ((s = strtok(NULL, "\n")));
		}

		if (nickname_in_use(ctx->db_r, ctx->user.nickname)) {
			free(q);

			if (!(s = suggest_nickname(ctx->db_r, ctx->user.nickname)))
				abort();

			send_packet(ctx, new_packet(PACKET_REGISTRATION_NAME_IN_USE, strlen(s), s, 0));
			break;
		}

		if (!ctx->user.nickname || !ctx->user.password || register_user(ctx->db_w, &ctx->user)) {
			free(q);
			send_packet(ctx, new_packet(PACKET_REGISTRATION_FAILED, 0, NULL, 0));
			break;
		}

		/* Reply with the uid */
		user_set_password(ctx->db_w, ctx->user.uid, ctx->user.password);
		user_set_secret_question(ctx->db_w, ctx->user.uid, id, q);
		buf[0] = (ctx->user.uid >> 24) & 0xff;
		buf[1] = (ctx->user.uid >> 16) & 0xff;
		buf[2] = (ctx->user.uid >> 8)  & 0xff;
		buf[3] = ctx->user.uid & 0xff;
		send_packet(ctx, new_packet(PACKET_REGISTRATION_SUCCESS, 4, buf, PACKET_F_COPY));
		free(q);

		if (ctx->pkt_in.version < PROTOCOL_VERSION_82)
			transition_fro(ctx);
		break;
	case PACKET_REGISTRATION_ADINFO:
		/* [PT8] Advertising related info:
		 * Data:
		 *  advc=0&pagc=0&refc=0&start=1&progname=name.exe
		 *                      (success=1 when registration is finished)
		 *
		 * The first three are presumably counters, likely similar
		 * to the ones in PT5_BANNER_COUNTERS.
		 *
		 * Note: PT8 sends this multiple times, including right before
		 * going back into the login flow after registration. They
		 * _really_ didn't want to miss it...
		 */
		if (strstr(ctx->pkt_in.data, "&success=1"))
			transition_fro(ctx);
		break;

	default:
		ERROR(("registration: unexpected packet"));
#ifdef NDEBUG
		dump_packet(0, &ctx->pkt_in);
#endif
	}
}

