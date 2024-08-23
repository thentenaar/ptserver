#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "logging.h"
#include "packet.h"
#include "protocol.h"
#include "encode.h"
#include "server_handler.h"
#include "user.h"

#define INCORRECT_PW_LEN 18
static const char * const incorrect_pw = "Incorrect password";

void password_reset_transition(struct pt_context *ctx)
{
	char buf[3];
 	ustoa((unsigned char *)buf, ctx->challenge + 0x01fd, 3);
	send_packet(ctx, new_packet(PACKET_RESET_PASSWORD, 3, buf, PACKET_F_COPY));
}

void password_reset_flow(struct pt_context *ctx)
{
	unsigned short q;
	char *old_pw, *new_pw;

	switch (ctx->pkt_in.type) {
	case PACKET_NEW_PASSWORD:
		/**
		 * Data:
		 *  0 - 3: uid (32 bits)
		 *  4 - *: old password (v1 encoded)
		 *  * - *: \n
		 *  * - *: new password (v1 encoded / 0 challenge value)
		 */
		old_pw = pt_decode(ctx, 1, strtok(ctx->pkt_in.data + 4, "\n"));
		new_pw = pt_decode_with_challenge(ctx, 1, 0, strtok(NULL, "\n"));
		if (!old_pw || !new_pw) {
			ERROR(("new_password: Failed to decode password"));
			send_return_code(ctx, -1, incorrect_pw, INCORRECT_PW_LEN);
			break;
		}

		if (!user_check_password(ctx->db_r, ctx->uid, old_pw)) {
			send_return_code(ctx, 1, incorrect_pw, INCORRECT_PW_LEN);
			break;
		}

		user_set_password(ctx->db_w, ctx->uid, new_pw);
		send_return_code(ctx, 0, NULL, 0);
		break;
	case PACKET_PASSWORD_HINT:
		/**
		 * Data:
		 *   0 - 1: Secret question id (0 for none)
		 *   2 - *: Secret question response (can be empty)
		 *          \n password hint text
		 *
		 * Example of empty question response input:
		 *   0 - 3: 00 00 0a
		 *   4 - *: Password hint text
		 */
		q      = ntohs(*(unsigned short *)ctx->pkt_in.data);
		old_pw = strtok(ctx->pkt_in.data + 2, "\n");
		new_pw = strtok(NULL, "\n");

		user_set_secret_question(ctx->db_w, ctx->uid, q, old_pw);
		user_set_password_hint(ctx->db_w, ctx->uid, new_pw);
		transition_fro(ctx);
		break;
	default:
		ERROR(("password_reset: unexpected packet"));
#ifdef NDEBUG
		dump_packet(0, &ctx->pkt_in);
#endif
	}
}

