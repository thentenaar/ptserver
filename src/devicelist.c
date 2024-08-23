/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include "packet.h"
#include "database.h"
#include "devicelist.h"

/* Prepared queries on db_w */
static void *in_list;
static void *add_to_list;
static void *inc_logins;

/**
 * Non-zero if the current device is in the user's device list
 */
int device_in_list(struct pt_context *ctx)
{
	if (!ctx->device_id)
		return 0;

	if (!in_list) {
		in_list = db_prepare(
			ctx->db_w,
			"SELECT COUNT(*) FROM user_devices WHERE uid=? AND device_id=?"
		);
	}

	if (!in_list)
		return 0;

	db_reset_prepared(in_list);
	db_bind(in_list, "it", ctx->uid, ctx->device_id);
	return !!db_get_count(in_list);
}

/**
 * Add the current device to the device list
 */
void device_add(struct pt_context *ctx)
{
	if (!ctx->device_id)
		return;

	if (!add_to_list) {
		add_to_list = db_prepare(
			ctx->db_w,
			"INSERT INTO user_devices(uid, device_id) VALUES(?,?)"
		);
	}

	if (!add_to_list)
		return;

	db_reset_prepared(add_to_list);
	db_bind(add_to_list, "it", ctx->uid, ctx->device_id);
	db_do_prepared(add_to_list);
}

/**
 * Increment the login counter for the current device
 */
void device_inc_logins(struct pt_context *ctx)
{
	if (!ctx->device_id)
		return;

	if (!inc_logins) {
		inc_logins = db_prepare(
			ctx->db_w,
			"UPDATE user_devices SET logins=logins + 1 WHERE uid=? AND device_id=?"
		);
	}

	if (!inc_logins)
		return;

	db_reset_prepared(inc_logins);
	db_bind(inc_logins, "it", ctx->uid, ctx->device_id);
	db_do_prepared(inc_logins);
}

