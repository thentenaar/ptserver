/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef DEVICELIST_H
#define DEVICELIST_H

#include "packet.h"

/**
 * Non-zero if the current device is in the user's device list
 */
int device_in_list(struct pt_context *ctx);

/**
 * Add the current device to the device list
 */
void device_add(struct pt_context *ctx);

/**
 * Increment the login counter for the current device
 */
void device_inc_logins(struct pt_context *ctx);

#endif /* DEVICELIST_H */
