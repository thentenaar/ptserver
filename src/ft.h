/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef FT_H
#define FT_H

#include "packet.h"

/**
 * Handle the initial file transfer request
 *
 * \return 0 on success
 */
int ft_xfer_init(struct pt_context *sender, struct pt_context *recipient);

/**
 * The recipient has accepted a file transfer request
 *
 * \return 0 on success
 */
int ft_xfer_accept(struct pt_context *sender, struct pt_context *recipient);

/**
 * The recipient has rejected a file transfer request
 *
 * \return 0 on success
 */
int ft_xfer_reject(struct pt_context *sender, struct pt_context *recipient);

#endif /* FT_H */
