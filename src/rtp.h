/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef RTP_H
#define RTP_H

#include <stddef.h>

#define RTP_JOIN        0 /* User joined a channel      */
#define RTP_PART        1 /* User parted a channel      */
#define RTP_CLOSED      2 /* Room closed                */
#define RTP_UNRED       3 /* User is no longer redotted */
#define RTP_RED         4 /* User is reddotted (0=room) */
#define RTP_USER_UNMUTE 5 /* User has unmuted the room  */
#define RTP_USER_MUTE   6 /* User has muted the room    */

/**
 * Send a message to the RTP service
 *
 * \param msg      Message number
 * \param rid      Room ID
 * \param uid      User ID
 * \param data     Additional data
 * \param date_len Length of \a data
 */
void rtpctl(unsigned char msg, unsigned long rid, unsigned long uid,
            char *data, size_t data_len);

#endif /* RTP_H */
