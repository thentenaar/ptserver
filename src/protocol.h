/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

/**
 * UID Constants
 *
 * Generally, UID values <= 0 indicate an error of some sort,
 * with a couple of exceptions.
 */
#define UID_ALL              0xffffffff
#define UID_NOT_FOUND        0xfffffffe /**< [PT5] "Welcome Msg" in room messages */
#define UID_PALTALK          0          /**< "Paltalk" in room messages */
#define UID_PALTALK_NOTIFIER 0xffffffe4 /**< PT5 uses this im IMs only, "Welcome Msg" in rooms; PT 8+ doesn't display it in IMs, but does in rooms as "Paltalk".  */
#define UID_MIN              2
#define UID_IS_ERROR(X)      (!(X) || (!!((X) >> 31) && (X) != 0xfffffffe && (X) != 0xffffffe4))

/**
 * Special uid value for our fake "newuser" user
 *
 * 5.x specifically wants 2 <= uid <= 0x7fffffff for usable uids for login
 */
#define UID_NEWUSER 0x7fffffff

/**
 * Room Constants
 */
#define ALL_ROOMS         0xffffffff
#define ALL_CATEGORIES    0xffffffff
#define ROOM_TYPE_TEXT          0
#define ROOM_TYPE_PRIVATE_VOICE 1
#define ROOM_TYPE_VOICE         3
#define ROOM_TYPE_PRIVATE_TEXT  5
#define ROOM_TYPE_ANONYMOUS     7

/**
 * Virtual Categories (hardcoded in PT 7+)
 */
#define CATEGORY_TOP      0x7530 /* PT7+ Top Rooms */
#define CATEGORY_FEATURED 0x7594 /* PT7+ Featured  */

/**
 * Status words
 */
#define STATUS_BLOCKED   0xffffffff
#define STATUS_OFFLINE   0x00000000
#define STATUS_ONLINE    0x0000001e
#define STATUS_AWAY      0x00000046
#define STATUS_DND       0x0000005a
#define STATUS_INVISIBLE 0x0000006e

/**
 * Limits
 */
#define NICKNAME_MAX  26
#define STATUSMSG_MAX 50

/**
 * Protocol versions
 *
 * These don't seem to be checked anywhere on the client side.
 */
#define PROTOCOL_VERSION    0xdead
#define PROTOCOL_VERSION_50 0x0047 /**< Paltalk 5.0  */
#define PROTOCOL_VERSION_51 0x004b /**< Paltalk 5.1  */
#define PROTOCOL_VERSION_70 0x004f /**< Paltalk 7.0  */
#define PROTOCOL_VERSION_80 0x0053 /**< Paltalk 8.0? */
#define PROTOCOL_VERSION_82 0x0056 /**< Paltalk 8.2  */
#define PROTOCOL_VERSION_90 0x0057 /**< Paltalk 9.0  */
#define PROTOCOL_VERSION_91 0x0058 /**< Paltalk 9.1  */

/**
 * Paltak packet types: client -> server
 */
#define PACKET_FILE_XFER_RECV_INIT      0x0000 /* This is the same as XFER_REJECT */
//#define 0xe7ff /* PT 8+: Unknown TODO: investigate */
//#define 0xe872 /* PT 5/7/8/9: Sent when certain messages are received on the room window, and certain other events. data: 4 bytes (wParam), 4 bytes (lParam lower 16) */
//#define 0xe87c /* PT 7+: Unknown TODO: investigate */
//#define 0xe800 /* PT 8+: Unknown TODO: investigate */
//#define 0xe884 /* PT 5/7/8/9: Unknown. Sent from room dialog proc. TODO: investigate */
//#define 0xe886 /* PT 7+: Unknown TODO: investigate */
//#define 0xe888 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xe889 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xe88a /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xec00 /* PT 9.1: Unknown TODO: investigate */
//#define 0xec0a /* PT 9.1: Unknown TODO: investigate */
//#define 0xec14 /* PT 9.1: Unknown TODO: investigate */
//#define 0xec6d /* PT 9.1: Unknown [Unused?] TODO: investigate */
#define PACKET_FILE_XFER_REJECT         0xec76
#define PACKET_FILE_XFER_SEND_INIT      0xec77
//#define 0xf038 /* PT 7+: Unknown TODO: investigate */
//#define 0xf43e /* PT 9.1: Unknown TODO: investigate */
#define PACKET_SEARCH_ROOM              0xf510 /* PT7+ data: search text */
//#define 0xf563 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf564 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf565 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf566 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf568 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf570 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf572 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xf574 /* PT 9.1: Unknown [Unused?] TODO: investigate */
#define PACKET_GET_SERVICE_URL          0xf5d8 /* PT7: 00 00 00 22 00 00 00 01 - change my profile */
                                               /* PT7: 00 00 00 10 00 00 00 01 - change my password */
                                               /* PT7: 00 00 00 0f 00 00 00 01 - get palplus */
                                               /* PT7: 00 00 00 0c 00 00 00 01 - pal personals */
                                               /* PT7: 00 00 00 0b 00 00 00 01 - mypaltalk */
                                               /* PT5: 00 00 00 0d 00 00 00 00 - Create your own permanent group */
                                               /* PT5: 00 00 00 0e d2 04 00 00 - buy a gift subscription (for d2 04 00 00 -- yes, little endian) */
                                               /* PT8: 00 00 03 21 00 00 00 01 - Main window upgrade banner (Basic level) */
                                               /* PT8: 00 00 03 22 00 00 00 01 - Main window upgrade banner (Plus level) */
                                               /* PT8: 00 00 03 25 00 00 00 01 - Upgrade to get video */
                                               /* PT8: 00 00 03 2a 00 00 00 00 - "X-Treme Upgrade" button in room window */
                                               /* PT8: 00 00 03 2b 00 00 00 00 - ? */
                                               /* PT8: 00 00 03 2c 00 00 00 00 - ? */
                                               /* PT8: 00 00 03 36 00 00 00 01 - Create a chat room */
                                               /* PT8: 00 00 03 37 00 00 00 01 - Paltalk e-store */
//#define 0xf632 /* PT 9.1: Unused? TODO: investigate */
//#define 0xf768 /* PT 9.1: Unused? TODO: investigate */
#define PACKET_VERSION_INFO             0xf7b0 /* PT 8+: data: COM-style version number. Sent after VERSIONS */
#define PACKET_NEW_CHECKSUMS            0xf7b1 /* PT 7+: Sent as an newer alternative to CHECKSUMS */
#define PACKET_INCOMPATIBLE_3P_APP      0xf7b3 /* PT 5+: data: app pattern matched */
#define PACKET_CHECKSUMS                0xf7b5
//#define 0xf7b6 /* PT 5/7/8/9: Sent in response to ROOM_UNKNOWN_ENCODED */
#define PACKET_REGISTRY_INT_VALUE       0xf7c9 /* data: challenge, six bytes from GET_REGISTRY_INT, variant 2 encoded Hive\Key=int */
#define PACKET_VERSIONS                 0xf7ca /* Sent in response to LOGIN_SUCCESS (first) */
#define PACKET_UID_FONTDEPTH_ETC        0xf7cc /* Sent in response to LOGIN_SUCCESS (second) */
#define PACKET_SEND_GLOBAL_NUMBERS      0xfa24 /* 0-length. Request the global stats */
#define PACKET_REGISTRATION_INFO        0xfa6a
#define PACKET_REGISTRATION_CHALLENGE   0xfa73 /* PT 7+: Ack DO_REGISTRATION */
#define PACKET_REGISTRATION             0xfa74 /* PT 7+: Sent when you try to start the registration process */
#define PACKET_COMMENCING_AUTOJOIN      0xfb00 /* PT 7+: 0-length Sent in response to LOGIN_SUCCESS before doing the autojoin */
/* ^ 9.0+ unused? */
#define PACKET_USER_FUCKER_STATUS       0xfb0a /* Inform the server which actions the USER_FUCKER took */
//#define 0xfb64 /* PT 9.1: Unused? TODO: investigate */
#define PACKET_VERIFY_EMAIL             0xfb75 /* PT8+: Request an email verification code */
#define PACKET_EMAIL_VERIFIED           0xfb76 /* PT8+: Informs the server of successful email verification */
#define PACKET_NEW_PASSWORD             0xfb78
//#define 0xfb82 /* PT 9.1: Unused? TODO: investigate */
#define PACKET_LOGIN                    0xfb84
//#define 0xfb93 /* PT 8+: Signifies a login issue (not capable to login, or register?) data: uid TODO: investigate */
#define PACKET_GET_UID                  0xfb95
#define PACKET_INITIAL_STATUS           0xfb96
#define PACKET_INITIAL_STATUS_2         0xfba1 /* PT7/8/9: Alternative to INITIAL_STATUS */
#define PACKET_CLIENT_DISCONNECT        0xfbb4 /* Sent when the client wants to disconnect */
#define PACKET_ROOM_CLOSE               0xfc54 /* data: room_id */
#define PACKET_ROOM_NEW_USER_MIC        0xfc5c /* data: room_id, 00 01 - true, 00 00 - false */
#define PACKET_ROOM_REDDOT_VIDEO        0xfc5d
#define PACKET_ROOM_REDDOT_TEXT         0xfc5e
#define PACKET_ROOM_BAN_NICK            0xfc66 /* room_id + target_nick TODO: investigate */
#define PACKET_ROOM_UNBAN_USER          0xfc67
#define PACKET_ROOM_BAN_USER            0xfc68
#define PACKET_ROOM_UNBOUNCE_USER       0xfc71
#define PACKET_ROOM_GET_ADMIN_INFO      0xfc7c
//#define 0xfd30 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfd3a /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfd43 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfd44 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfd58 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfd6a /* PT 9.1: Unknown [Unused?] TODO: investigate */
#define PACKET_CHANGE_STATUS            0xfd94 /* PT8: 00 00 00 46, custom away msg */
//#define 0xfd9e /* PT 9.1: Unknown [Unused?] TODO investigate */
//#define 0xfda8 /* PT 9.1: Unknown [Unused?] TODO investigate */
#define PACKET_UNBLOCK_BUDDY            0xfdf8
#define PACKET_GET_PRIVACY              0xfe02 /* 0-length */
#define PACKET_BLOCK_BUDDY              0xfe0c
//#define 0xfe3c /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfe3e /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfe3f /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfe40 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfe43 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfe44 /* PT 9.1: Unknown [Unused?] TODO: investigate */
//#define 0xfe45 /* PT 9.1: Unknown [Unused?] TODO: investigate */
#define PACKET_SET_PRIVACY              0xfe66 /* Set Privacy Setting (A [all users can contact me]/T [transfers from buddies only]/P [contact from buddy list only]) data: one byte */
//#define 0xfe6d /* PT 9.1: Unknown TODO: investigate */
//#define 0xfe6e /* PT 9.1: Unknown TODO: investigate */
#define PACKET_ROOM_HAND_DOWN           0xfe71 /* data: room id */
#define PACKET_ROOM_HAND_UP             0xfe72 /* data: room id */
#define PACKET_ROOM_UNREDDOT_USER       0xfe73
#define PACKET_ROOM_IGNORE_USER         0xfe74 /* PT 5/7/8/9: Ignore user in room? Data: room_id, target_uid, 00 00 - unignore, 00 01 - ignore */
//#define 0xfe76 /* PT 9.1: Send SuperIM Request TODO: investigate */
//#define 0xfe77 /* PT 9.1:
//#define 0xfe78 /* PT 9.1: Create SuperIM? Unknown TODO: investigate */
#define PACKET_ROOM_BOUNCE_REASON       0xfe7a /* data: room_id, uid, BR: reason */
#define PACKET_ROOM_MUTE                0xfe81 /* PT7+ Mute/Unmute the room data: room_id, 00 00 - mute, 00 01 - unmute */
#define PACKET_ROOM_LOWER_ALL_HANDS     0xfe82
#define PACKET_ROOM_REDDOT_USER         0xfe83
#define PACKET_ROOM_BOUNCE_USER         0xfe84
//#define 0xfe8e /* PT 9.1: Unknown [Unused?] TODO: investigate */
#define PACKET_ROOM_INVITE_OUT          0xfe98 /* data: room_id, uid */
#define PACKET_ROOM_SET_ALL_MICS        0xfe9d /* data: room_id, 00 - off, 01 - on */
#define PACKET_ROOM_SET_TOPIC           0xfea1 /* data: room_id, topic */
#define PACKET_ROOM_MESSAGE_OUT         0xfea2
//#define 0xfeac /* PT 9.1: Unknown [Unused?] TODO: investigate */

#define PACKET_LIST_SUBCATEGORY         0xfeaf /* PT 8.2+: List rooms in a subcategory. data: category_id, subcategory_id */
#define PACKET_NEW_LIST_CATEGORY        0xfeb0 /* PT8+: simplification of the older LIST_CATEGORY. data: category_id */
//#define 0xfeb1 /* PT 8+: Unknown 0-length TODO: investigate */
#define PACKET_LIST_CATEGORY            0xfeb6
#define PACKET_ROOM_LEAVE               0xfec0
//#define 0xfec2 /* PT 8+: Unknown TODO: investigate */
#define PACKET_ROOM_JOIN_AS_ADMIN2      0xfec3 /* PT8 TODO: investigate */
#define PACKET_ROOM_JOIN_AS_ADMIN       0xfec4 /* data: rid, code (4 bytes), 0000082a (constant -- coincides with the incoming udp voice port) */
//#define 0xfec8 /* PT 9.1: Unknown TODO: investigate */
//#define 0xfec9 /* PT 5/7/8: Related to joining a voice group? TODO: investigate data: k=v fields: aff,name,invis,port,lock */
#define PACKET_ROOM_JOIN                0xfeca /* data: room_id, join_as_invisible (16 bits, 0|1), 0000082a (constant), options string? */
#define PACKET_ROOM_REPORT_USER         0xfecf /* data: room_id, uid, complaint text */
#define PACKET_ROOM_PRIVATE_INVITE      0xfed2 /* PT 7+: Replaces PT5 p2p functionality. data: 00 01 0000082a (constant) 00 01 uid */
#define PACKET_ROOM_CREATE              0xfed4 /* PT 5: Create a room data: flags: 00 00 - no voice or private, 01 - private&voice, 03 - voice, 05 - private, category_id, 0000082a (constant), rating room_name \n password */
#define PACKET_SEND_INVITE              0xff38 /* body is email=email@host.tld \n origin=255 */
#define PACKET_SET_BUDDY_DISPLAY_NAME   0xff59 /* PT 5/7/8: Set a display name for a user data: uin (32 bits), displayname */
#define PACKET_PING                     0xff5e /* PT 9.1: Some kind of pinger. Sent every 5 seconds after login. data: timestamp 32-bits. */
//#define 0xff60 /* PT 5: ??? sent on a 1/minute timer (0x7e9) from create_room_dialog PT 9.1: Unused? TODO: investigate */
//#define 0xff68 /* PT 9.1: Unknown TODO: investigate */
#define PACKET_NUDGE_OUT                0xff7b /* PT8 data: uin (32 bits), 00 00 00 00, nudge_type (32 bits) [1=car horn, 2=fog horn, 3=monkey] */
//#define 0xff7c /* PT 8+: Unknown (advertising related?) TODO: investigate */
#define PACKET_REGISTRATION_ADINFO      0xff7e /* PT8/9: [registration] advertising-related settings */
#define PACKET_CLIENT_HELLO             0xff9b
#define PACKET_PASSWORD_HINT            0xffb9
#define PACKET_SEARCH_USER              0xffbb
#define PACKET_UNKNOWN_USER             0xffbc /* Received IM from an unknown user. data: unknown_uid (32 bits) */
#define PACKET_ADD_BUDDY                0xffbd
#define PACKET_REMOVE_BUDDY             0xffbe
#define PACKET_UPDATE_PROFILE           0xffbf /* PT5: Sent by the alter user info dialog; the return code is referenced in 7/8. TODO: return code? */
#define PACKET_ANNOUNCEMENT             0xffd9
#define PACKET_PERSONALS_MSG_OUT        0xffe6 /* PT5: Personals message reply. data: dw1, dw2, recipient_uid, sender_uid, message */
//#define 0xffe7 /* PT 9.1: Unknown [Unused?] TODO: investigate */
#define PACKET_IM_OUT                   0xffec

/**
 * Paltak packet types: server -> client
 */
#define PACKET_IM_IN                    0x0014
#define PACKET_PERSONALS_MSG_IN         0x001a /* data: sender_uid recipient_uid dw1 dw2 message; Shows some an IM dialog in PT 5.1; "Coming Soon" in PT 7/8 */
#define PACKET_KICKUSER                 0x002a /* Display an annoucement and exit */
#define PACKET_BUDDY_REMOVED            0x0042
#define PACKET_BUDDY_LIST               0x0043
#define PACKET_SEARCH_RESULTS2          0x0044 /* [PT 5/7/8] Handled the same as 0x0045 */
#define PACKET_SEARCH_RESULTS           0x0045 /* Variant I included in the original code */
#define PACKET_RETURN_CODE              0x0064
#define PACKET_COUNTRY_COREG            0x0065 /* PT 8+: looks like it drops MyWay Search Bar */
#define PACKET_HELLO                    0x0075 /* The data is ignored by the client */
#define PACKET_UPGRADE                  0x0078 /* Ignored               */
//#define 0x007a /* PT 9: TODO investigate */
#define PACKET_NUDGE_IN                 0x0085 /* [PT8] TODO: investigate */
#define PACKET_ROOM_JOINED              0x0136
#define PACKET_ROOM_USER_JOINED         0x0137
#define PACKET_ROOM_TRANSMITTING_VIDEO  0x0138
#define PACKET_ROOM_MEDIA_SERVER        0x013b
#define PACKET_ROOM_USER_LEFT           0x0140
#define PACKET_CATEGORY_COUNTS          0x014b /* Number of rooms per category */
#define PACKET_ROOM_LIST                0x014c /* List of rooms for a requested category */
//#define 0x014f /* PT 9: Unknown TODO: investigate */
#define PACKET_NEW_ROOM_LIST            0x0150 /* [PT8.2+] New room list for a category    */
#define PACKET_SUBCATEGORY_ROOM_LIST    0x0151 /* [PT8.2+] List of rooms for a subcategory */
#define PACKET_ROOM_USERLIST            0x0154
#define PACKET_ROOM_MESSAGE_IN          0x015e
#define PACKET_ROOM_TOPIC               0x015f
#define PACKET_ROOM_SET_MIC             0x0163
#define PACKET_ROOM_INVITE_IN           0x0168
//#define 0x0174 /* PT 5.1: Unknown: TODO investigate */
#define PACKET_TCP_VOICE_RECON          0x0176 /* [PT 5/7/8] TODO: Investigate */
#define PACKET_ROOM_CLOSED              0x017c
#define PACKET_ROOM_USER_REDDOT_ON      0x017d
#define PACKET_ROOM_USER_MUTE           0x017f /* PT 7+: data: room_id, uid, on/off (16 bits) */
#define PACKET_ROOM_IGNORE              0x018c /* [PT 7/8] TODO: Investigate */
#define PACKET_ROOM_USER_REDDOT_OFF     0x018d
#define PACKET_ROOM_USER_HAND_UP        0x018e
#define PACKET_ROOM_USER_HAND_DOWN      0x018f
#define PACKET_BUDDY_STATUSCHANGE       0x0190
#define PACKET_USER_DATA                0x019a /* XXX: Checksums sent in response */
#define PACKET_VERIFY_PRIVACY           0x019b /* Set the user's privacy setting (in response to a change) */
#define PACKET_CATEGORY_LIST            0x019c
//#define 0x019d /* PT 8/9: Unknown: TODO: investigate */
#define PACKET_SUBCATEGORY_LIST         0x019e /* PT 8.2+: Subcategories for a category */
#define PACKET_RESET_PARENTAL_CONTROLS  0x019f /* Resets the parental controls settings. data: target_uid (32 bits) */
//#define 0x01a4 /* PT 5: Unknown: TODO: investigate */
//#define 0x01bb /* PT 5: transfer rejected TODO: investigate */
//#define 0x01bc /* PT 5: Unknown: TODO: investigate */
//#define 0x01bd /* PT 5: Unknown: TODO: investigate */
#define PACKET_BLOCK_RESPONSE           0x01f4 /* data: uid, 00 00 - unblocked, 00 01 - blocked, Message (must contain "uccess" for successful cases) */
#define PACKET_BLOCKED_BUDDIES          0x01fe
#define PACKET_USER_STATUS              0x026c
#define PACKET_FORCED_IM                0x0294 /* Kindof like a system message         */
#define PACKET_BANNER_INTERVAL          0x02b2 /* Set the banner refresh interval. data: interval (16 bits, multiplied by ~1.5 seconds), 'C' (IM windows) / 'G' (Room windows) */
#define PACKET_ROOM_BANNER_URL          0x0320 /* data: room id, banner URL */
#define PACKET_TARGET_BANNER_IM         0x032a /* data: uid, banner URL */
#define PACKET_ROOM_ADMIN_INFO          0x0384
#define PACKET_SERVER_DISCONNECT        0x044c /* A stronger KICKUSER */
#define PACKET_UID_RESPONSE             0x046b
#define PACKET_CHALLENGE                0x0474
#define PACKET_RESET_PASSWORD           0x0488 /* Triggers the password reset dialog */
#define PACKET_EXPIRATION_IN_DAYS       0x048d /* [PT 5/7/8] TODO: investigate */
#define PACKET_SUBSCRIPTION_EXPIRED     0x048e /* [PT 7/8] TODO: investigate */
#define PACKET_LOGIN_SUCCESS            0x04a6 /* 0-length */
#define PACKET_PREPARE_USER_FUCKER      0x04ec /**
                                                * Grab the lube and get ready
                                                *
                                                * Data:
                                                *   - Challenge (stringified, v1 encoded)
                                                *   The challenge for this string is
                                                *   uid % 0x3f
                                                */
#define PACKET_FUCK_USER                0x04f6 /**
                                                * Fuck over the user, likely
                                                *  part of some built-in ban system.
                                                *
                                                * Data:
                                                *   - 2 bytes
                                                *     0x1e36: Forcibly shutdown Winblows
                                                *     0x1119: Exhaust the heap memory
                                                *   - v1 encoded: target uin
                                                */
#define PACKET_ROOM_PREMIUM             0x0528 /* Details Unknown */
#define PACKET_DO_REGISTRATION          0x058c /* [PT 7/8] Trigger the new user request dialog */
#define PACKET_REGISTRATION_SUCCESS     0x05a0
#define PACKET_REGISTRATION_FAILED      0x05a1
#define PACKET_REGISTRATION_NAME_IN_USE 0x05aa /* [PT 7/8] The name you're registering is in use */
#define PACKET_GLOBAL_NUMBERS           0x05dc /* PT7+ "x users are in y groups" */
#define PACKET_CLIENT_CONTROL           0x0834 /* Ban-related: Creates/Deletes a couple of bogus registry keys */
                                               /* HKCU\Software\Microsoft
                                               	* 	- NSPlugins\pgnumber REG_DWORD 1
                                               	* 	- Notepad\lFontSize  REG_DWORD 1
                                               	*/
#define PACKET_GET_REGISTRY_INT         0x0837 /* data: challenge, six bytes, v2 encoded hive\path */
#define PACKET_SET_REGISTRY_INT         0x0838 /* data: challenge, v2 encoded hive\path = int */
#define PACKET_DELETE_REGISTRY_KEY      0x0839 /* data: challenge, v2 encoded hive\path */
#define PACKET_ROOM_UNKNOWN_ENCODED     0x084a /* What the hell?  */
#define PACKET_INTEROP_URL              0x0850 /* Ignored */
#define PACKET_POPUP_URL                0x09c4 /* Ignored */
#define PACKET_SPECIAL_OFFER            0x09d8 /* [PT 7/8] TODO: investigate */
#define PACKET_SERVICE_URL              0x0a28
#define PACKET_BUDDY_GROUPS_LIST        0x0a8c /* [PT 7/8] TODO: investigate */
#define PACKET_BUDDY_GROUP_MEMBERS      0x0a98 /* [PT 7/8] TODO: investigate */
#define PACKET_ROOM_SEARCH_RESULTS      0x0af0 /* PT 7+ Room Search Results TODO: investigate */
#define PACKET_MY_ROOM_INFO             0x0bc2 /* [PT8] TODO: investigate */
#define PACKET_FILE_XFER_REQUEST        0x1389
#define PACKET_FILE_XFER_REFUSED        0x138b
#define PACKET_FILE_XFER_ACCEPTED       0x138c
#define PACKET_FILE_XFER_ERROR          0x138d
#define PACKET_PUB_UID_OUT              0x1777 /* [PT 7/8] no-op? TODO: investigate */
#define PACKET_PUBLISH_START            0x17d4 /* [PT 5/7/8] TODO: investigate */
#define PACKET_PUBLISH_STOP             0x17de /* [PT 5/7/8] TODO: investigate */
#define PACKET_VIEW_VIDEO_PARAMS        0x17e8 /* [PT 5/7/8] TODO: investigate */
//#define 0xe7fa /* PT5: Unknown 0-length TODO: investigate */
//#define 0xe7ff /* PT8: Unknown TODO: investigate */
//#define 0xfd30 /* PT5: Unknown video-related TODO: investigate */
#define PACKET_INVITE_BOTHER            0xfe4f /* [PT8] TODO: investigate (no data) */
#define PACKET_EMAIL_BOTHER             0xfe50 /* [PT 7/8] Bother the user to confirm their email (Shows the email confirmation dialog) TODO: investigate data */
#define PACKET_SET_DISPLAYNAME          0xfe59 /* Set a display name for a user. data: uid name */
//#define 0xff60 /* PT5: Unknown 0-length TODO: investigate */
#define PACKET_REDIRECT                 0xff89
//#define 0xff8b /* PT 9.1: Handled the same as PACKET_HELLO */
#define PACKET_SEARCH_ERROR             0xffbb
//#define 0xffbc /* PT 7/8: Unknown TODO: investigate */
#define PACKET_SEARCH_RESULTS3          0xffbf /* PT 5+, synonymous with 0x0044 and 0x0045 */

// XXX: PT8 has quite a few more new c->s packets...

/**
 * PT 5-specific
 */

/* client -> server */
#define PACKET_PT5_BANNER_COUNTERS      0xf448
#define PACKET_PT5_ROOM_GAME_REQUEST    0xf632 /** PT 5: [Room] View/Play game.
                                                   data: room_id (32-bits),
                                                   game_id (16 bits):
                                                     00 01 - cards
                                                     00 02 - chess
                                                   action (16 bits):
                                                     00 00 - watch
                                                     00 01 - play
                                               */
#define PACKET_PT5_EMAIL_VERIFY         0xf768 /* data: 00 01 <verification_code> */
#define PACKET_PT5_C_DRIVE_SERIAL       0xfb37 /* data: [response to 0x04c9] drive C volume serial (variant 1 encoded) */
#define PACKET_PT5_REGISTRATION         0xfb6e
#define PACKET_PT5_ACCEPT_VIDEO_CALL    0xfd3a /* data: uin_other_end port (network order) */
#define PACKET_PT5_DECLINE_VIDEO_CALL   0xfd43 /* data: uin_other_end */
#define PACKET_PT5_START_PRIVATE_VIDEO  0xfd44 /* data: uid_other_end port (network order) */
#define PACKET_PT5_START_VOICE_CALL     0xfe3e /* data: uid_other_end port (network order) */
#define PACKET_PT5_ACCEPT_VOICE_CALL    0xfe3f /* data: uid_other_end */
#define PACKET_PT5_HANGUP_VOICE_CALL    0xfe40 /* data: uid_other_end */
#define PACKET_PT5_DECLINE_VOICE_CALL   0xfec3 /* data: uid_other_end */
#define PACKET_OLD_CLIENT_HELLO         0xff9c /* Client hello packet */

/* server -> client */
#define PACKET_PT5_INVITE_STATUS        0x00c8 /* Status of sent invites. 0xc8 delimited list of email= status= */
#define PACKET_PT5_TELL_YOUR_FRIENDS    0x00c9 /* Show the "Tell your friends..." dialog (0-length) */
//#define 0x014a /* PT 5.1: [Alternate Room list?] Unknown TODO: investigate */
//#define 0x014d /* PT 5.1: Unknown TODO: investigate */
//#define 0x014e /* PT 5.1: Unknown [Room list related] TODO: investigate */
#define PACKET_PT5_GRANT_ROOM_ADMIN     0x0172 /* data: room_id */
#define PACKET_PT5_VOICE_CONN_INFO      0x01c1
#define PACKET_PT5_VOICE_CALL_INVITE    0x01c2
#define PACKET_PT5_VOICE_CALL_HANGUP    0x01c3 /* TODO: investigate */
#define PACKET_PT5_VIDEO_CALL_INVITE    0x02bc /* data: same as 0x01c2 */
#define PACKET_PT5_VIDEO_CALL_DECLINED  0x02bd /* TODO: investigate */
#define PACKET_PT5_VIDEO_CONN_INFO      0x02c6 /* TODO: dword, dword, word investigate */
#define PACKET_PT5_VIDEO_CALL_HANGUP    0x02d0 /* TODO: investigate */
#define PACKET_PT5_SEND_C_DRIVE_SERIAL  0x04c9 /* data: 00 00 challenge_for_fb37 */
#define PACKET_PT5_EMAIL_CONFIRM        0x0898 /* Display email confirmation code dialog */
#define PACKET_PT5_SEND_LOGIN           0xffb1 /* PT 5: Causes PACKET_LOGIN to be sent (same payload as PACKET_CHALLENGE) */

void each_field(char *s, void *ud, void (*cb)(void *ud, unsigned i, const char *line));
void each_field_kv(char *s, void *ud, void (*cb)(void *ud, const char *k, const char *v));
void each_record(char *s, void *ud, int (*cb)(void *userdata, const char *record));
char *append_value(char *s, const char *v);
char *append_field(char *s, const char *k, const char *v);
char *append_record(char *s, const char *r);
char *prepend_record(char *r, const char *s);

#endif /* PROTOCOL_H */
