/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef PACKETS_H
#define PACKETS_H

#include <stddef.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "user.h"

/**
 * Packet flags
 */
#define PACKET_F_STATIC 0x01 /**< Data is static          */
#define PACKET_F_COPY   0x02 /**< Make a copy of the data */

/**
 * Length of the generated codebook
 */
#define CODEBOOK_LEN   0x558

/**
 * Allows for encoding up to 128 unencoded bytes
 */
#define CHALLENGE_MAX  226

/**
 * Paltalk packet
 */
struct pt_packet {
	unsigned short type;
	unsigned short version;
	unsigned short length;
	char *data;
	unsigned refcnt;
	unsigned flags;
	size_t remaining;
};

/**
 * Connection context
 */
struct pt_context {
	int fd;
	int disconnect;
	struct sockaddr_in addr;
	void *db_r;
	void *db_w;
	struct user user;

/*
	time_t last_pkt_in;
	time_t last_pkt_out;
*/

	time_t time;
	unsigned short protocol_version;
	unsigned short challenge;
	unsigned long ccban_level;
	unsigned long status;
	char *status_msg;
	char *device_id;
	unsigned long uid;
	char uid_str[11];
	in_addr_t server_ip; /**< IP according to the client, little endian */

	/* 8.2 codebook params */
	unsigned short cb1_offset; /**< Offset into the first codebook data */
	unsigned short cb2_step;   /**< Step for the second codebook        */
	unsigned short cb3_step;   /**< Step for the generated codebook     */
	unsigned char codebook[CODEBOOK_LEN];

	/* Packet I/O */
	struct msghdr hdr_in;
	struct msghdr data_in;
	struct msghdr pkt_out;
	struct pt_packet pkt_in;
	struct pt_packet **pkts_out; /**< So that we can track them */
	size_t npkts_out;

	/* Packet callback */
	void (*on_packet)(struct pt_context *);
	void (*prev_on_packet)(struct pt_context *);
};

void pt_context_init(struct pt_context *ctx, int fd);
void pt_context_destroy(struct pt_context *ctx);

void packet_in(struct pt_context *ctx);
void packet_out(struct pt_context *ctx);
struct pt_packet *new_packet(unsigned short type, unsigned short len, const char *data, unsigned flags);
void send_packet(struct pt_context *ctx, struct pt_packet *pkt);
void free_packet(struct pt_packet *pkt);
void dump_packet(int, struct pt_packet *pkt);

// XXX: my original uid: 02 aa 17 e6

#endif /* PACKETS_H */
