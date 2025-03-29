/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef NET_H
#define NET_H

#include <netinet/in.h>

/**
 * Absolute max number of connections
 */
#define MAX_CONN 8192

/**
 * Poll flags
 */
#define NET_POLL_R  1 /**< Reads only  */
#define NET_POLL_W  2 /**< Writes only */
#define NET_POLL_RW 3 /**< Do both read and write ops */

/**
 * Connection flags
 */
#define CONN_STREAM        1
#define CONN_LISTEN        2
#define CONN_DEFER_CONNECT 4
#define CONN_SOCKETPAIR    8
extern unsigned max_conn;

/**
 * Lifecycle callbacks
 *
 * err: If the callback returns non-zero, close the connection.
 */
struct netconn_ops {
	/* fd2 here is the other end of a socketpair (for CONN_SOCKETPAIR) */
	void (*init)(void *ctx, unsigned long conn, int fd, int fd2);
	unsigned (*poll_events)(void *ctx, unsigned long conn, int fd);
	void (*connect)(void *ctx, unsigned long conn, int fd);
	void (*accept)(void *ctx, struct sockaddr *addr, socklen_t addrlen,
	               unsigned long new_conn, int new_fd);
	void (*read)(void *ctx, unsigned long conn, int fd);
	void (*write)(void *ctx, unsigned long conn, int fd);
	void (*close)(void *ctx, unsigned long conn, int fd);
	int  (*err)(void *ctx, unsigned long conn, int fd);
};

/**
 * Create a new network connection
 *
 * \param ctx     Context data
 * \param ops     Netconn ops for the new connection
 * \param addr    Socket address (in/out)
 * \param addrlen Length of \a addr
 * \param flags   Flags (i.e. NETCONN_STREAM)
 * \param stream  If non-zero, open a stream socket; datagram otherwise
 * \param lstn    If non-zero, listen on the socket
 * \return The new connection id on success, -1 on failure
 */
unsigned long net_conn(void *ctx, const struct netconn_ops *ops,
                       struct sockaddr *addr, socklen_t addrlen,
                       unsigned flags);

/**
 * Clear the connections state (after fork), leaving the given connection
 * with the given fd (the other end of the socketpair) as the only active
 * entry
 */
void net_reset(unsigned long conn, int fd);

/**
 * Set the context data for a connection
 */
void net_set_ctx(unsigned long conn, void *ctx);

/**
 * Set the timeout for a connection (0 = no timeout)
 */
void net_set_timeout(unsigned long conn, unsigned secs);

/**
 * Get the context data for a connection
 */
void *net_get_ctx(unsigned long conn);

/**
 * Get the ops for a connection
 */
const struct netconn_ops *net_get_ops(unsigned long conn);

/**
 * Connect to the address originally given to net_conn()
 */
int net_connect(unsigned long conn);

/**
 * Do a read on a connection, without polling
 */
void net_read(unsigned long conn);

/**
 * Poll connections
 *
 * \param flags   Do reads, writes, or both
 * \param timeout Number of milliseconds to wait for activity
 */
int net_poll(int flags, int timeout);

/**
 * Close the given connection
 */
void net_close(unsigned long conn);

#endif /* NET_H */
