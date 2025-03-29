/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#ifndef SERVICE_H
#define SERVICE_H

#include <stddef.h>

#define THIS_SERVICE 0

/**
 * Operations for a service
 */
struct service_ops {
	void (*start)(void);
	void (*parent_read)(int fd);
	void (*child_read)(int fd);
	void (*stop)(void);
};

/**
 * Start a service
 * \return a service handle, or -1 on error
 */
unsigned long service_start(struct service_ops *ops);

/**
 * Check a service for activity, and respond accordingly
 */
void service_recv(unsigned long handle);

/**
 * Send data to a service
 * \return Number of bytes written, or -errno on error
 */
int service_send(unsigned long handle, char *data, unsigned len);

/**
 * Stop a service
 */
void service_stop(unsigned long handle);

#endif /* SERVICE_H */
