/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef HTTP_HANDLERS_H
#define HTTP_HANDLERS_H

#include "hash.h"
#include "parse_http.h"

typedef void (*http_handler)(struct http_request *request,
                             struct http_response *response,
                             struct ht *params);

/**
 * Initialize the handler table and install known handlers
 */
void http_init_handlers(void);

/**
 * Lookup the handler for the given path
 */
http_handler http_find_handler(const char *host, const char *path);

/**
 * Parse the query string into a hash table
 */
struct ht *http_query_params(char *query);

/**
 * Install a handler for the given host/path
 *
 * A host value of "*" is a wildcard, which will match if there's no
 * proper host-specific match for the path.
 */
void http_install(const char *host, const char *path, http_handler handler);

/**
 * Free the handler table
 */
void http_free_handlers(void);

#endif /* HTTP_HANDLERS_H */

