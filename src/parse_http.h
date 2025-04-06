/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#ifndef PARSE_HTTP_H
#define PARSE_HTTP_H

#include <stddef.h>
#include <sys/types.h>

#include "hash.h"

/**
 * HTTP Methods
 */
#define HTTP_GET      1
#define HTTP_HEAD     2
#define HTTP_POST     3
#define HTTP_PUT      4
#define HTTP_DELETE   5
#define HTTP_OPTIONS  6
#define HTTP_PATCH    7
#define HTTP_TRACE    8

/**
 * A buffer large enough to hold the request line and up to 18 header
 * fields (4 KB with the defaults.)
 */
#define HTTP_BUFSIZ (20 + http_max_uri_len + http_max_query_len + (http_max_field_len * 18))

/**
 * Method id to name
 */
extern const char * const http_method_name[HTTP_TRACE + 1];

/**
 * Size limits
 */
extern unsigned http_max_body_len;
extern unsigned http_max_field_len;
extern unsigned http_max_uri_len;
extern unsigned http_max_query_len;

struct http_request {
	unsigned  method;
	char      *target;
	char      *query;
	struct ht *headers;
	char      *body;
	size_t    len;
};

struct http_response {
	unsigned  status;
	struct ht *headers;
	char      *body;
	size_t    len;
	off_t     off;
	int       fd;
	size_t    fd_len;
	unsigned  static_body;
};

/**
 * Parse a HTTP request and fill in the \a in and \a out structs.
 *
 * If we can't find the body, this function will set out->status to
 * zero, indicating that we need more data.
 *
 * If we can't parse the request, the appropriate 4xx/5xx status code
 * will be placed in out->status.
 *
 * \return Non-zero on error
 */
int http_request(char *buf, struct http_request *in, struct http_response *out);

/**
 * Serialize the response
 */
void http_serialize_response(struct http_response *out);

/**
 * Get the reason phrase for the corresponding status code
 */
const char *http_reason_phrase(unsigned status);

/**
 * Reset a HTTP request
 */
void http_request_reset(struct http_request *r);

/**
 * Reset a HTTP response
 */
void http_response_reset(struct http_response *r);

#endif /* PARSE_HTTP_H */

