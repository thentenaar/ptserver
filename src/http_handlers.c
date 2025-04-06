/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "hash.h"
#include "parse_http.h"
#include "http_handlers.h"

/* server.c */
extern unsigned short pt_port;
extern const char *external_ip;

static struct ht *handlers;
static struct ht *typemap;
static char location_buf[32];

/**
 * Simple static text or html
 */
static void static_html(struct http_response *response, char *buf, size_t len)
{
	char len_s[32];

	sprintf(len_s, "%lu", len);
	response->status = 200;
	response->body   = buf;
	response->len    = len;
	response->static_body++;
	ht_set(response->headers, "Content-Type", HT_STR,
	       *buf == '<' ? "text/html" : "text/plain");
	ht_set(response->headers, "Content-Length", HT_STR, len_s);
}

/**
 * Send back a file
 */
static void file(struct http_response *response, const char *filepath)
{
	int fd;
	char buf[PATH_MAX];
	const char *type;
	struct stat st;

	if (strstr(filepath, ".."))
		goto not_found;

	if (strlen(filepath) + 6 >= PATH_MAX)
		goto not_found;

	sprintf(buf, "data/%s", filepath);
	if (stat(buf, &st))
		goto not_found;

	if ((fd = open(buf, O_RDONLY)) < 0) {
		response->status = errno == ENOENT ? 404 : 403;
		return;
	}

	if (!(type = ht_get_str(typemap, strrchr(filepath, '.'))))
		type = "application/octet-stream";

	response->status = 200;
	response->fd     = fd;
	response->fd_len = (size_t)st.st_size;
	sprintf(buf, "%lu", response->fd_len);
	ht_set(response->headers, "Content-Type", HT_STR, type);
	ht_set(response->headers, "Content-Length", HT_STR, buf);
	return;

not_found:
	response->status = 404;
}

/**
 * Handle requests for location2.txt
 */
static void location2(struct http_request *request,
                      struct http_response *response,
                      struct ht *params)
{
	(void)params;

	if (request->method != HTTP_GET && request->method != HTTP_HEAD) {
		response->status = 405;
		ht_set(response->headers, "Allow", HT_STR, "GET, HEAD");
		return;
	}

	if (!location_buf[0])
		sprintf(location_buf, "LOCATION:%s:%u", external_ip, pt_port);
	static_html(response, location_buf, strlen(location_buf));
}

/**
 * Handle requests for /perl/bannerless.pl
 */
static void bannerless(struct http_request *request,
                       struct http_response *response,
                       struct ht *params)
{
	(void)params;

	if (request->method != HTTP_GET && request->method != HTTP_HEAD) {
		response->status = 405;
		ht_set(response->headers, "Allow", HT_STR, "GET, HEAD");
		return;
	}

	file(response, "bannerless.html");
}

/**
 * /banners/custom/nobannerbanner.gif
 */
static void nobanner(struct http_request *request,
                     struct http_response *response,
                     struct ht *params)
{
	(void)params;

	if (request->method != HTTP_GET && request->method != HTTP_HEAD) {
		response->status = 405;
		ht_set(response->headers, "Allow", HT_STR, "GET, HEAD");
		return;
	}

	file(response, "nobannerbanner.gif");
}

/**
 * Initialize the handler table and install known handlers
 */
void http_init_handlers(void)
{
	if (handlers) ht_free(handlers);
	if (typemap)  ht_free(typemap);

	if (!(handlers = ht_alloc(HT_VALUE_DEFAULT, 0)) ||
	    !(typemap  = ht_alloc(HT_VALUE_DEFAULT, 0)))
		abort();

	/* naive, extension-based type inference */
	ht_set(typemap, ".html", HT_STR, "text/html");
	ht_set(typemap, ".gif",  HT_STR, "image/gif");

	http_install("*", "/location2.txt", location2);
	http_install("*", "/location2.php", location2);
	http_install("advertising.paltalk.com", "/perl/bannerless.pl", bannerless);
	http_install("advertising.paltalk.com", "/banners/custom/nobannerbanner.gif", nobanner);
}

/**
 * Lookup the handler for the given path
 */
http_handler http_find_handler(const char *host, const char *path)
{
	char *buf;
	http_handler handler;

	if (!host)
		host = "*";

	if (!path || !*path)
		path = "/";

	if (!(buf = malloc(strlen(host) + strlen(path) + 1)))
		abort();

again:
	sprintf(buf, "%s%s", host, path);
	if (!(handler = (http_handler)ht_get_fptr(handlers, buf))) {
		if (*host != '*') {
			host = "*";
			goto again;
		}
	}

	free(buf);
	return handler;
}

/**
 * Parse the query string into a hash table
 */
struct ht *http_query_params(char *query)
{
	char *s, *q;
	size_t len;
	struct ht *ht;

	if (!query || !*query)
		return NULL;

	/* preserve query */
	if (!(q = malloc(strlen(query) + 1)))
		abort();
	memcpy(q, query, strlen(query) + 1);

	if (!(ht = ht_alloc(HT_VALUE_DEFAULT, 0)))
		abort();

	if (!(s = strtok(q, "&")))
		s = strtok(q, "\x01");

	do {
		if (!(len = strcspn(s, "="))) {
			ht_set(ht, s, HT_STR, "");
			continue;
		}

		s[len] = '\0';
		ht_set(ht, s, HT_STR, s + len + 1);
	} while ((s = strtok(NULL, "&")));

	free(q);
	return ht;
}

/**
 * Install a handler for the given host/path
 *
 * A host value of "*" is a wildcard, which will match if there's no
 * proper host-specific match for the path.
 */
void http_install(const char *host, const char *path, http_handler handler)
{
	char *buf;

	assert(handlers);
	if (!(buf = malloc(strlen(host) + strlen(path) + 1)))
		abort();

	sprintf(buf, "%s%s", host, path);
	ht_set(handlers, buf, HT_FPTR, &handler);
	free(buf);
	return;
}

/**
 * Free the handler table
 */
void http_free_handlers(void)
{
	ht_free(handlers);
	ht_free(typemap);
}

