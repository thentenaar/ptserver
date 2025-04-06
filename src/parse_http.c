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
#include <unistd.h>
#include <limits.h>
#include <time.h>

#include "parse_http.h"

/**
 * Size limits
 */
unsigned http_max_body_len  = 2 * 1024 * 1024;
unsigned http_max_field_len = 200;
unsigned http_max_uri_len   = 238;
unsigned http_max_query_len = 238;

/**
 * RFC 9110 §5.6.2
 *
 * token = 1*tchar
 * tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
 *       / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
 *       / DIGIT / ALPHA
 *       ; any VCHAR, 0x21 - 0x7e, except delimiters
 */
static const unsigned short tchar[8] = {
	0x0000, /* 0x00 - 0x1f                           */
	0x0000, /* 0x10 - 0x1f                           */
	0x6ffc, /* 0x20 - 0x2f !(0x20, 0x22, 0x2c, 0x2f) */
	0x03ff, /* 0x30 - 0x3f !(0x3a - 0x3f)            */
	0xfffe, /* 0x40 - 0x4f !0x40                     */
	0xc7ff, /* 0x50 - 0x5f !(0x5b - 0x5d)            */
	0xffff, /* 0x60 - 0x6f                           */
	0x57ff  /* 0x70 - 0x7f !(0x7b, 0x7d, 0x7f)       */
};

/**
 * RFC 9110 §5.6.3
 *
 * OWS = *( SP / HTAB )  ; optional whitespace
 * RWS = 1*( SP / HTAB ) ; required whitespace
 * BWS = OWS             ; "bad" whitespace
 */
static const unsigned short wschar[8] = {
	0x0200, /* 0x00 - 0x0f (0x09 = '\t') */
	0x0000, /* 0x10 - 0x1f */
	0x0001, /* 0x20 - 0x2f (0x20 = ' ')  */
	0x0000, /* 0x30 - 0x3f */
	0x0000, /* 0x40 - 0x4f */
	0x0000, /* 0x50 - 0x5f */
	0x0000, /* 0x60 - 0x6f */
	0x0000, /* 0x70 - 0x7f */
};

/**
 * RFC 3986 §3.3
 *
 * pchar       = unreserved / pct-encoded / sub-delims / ":" / "@"
 * unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
 * pct-encoded = "%" HEXDIG HEXDIG
 * sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
 *               / "*" / "+" / "," / ";" / "="
 */
static const unsigned short pchar[8] = {
	0x0000, /* 0x00 - 0x1f                     */
	0x0000, /* 0x10 - 0x1f                     */
	0xfffc, /* 0x20 - 0x2f !(0x20, 0x22)       */
	0x2fff, /* 0x30 - 0x3f !(0x3c, 0x3e, 0x3f) */
	0xfffe, /* 0x40 - 0x4f !0x40               */
	0xc7ff, /* 0x50 - 0x5f !(0x5b - 0x5d)      */
	0xffff, /* 0x60 - 0x6f                     */
	0x57ff  /* 0x70 - 0x7f !(0x7b, 0x7d, 0x7f) */
};

/**
 * RFC 3986 §3.4
 *
 * query = *( pchar / "/" / "?" )
 */
static const unsigned short qchar[8] = {
	0x0000, /* 0x00 - 0x1f                     */
	0x0000, /* 0x10 - 0x1f                     */
	0xfffc, /* 0x20 - 0x2f !(0x20, 0x22)       */
	0xafff, /* 0x30 - 0x3f !(0x3c, 0x3e)       */
	0xfffe, /* 0x40 - 0x4f !0x40               */
	0xc7ff, /* 0x50 - 0x5f !(0x5b - 0x5d)      */
	0xffff, /* 0x60 - 0x6f                     */
	0x57ff  /* 0x70 - 0x7f !(0x7b, 0x7d, 0x7f) */
};

/**
 * Hash constants for method lookup
 */
#define METHOD_MAX  7
#define METHOD_GLEN 10
static const char *method_S[2] = { "fDYbIBI", "hvfcbZL" };
static const unsigned char method_G[10]  = { 0, 2, 3, 0, 0, 8, 1, 4, 2, 4  };

/**
 * Method id to name
 */
const char * const http_method_name[HTTP_TRACE + 1] = {
	"UNKNOWN",
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"OPTIONS",
	"PATCH",
	"TRACE"
};

/**
 * Given that we expect a `token,' scan it and return its length.
 *
 * A return value of zero indicates failure.
 *
 * The `xfrm' callback allows for transparent situation-specific
 * checks/transforms; and are expected to return non-zero on success.
 */
static unsigned token(char *buf, int (*xfrm)(char *buf, int c, int pc))
{
	int c, pc = 0;
	unsigned e = 0;

	assert(buf);
	while ((c = *buf++)) {
		if (c & 0x80 || !((tchar[c >> 4] >> (c & 0x0f)) & 1))
			break;

		if (xfrm && !xfrm(buf - 1, c, pc))
			break;

		e++;
		pc = c;
	}

	return e;
}

/**
 * Since field names are case-insensitive, normalize them
 */
static int normalize_field_name(char *buf, int c, int pc)
{
	if (!pc || pc == '-') {
		if (c >= 'a' && c <= 'z')
			*buf = c & ~0x20;
	} else if (c >= 'A' && c <= 'Z')
		*buf = c | 0x20;
	return 1;
}

/**
 * Methods are case-sensitive
 */
static int check_method_case(char *buf, int c, int pc)
{
	(void)buf;
	(void)pc;
	return (c & 0xf0) >= 0x40 && (c & 0xf0) <= 0x50;
}

/**
 * Scan whitespace, returning its length
 */
static int ws(char *buf)
{
	int c;
	unsigned e = 0;

	assert(buf);
	while ((c = *buf++)) {
		if (c & 0x80 || !((wschar[c >> 4] >> (c & 0x0f)) & 1))
			break;

		e++;
	}

	return e;
}

/**
 * Consume the HTTP method in \a buf, returning the method constant, or
 * an HTTP error code
 */
static unsigned method(char **buf)
{
	int e,i;
	char *b;
	unsigned x = 0, y = 0;

	assert(buf);
	if (!(b = *buf))
		return 500;

	if ((e = token(b, check_method_case)) <= 0)
		return 400;

	if (e > METHOD_MAX)
		return 501;

	for (i = 0; i < e && *b; i++, b++) {
		x += method_S[0][i] * *b;
		y += method_S[1][i] * *b;
	}

	i = 1 + (method_G[x % METHOD_GLEN] + method_G[y % METHOD_GLEN]) % METHOD_GLEN;
	if ((unsigned)e != strlen(http_method_name[i]) ||
	    memcmp(http_method_name[i], *buf, e))
		return 501;

	*buf = b;
	return (i > HTTP_TRACE) ? 501 : i;
}

/**
 * path-absolute = "/" [ segment-nz *( "/" segment ) ]
 */
static unsigned absolute_path(char *buf)
{
	int c, pc = '/';
	unsigned e = 1;

	if (*buf != '/')
		return 400;

	while ((c = *++buf)) {
		if (c & 0x80 || (pc == '/' && c == '/') || !((pchar[c >> 4] >> (c & 0x0f)) & 1))
			break;
		pc = c;
		e++;
	}

	return e >= http_max_uri_len ? 414 : e;
}

/**
 * query = *( pchar / "/" / "?" )
 */
static unsigned query(char *buf)
{
	int c;
	unsigned e = 0;

	if (*buf != '?')
		return 400;

	while ((c = *++buf)) {
		if (c & 0x80 || !((qchar[c >> 4] >> (c & 0x0f)) & 1))
			break;
		e++;
	}

	return e >= http_max_query_len ? 414 : e;
}

/**
 * Consume the request-target, returning a HTTP error code on failure.
 *
 * Since we don't support CONNECT, only the origin-form and asterisk-form
 * apply.
 *
 * request-target = origin-form = absolute-path [ "?" query ]
 *                / '*'
 */
static int request_target(char **buf, struct http_request *in)
{
	unsigned e;

	if (**buf == '*') {
		*buf = *buf + 1;
		return 0;
	}

	if ((e = absolute_path(*buf)) >= 400)
		return e;

	if (!e)
		return 400;

	if (!(in->target = calloc(e + 1, 1)))
		abort();
	memcpy(in->target, *buf, e);
	*buf += e;

	if (**buf == '?') {
		if ((e = query(*buf)) >= 400)
			return e;

		if (!(in->query = calloc(e + 1, 1)))
			abort();
		memcpy(in->query, *buf + 1, e);
		*buf += e + 1;
	}

	return 0;
}

/**
 * Consume the request line
 *
 * request-line = method SP request-target SP "HTTP" "/" DIGIT "." DIGIT
 */
static int request_line(char **buf, struct http_request *in, struct http_response *out)
{
	unsigned e;

	if ((e = method(buf)) >= 400)
		goto ret_e;

	in->method = e;
	if (**buf != ' ')
		goto bad_request;

	++*buf;
	if ((e = request_target(buf, in)) >= 400)
		goto ret_e;

	if (**buf != ' ')
		goto bad_request;

	++*buf;
	if (memcmp(*buf, "HTTP/", 5))
		goto bad_request;

	if ((*buf)[6] && ((*buf)[6] != '.' || (*buf)[7] < '0' || (*buf)[7] > '9'))
		goto bad_request;

	if ((*buf)[5] != '1' || ((*buf)[6] && (*buf)[7] > '1')) {
		out->status = 505;
		return -1;
	}

	*buf += (*buf)[6] ? 8 : 6;
	return 0;

bad_request:
	out->status = 400;
	return -1;

ret_e:
	out->status = e;
	return -1;
}

/**
 * Consume a header line
 *
 * field-line    = field-name ":" OWS field-value OWS
 * field-value   = *field-content
 * field-content = field-vchar
 *                 [ 1*( SP / HTAB / field-vchar ) field-vchar ]
 * field-vchar   = VCHAR
 */
static int field_line(char **buf, struct http_request *in, struct http_response *out)
{
	int c;
	unsigned e;
	char *name = NULL, *value = NULL;

	if ((e = token(*buf, normalize_field_name)) <= 0)
		goto bad_request;

	if (!(name = calloc(e + 1, 1)))
		abort();
	memcpy(name, *buf, e);
	*buf += e;

	if (**buf != ':')
		goto bad_request;
	*buf += 1 + ws(*buf + 1);

	/* field-value */
	if (**buf < 0x21 || **buf > 0x7e)
		goto bad_request;

	e = 0;
	while ((c = (*buf)[e++])) {
		if ((c < 0x20 && c != '\t') || c > 0x7e || e > http_max_field_len)
			break;
	}

	if (!--e)
		goto bad_request;

	/* Consume and add it to the hash table */
	if (!(value = calloc(e + 1, 1)))
		abort();
	memcpy(value, *buf, e);

	*buf += e;
	if (!in->headers && !(in->headers = ht_alloc(HT_VALUE_DEFAULT, 0)))
		abort();

	ht_set(in->headers, name, HT_STR, value);
	free(name);
	free(value);
	*buf += ws(*buf);
	return 0;

bad_request:
	free(name);
	free(value);
	out->status = 400;
	return -1;
}

/**
 * Parse a HTTP request and fill in the \a in and \a out structs.
 *
 * If we can't find the end of headers, this function will set
 * out->status to zero, indicating that we need more data.
 *
 * If we can't parse the request, the appropriate 4xx/5xx status code
 * will be placed in out->status.
 *
 * \return Non-zero on error
 */
int http_request(char *buf, struct http_request *in, struct http_response *out)
{
	int i;
	char *eoh;
	const char *s;
	assert(buf && in && out);

	http_request_reset(in);
	http_response_reset(out);

	/* Wait until we have the entire frame */
	if (!(eoh = strstr(buf, "\r\n\r\n")) && !(eoh = strstr(buf, "\n\n")))
		return -1;

	if (request_line(&buf, in, out) < 0)
		return -1;

	while (buf < eoh) {
		if (*buf == '\r')
			++buf;

		if (*buf++ != '\n')
			goto bad_request;

		if (field_line(&buf, in, out) < 0)
			return -1;
	}

	/* End of headers */
	for (i = 0; i < 2; i++) {
		if (*buf == '\r')
			++buf;

		if (*buf++ != '\n')
			goto bad_request;
	}

	s = ht_get_str(in->headers, "Content-Length");
	if (in->method == HTTP_POST || in->method == HTTP_PUT || in->method == HTTP_PATCH) {
		if (!s) {
			out->status = 411;
			return -1;
		}

		in->len = strtoul(s, NULL, 10);
		if (in->len > http_max_body_len) {
			out->status = 413;
			return -1;
		}

		in->body = buf;
		in->len  = strtoul(s, NULL, 10);
	} else if (s) goto bad_request;

	return 0;

bad_request:
	out->status = 400;
	return -1;
}

/**
 * Serialize the response
 */
void http_serialize_response(struct http_response *out)
{
	time_t t;
	struct tm *tm;
	char *buf, date[64];
	const char *key;
	const void *value;
	unsigned char type = HT_PTR;
	size_t sz = 0, cap;
	unsigned i = 0;

	cap = HTTP_BUFSIZ + out->len;
	if (out->body && out->len)
		cap += out->len;

	if (!(buf = malloc(cap)))
		abort();

	t       = time(NULL);
	date[0] = '\0';
	tm = gmtime(&t);
	strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S %Z", tm);

	sz += sprintf(buf, "HTTP/1.1 %u %s\r\nDate: %s\r\nConnection: close\r\n",
	              out->status,
	              http_reason_phrase(out->status), date);

	while (i != UINT_MAX) {
		i = ht_next(out->headers, i, &key, &value, &type);
		if (type != HT_STR)
			continue;

		if (cap < 2 + sz + strlen(key) + strlen((const char *)value) + 4) {
			/* Headers too big */
			sz = sprintf(buf, "HTTP/1.1 500 %s\r\nDate: %s\r\nConnection: close\r\n",
			             http_reason_phrase(500), date);
			out->len    = 0;
			out->status = 500;
			break;
		}

		sz += sprintf(buf + sz, "%s: %s\r\n", key, (const char *)value);
	}

	buf[sz++] = '\r';
	buf[sz++] = '\n';
	if (out->body && out->len) {
		memcpy(buf + sz, out->body, out->len);
		sz += out->len;
	}

	if (!out->static_body)
		free(out->body);
	out->static_body = 0;
	out->body = buf;
	out->len  = sz;
	out->off  = 0;
}

/**
 * Get the reason phrase for the corresponding status code
 */
const char *http_reason_phrase(unsigned status)
{
	switch (status) {
	case 100: return "Continue";
	case 101: return "Switching Protocols";
	case 102: return "Processing";
	case 103: return "Early Hints";
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 203: return "Non-Authoritative Information";
	case 204: return "No Content";
	case 205: return "Reset Content";
	case 206: return "Partial Content";
	case 208: return "Already Reported";
	case 226: return "IM Used";
	case 300: return "Multiple Choices";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 305: return "Use Proxy";
	case 307: return "Temporary Redirect";
	case 308: return "Permanent Redirect";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 402: return "Payment Required";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case 408: return "Request Timeout";
	case 409: return "Conflict";
	case 410: return "Gone";
	case 411: return "Length Required";
	case 412: return "Precondition Failed";
	case 413: return "Content Too Large";
	case 414: return "URI Too Long";
	case 415: return "Unsupported Media Type";
	case 416: return "Range Not Satisfiable";
	case 417: return "Expectation Failed";
	case 418: return "I'm a teapot";
	case 421: return "Misdirected Request";
	case 426: return "Upgrade Required";
	case 428: return "Precondition Required";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Timeout";
	case 505: return "HTTP Version Not Supported";
	case 511: return "Network Authentication Required";
	default:  return "Unknown Reason";
	}
}

/**
 * Reset a HTTP request
 */
void http_request_reset(struct http_request *r)
{
	free(r->target);
	free(r->query);
	ht_free(r->headers);

	r->method  = 0;
	r->len     = 0;
	r->target  = NULL;
	r->query   = NULL;
	r->headers = NULL;
	r->body    = NULL;
}

/**
 * Reset a HTTP response
 */
void http_response_reset(struct http_response *r)
{
	ht_free(r->headers);
	if (!r->static_body)
		free(r->body);

	if (r->fd >= 0)
		close(r->fd);

	r->status      = 0;
	r->off         = 0;
	r->len         = 0;
	r->fd          = -1;
	r->fd_len      = 0;
	r->headers     = NULL;
	r->body        = NULL;
	r->static_body = 0;
}

