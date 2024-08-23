/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

static const char value_sep[2]  = { '=',        '\0' };
static const char field_sep[2]  = { '\n',       '\0' };
static const char record_sep[2] = { (char)0xc8, '\0' };

void each_field(char *s, void *ud, void (*cb)(void *ud, unsigned i, const char *line))
{
	char *f;
	unsigned i = 0;

	if (!s || !*s || !cb || !(f = strtok(s, field_sep)))
		return;

	do { cb(ud, ++i, f); } while ((f = strtok(NULL, field_sep)));
}

void each_field_kv(char *s, void *ud, void (*cb)(void *ud, const char *k, const char *v))
{
	char *f, *k;

	if (!s || !*s || !cb || !(f = strtok(s, field_sep)))
		return;

	do {
		s += strlen(f) + 1;
		k  = strtok(f, value_sep);
		cb(ud, k, strtok(NULL, value_sep));
	} while (*s && (f = strtok(s, field_sep)));
}

void each_record(char *s, void *ud, int (*cb)(void *userdata, const char *record))
{
	char *r;

	if (!s || !*s || !cb || !(r = strtok(s, record_sep)))
		return;

	do { cb(ud, r); } while ((r = strtok(NULL, record_sep)));
}

char *append_value(char *s, const char *v)
{
	size_t slen = s ? strlen(s) : 0;

	if (!v || !*v)
		return s;

	if (!(s = realloc(s, slen + strlen(v) + 2)))
		abort();

	sprintf(s + slen, "%s%c", v, *field_sep);
	return s;
}

char *append_field(char *s, const char *k, const char *v)
{
	size_t slen = s ? strlen(s) : 0;

	if (!k || !v || !*k || !*v)
		return s;

	if (!(s = realloc(s, slen + strlen(k) + strlen(v) + 3)))
		abort();

	sprintf(s + slen, "%s%c%s%c", k, *value_sep, v, *field_sep);
	return s;
}

char *append_record(char *s, const char *r)
{
	size_t slen = s ? strlen(s) : 0;
	size_t rlen = r ? strlen(r) : 0;

	if (!rlen)
		return s;

	if (!(s = realloc(s, slen + rlen + 2)))
		abort();

	memcpy(s + slen, r, rlen);
	s[slen + rlen] = *record_sep;
	s[slen + rlen + 1] = '\0';
	return s;
}

char *prepend_record(char *r, const char *s)
{
	size_t slen = s ? strlen(s) : 0;
	size_t rlen = r ? strlen(r) : 0;

	if (!slen)
		return r;

	if (!(r = realloc(r, slen + rlen + 2)))
		abort();

	memmove(r + slen + 1, r, rlen);
	memcpy(r, s, slen);
	r[slen] = *record_sep;
	r[slen + rlen + 1] = '\0';
	return r;
}

