/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "codec.h"

const struct codec gsm_factory;
struct codec_ops gsm_ops;

/* {{{ external/gsm-1.0.12 */
extern void *gsm_create(void);
extern void gsm_destroy(void *);
extern void gsm_encode(void *, short *, unsigned char  *);
extern int  gsm_decode(void *, unsigned char *, short *);
/* }}} */

static struct codec *init(unsigned qual)
{
	struct codec *new;

	(void)qual;
	if (!(new = malloc(sizeof *new)))
		abort();

	memcpy(new, &gsm_factory, sizeof *new);
	new->ops     = &gsm_ops;
	new->name    = "gsm 6.10";
	new->e_state = gsm_create();
	new->d_state = gsm_create();
	return new;
}

static void encode(const struct codec *c, short *in, unsigned char *out)
{
	gsm_encode(c->e_state, in, out);
}

static void decode(const struct codec *c, unsigned char *in, short *out)
{
	gsm_decode(c->d_state, in, out);
}

static void _free(struct codec *c)
{
	gsm_destroy(c->e_state);
	gsm_destroy(c->d_state);
	free(c);
}

static struct codec_ops factory_ops = {
	init,
	NULL,
	NULL,
	NULL
};

struct codec_ops gsm_ops = {
	NULL,
	encode,
	decode,
	_free
};

const struct codec gsm_factory = {
	&factory_ops,
	"gsm_factory",
	/* rate, samp_per_frame, samp_per_packet, frame_size, pt */
	8000, 160, 640, 33, 3,
	NULL, NULL, NULL
};

