/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef CODEC_H
#define CODEC_H

#if 0
	{ 16000, 2, 320, 1280, 54,  0 }, /* Speex */
	{ 32000, 2, 640, 2560, 122, 0 }  /* Siren / G722.1C */
#endif

/**
 * Audio codec interface
 *
 * Codecs will have a global "factory" defined in their header which
 * must be used to create suitably initialized instances of a given
 * codec, via c = ops->init().
 *
 * Be sure to call c->ops->free(c) when done with it.
 */
struct codec {
	struct codec_ops *ops;
	const char *name;
	const unsigned rate;       /* sample rate (Hz)   */
	const unsigned spf;        /* samples per frame  */
	const unsigned spkt;       /* samples per packet */
	const unsigned frame_size; /* (in bytes)         */
	const unsigned pt;         /* RTP payload type   */
	void *e_state;             /* Encoder state      */
	void *d_state;             /* Decoder state      */
};

struct codec_ops {
	struct codec *(*init)(void);
	void (*encode)(const struct codec *c, short *in, unsigned char *out);
	void (*decode)(const struct codec *c, unsigned char *in, short *out);
	void (*free)(struct codec *c);
};

#endif /* CODEC_H */
