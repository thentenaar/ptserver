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
#include <assert.h>

#include "macros.h"
#include "codec.h"

const struct codec speex_factory;
struct codec_ops speex_ops;
static const struct codec speex_params[2];

/**
 * The client uses the following encoder params:
 *
 * qual=1: narrowband, quality=9
 * qual=2: wideband,   quality=6
 * qual=3: wideband,   quality=8
 */
static const int speex_qual[3]      = { 9, 6, 8 };
static const unsigned speex_size[3] = { 48, 54, 72 };

/* {{{ external/speex-1.2.1 */
#define SPEEX_SET_ENH        0
#define SPEEX_GET_FRAME_SIZE 3
#define SPEEX_SET_QUALITY    4

struct SpeexMode;
struct SpeexBits {
   char *chars;   /**< "raw" data */
   int   nbBits;  /**< Total number of bits stored in the stream*/
   int   charPtr; /**< Position of the byte "cursor" */
   int   bitPtr;  /**< Position of the bit "cursor" within the current char */
   int   owner;   /**< Does the struct "own" the "raw" buffer (member "chars") */
   int   overflow;/**< Set to one if we try to read past the valid data */
   int   buf_size;/**< Allocated size for buffer */
   int   reserved1; /**< Reserved for future use */
   void *reserved2; /**< Reserved for future use */
};

extern void *speex_encoder_init(const struct SpeexMode *);
extern void *speex_decoder_init(const struct SpeexMode *);
extern void speex_encoder_destroy(void *);
extern void speex_decoder_destroy(void *);
extern int speex_encode_int(void *, short *, struct SpeexBits *);
extern int speex_decode_int(void *, struct SpeexBits *, short *);
extern int speex_encoder_ctl(void *, int, void *);
extern int speex_decoder_ctl(void *, int, void *);
extern void speex_bits_init(struct SpeexBits *);
extern void speex_bits_destroy(struct SpeexBits *);
extern void speex_bits_reset(struct SpeexBits *);
extern int speex_bits_nbytes(struct SpeexBits *);
extern void speex_bits_read_from(struct SpeexBits *, const unsigned char *, int);
extern int speex_bits_write(struct SpeexBits *, unsigned char *, int);

void *speex_resampler_init(unsigned long nb_channels,
                           unsigned long in_rate,
                           unsigned long out_rate,
                           int quality,
                           int *err);
int speex_resampler_process_int(void *st,
                                 unsigned long channel_index,
                                 const short *in,
                                 unsigned long *in_len,
                                 short *out,
                                 unsigned long *out_len);
void speex_resampler_destroy(void *st);

extern const struct SpeexMode speex_nb_mode;
extern const struct SpeexMode speex_wb_mode;
/* }}} */

static const struct SpeexMode *modes[2] = {
	&speex_nb_mode,
	&speex_wb_mode
};

/**
 * Resample an audio buffer via speex's resampler
 *
 * \param in       Sample input buffer
 * \param in_len   Input buffer length (in samples)
 * \param rate_in  Input sample rate (in Hz)
 * \param out      Sample output buffer
 * \param out_len  Output buffer length (in samples)
 * \param rate_out Output sample rate (in Hz)
 */
void resample(const short *in, unsigned long in_len, int rate_in,
              short *out, unsigned long out_len, int rate_out)
{
	void *state;

	assert(rate_in != rate_out);
	if (!(state = speex_resampler_init(1, rate_in, rate_out, 9, NULL)))
		abort();

	speex_resampler_process_int(state, 0, in, &in_len, out, &out_len);
	speex_resampler_destroy(state);
}

static struct codec *init(unsigned qual)
{
	struct codec *new;
	struct SpeexBits *sb;

	if (!(new = malloc(sizeof *new)))
		abort();

	qual = min(qual, 3);
	memcpy(new, &speex_params[!!(qual - 1)], sizeof *new);
	new->e_state = speex_encoder_init(modes[!!(qual - 1)]);
	new->d_state = speex_decoder_init(modes[!!(qual - 1)]);
	speex_encoder_ctl(new->e_state, SPEEX_SET_QUALITY, (void *)&speex_qual[(qual - 1) & 3]);
	memcpy((unsigned *)&new->frame_size, &speex_size[(qual - 1) & 3], sizeof(unsigned));

	if (!(sb = malloc(sizeof *sb)))
		abort();
	speex_bits_init(sb);
	new->ud = sb;
	return new;
}

/**
 * The client encodes and decodes the frames as:
 *
 * 0 - 1: Frame length (little endian)
 * 2 - *: Frame data
 *
 * The last frame seems to get an empty frame length appended, but since
 * there will only be four frames per packet, and the decode routine only
 * expects there to be four frames, I'm lead to believe that this is a bug
 * in the client DLL, thus we'll ignore it.
 */
static void encode(const struct codec *c, short *in, unsigned char *out)
{
	unsigned len;

	speex_bits_reset(c->ud);
	speex_encode_int(c->e_state, in, c->ud);
	len = speex_bits_nbytes(c->ud);
	*out++ = len & 0xff;
	*out++ = (len >> 8) & 0xff;
	speex_bits_write(c->ud, out, c->frame_size - 2);
}

static void decode(const struct codec *c, unsigned char *in, short *out)
{
	unsigned len;

	len = in[0] | (in[1] << 8);
	speex_bits_reset(c->ud);
	speex_bits_read_from(c->ud, in + 2, len);
	speex_decode_int(c->d_state, c->ud, out);
}

static void _free(struct codec *c)
{
	if (c->ud) speex_bits_destroy(c->ud);
	speex_encoder_destroy(c->e_state);
	speex_decoder_destroy(c->d_state);
	free(c->ud);
	free(c);
}

static struct codec_ops factory_ops = {
	init,
	NULL,
	NULL,
	NULL
};

struct codec_ops speex_ops = {
	NULL,
	encode,
	decode,
	_free
};

const struct codec speex_factory = {
	&factory_ops,
	"speex_factory",
	0, 0, 0, 0, 0,
	NULL, NULL, NULL
};

static const struct codec speex_params[2] = {
{
	&speex_ops,
	"speex (narrowband)",
	/* rate, samp_per_frame, samp_per_packet, frame_size, pt */
	8000, 160, 640, 48, 0,
	NULL, NULL, NULL
},
{
	&speex_ops,
	"speex (wideband)",
	/* rate, samp_per_frame, samp_per_packet, frame_size, pt */
	16000, 320, 1280, 54, 0,
	NULL, NULL, NULL
}};

