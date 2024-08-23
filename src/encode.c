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
#include <math.h>
#include <time.h>

#include "macros.h"
#include "packet.h"
#include "protocol.h"
#include "encode.h"
#include "logging.h"

/**
 * I recall how quickly this caught my eye when I first starting
 * reversing the encoding stuff. I can only appreciate how obvious
 * it is, even after 20 years. Note the glaring typo "becuase" not
 * sure if it's a 'feature' or a genuine typo, but it persists.
 */
static const char *ginger =
"Ginger was a big fat horse, a big fat horse was she. But don't tell that"
" to MaryLou becuase in love with her is she.I tell you this in private, "
"because I thought that you should know.But never say to MaryLou or both "
"our heads will go.I've said it once, I've said it twice, I'll say it onc"
"e again.Not a word of this to you know who or it will be our end!\r";

/**
 * Source material for 8.2's codebook generation algorithm. Somebody
 * obvioulsy fancies themselves a poet.
 */
#define CODEBOOK1_LEN       0x156
#define CODEBOOK2_LEN       0x156
#define CODEBOOK2_STEP_MASK 15
#define CODEBOOK3_STEP_MASK 15

static const char *codebook1 =
"WhEther it was me or wEather it was you, tis not the poinT I say. The Po"
"int tHat be is nOt to SEe ThE difference betWEen you and me.Four sconeS "
"and some ten pEnce EonS ago I loSt mY way. MaNy eOns have pAst since thE"
"n but I still don'T have much to sAY; THIRTENN AnD A HAlF DoLLARS FOR A "
"HAMBURGER?  WHAT'S IN tHE SPECIAL SAUCE, GOLD NUGGETS!";

static const char *codebook2 =
"95kjgr-t0GFGllbcbivvb;vmbl;kw-gmncFGDnxcvlkjt9^&*^$$)nfds0--rwefnfmcnfr9"
"0493jeGFDGsmkteotept;fdge;KL454954385rka8%^#)@gkfg0t3;l,0pejgfgkjgklfgke"
"rBVB03b  mB bibBV3rtnjfyggo9geaogig968959fk85jnfgsmCVbrkf,.er'wslr985BNV"
"BVXCV-9=]dlfkgVCVCVrkdgdgoB NJfgfx;ldffgjkDDGjkfdgkjreo-reFETUtogld0986b"
"mUYUjTfhkgoxiopggopflgkfdogdopgdlbdmgket0ettl;hglhmnll";

static const unsigned tenpow[5] = { 1000, 100, 10, 1, 0 };

/**
 * The classic M$ rand() function
 */
static unsigned ms_seed(unsigned x)
{
	return x * 0x343fd + 0x269e3c;
}

static unsigned ms_rand(unsigned x)
{
	return (ms_seed(x) >> 16) & 0x7fff;
}

/**
 * This will give better variance, making the padding digits, etc.
 * less obvious.
 */
static unsigned my_seed(void)
{
	struct timespec ts;
	if (!clock_gettime(CLOCK_MONOTONIC, &ts))
		return ms_seed((ts.tv_sec * 10e6 + ts.tv_nsec));
	return ms_seed(time(NULL));
}

/**
 * Write the given unsigned short as a three-digit string into the
 * supplied buffer.
 */
void ustoa(unsigned char *buf, unsigned short u, size_t len)
{
	unsigned i = 0;

	while (i < len) {
		buf[(len - 1) - i++] = '0' + (u % 10);
		u /= 10;
	}
}

/**
 * Generate the codebook used in the new algo in 8.2
 */
void pt_encode_cook_codebook(struct pt_context *ctx)
{
	unsigned i;

	srand(my_seed());
	ctx->cb1_offset = 1 + (rand() % (CODEBOOK1_LEN >> 2));
	ctx->cb2_step   = 1 + (rand() & CODEBOOK2_STEP_MASK);
	ctx->cb3_step   = 1 + (rand() & CODEBOOK3_STEP_MASK);

	/**
	 * Mix the two source codebooks and extend it with an interleaved set
	 * of characters.
	 */
	for (i = 0; i < CODEBOOK_LEN; i += 2) {
		ctx->codebook[i] = ((i >> 1) & 1)
			? codebook2[(((i >> 2) + 1) * ctx->cb2_step) % CODEBOOK2_LEN]
			: codebook1[((i >> 2) + ctx->cb1_offset)     % CODEBOOK1_LEN];
		ctx->codebook[i + 1] = '0' + ((((i >> 1) + 1) * ctx->cb3_step) % 0x4b);
	}
}

static char *pt_encode_with_codebook(struct pt_context *ctx, unsigned short challenge, const char *s)
{
	size_t slen, i, j, o = 0;
	char *out = NULL;
	unsigned a, s_pos;

	/* String start specifier */
	s_pos = ms_rand(my_seed()) * min(8999, CODEBOOK_LEN - 256);
	s_pos = 1001 + ((s_pos >> 15) | ((s_pos >> 14) & 1));
	if (!s || !(slen = strlen(s)))
		goto err;

	if (!(out = calloc((2 + slen + !(s_pos % 3) + !(s_pos & 3)) << 2, 1)))
		goto err;

	/* Pad to start with random digits */
	ustoa((unsigned char *)out, s_pos, o += 4);
	for (i = 4; i < (unsigned)(1 + !(s_pos % 3) + !(s_pos & 3)) << 2; i++)
		out[o++] = '0' + rand() % 10;

	for (i = 0; i < slen; i++, o += 4) {
		ustoa((unsigned char *)(out + o), 0x71 + i + s[i] + ctx->codebook[challenge + i], 3);

		/* addend digit */
		a = ms_rand(my_seed()) * min(9, CODEBOOK_LEN - 256);
		a = (1 + ((a >> 15) | ((a >> 14) & 1))) % 10;
		for (j = 0; j < 3; j++) {
			if ((out[o + j] += a) > '9')
				out[o + j] -= 10;
		}

		j = (ctx->codebook[challenge + i] + i + s_pos) & 3;
		memmove(out + o + j + 1, out + o + j, 3 - j);
		*(out + o + j) = '0' + a;
	}

	return out;

err:
	free(out);
	return NULL;
}

static char *pt_decode_with_codebook(struct pt_context *ctx, unsigned short challenge, const char *s)
{
	unsigned n = 0, x, a, s_pos, a_pos;
	size_t slen, i, j;
	char *out = NULL;

	if (!s || !(slen = strlen(s)) || slen & 3)
		goto err;

	/* The starting position is obtained from the first group */
	s_pos = s[0] * 1000 + s[1] * 100 + s[2] * 10 + s[3] - 53328;
	slen -= (unsigned)(1 + !(s_pos % 3) + !(s_pos & 3)) << 2;
	s    += (unsigned)(1 + !(s_pos % 3) + !(s_pos & 3)) << 2;

	if (!(out = calloc(1 + (slen >> 2), 1)))
		goto err;

	for (i = 0; i < slen >> 2; i++, n = 0) {
		/* Find the addend, remove it, and normalize the char */
		a_pos = (ctx->codebook[challenge + i] + i + s_pos) & 3;
		a     = s[a_pos + (i << 2)] - '0';

		for (j = 0; j < 4; j++) {
			x = s[j + (i << 2)] - a - '0';
			n += tenpow[(j == a_pos) ? 4 : (j + (j < a_pos))] * ((x + 10) % 10);
		}

		out[i] = n - 0x71 - ctx->codebook[challenge + i] - i;
	}

	return out;

err:
	free(out);
	return NULL;
}

/**
 * Encode a string with the given variant of the algorithm, using
 * the supplied challenge key.
 *
 * Produces an encoding string with 4 digits for each character
 * in the input string. The first three being the encoded representation
 * of the input, the fourth serving as a check digit.
 *
 * \param ctx       Paltalk context
 * \param variant   Encoding algorithm variant (1 - 3)
 * \param challenge Challenge key to use
 * \return A newly-allocated string, or NULL on error.
 */
char *pt_encode_with_challenge(struct pt_context *ctx, unsigned variant, unsigned short challenge, const char *s)
{
	size_t slen, i, o = 0;
	char *out = NULL;

	/* The old encoding was replaced with the codebook encoding in 8.2 */
	if (ctx->protocol_version >= PROTOCOL_VERSION_82 && ctx->cb1_offset)
		return pt_encode_with_codebook(ctx, challenge, s);

	if (!variant || variant > 3 || !s || !(slen = strlen(s)) || !(out = calloc(1 + (slen << 2), 1)))
		goto err;

	if (slen > ENCODE_MAX_LEN) {
		WARN(("pt_encode: truncating s to %u bytes (was %lu)", ENCODE_MAX_LEN, slen));
		slen = ENCODE_MAX_LEN;
	}

	for (i = 0; i < slen; i++, o += 4) {
		switch (variant) {
		case 1:
			ustoa((unsigned char *)(out + o), 0x7a + (i * (13 - i)) + s[i] + ginger[challenge + i], 3);
			break;
		case 2:
			ustoa((unsigned char *)(out + o), 0x7a + i + s[i] + ginger[challenge + i], 3);
			break;
		case 3:
			ustoa((unsigned char *)(out + o), 0x7a + s[i] + ginger[i] + (challenge * i), 3);
			--challenge;
			break;
		}

		/**
		 * Get a M$ random number between 0 and 10, based on our time
		 * value, taking the lower three bits for our check digit. Note,
		 * the client's decoding routines ignore the check digit entirely.
		 *
		 * I wonder if the use of 32678 vs the canonical 32768 here was
		 * a misinterpretation I made, a bug in the original, or intended
		 * behavior.
		 */
		*(out + o + 3) = '0' + ((unsigned)floor((ms_rand(ctx->time) / 32678.0f) * 10.0f) & 7);
		ctx->time = ms_seed(ctx->time);
	}

	return out;

err:
	free(out);
	return NULL;
}

/**
 * Decode a string with the given variant of the algorithm, using
 * the supplied challenge key.
 *
 * \param ctx       Paltalk context
 * \param variant   Encoding algorithm variant (1 - 3)
 * \param challenge Challenge key to use
 * \return A newly-allocated string, or NULL on error.
 */
char *pt_decode_with_challenge(struct pt_context *ctx, unsigned variant, unsigned short challenge, const char *s)
{
	unsigned n;
	size_t slen, i;
	char *out = NULL;

	/* The old encoding was replaced with the codebook encoding in 8.2 */
	if (ctx->protocol_version >= PROTOCOL_VERSION_82 && ctx->cb1_offset)
		return pt_decode_with_codebook(ctx, challenge, s);

	if (!variant || variant > 3 || !s || !(slen = strlen(s)) || slen & 3 || !(out = calloc(1 + (slen >> 2), 1)))
		goto err;

	if (slen > DECODE_MAX_LEN) {
		WARN(("pt_decode: truncating input to %u bytes (was %lu)", DECODE_MAX_LEN, slen));
		slen = DECODE_MAX_LEN;
	}

	for (i = 0; i < slen >> 2; i++) {
		n = s[i << 2] * 100 + s[1 + (i << 2)] * 10 + s[2 + (i << 2)] - 5328;
		if (n > 999) goto err;

		switch (variant) {
		case 1:
			out[i] = n - 0x7a - (i * (13 - i)) - ginger[challenge + i];
			break;
		case 2:
			out[i] = n - 0x7a - i - ginger[challenge + i];
			break;
		case 3:
			out[i] = n - 0x7a - ginger[i] - (challenge * i);
			--challenge;
			break;
		}
	}

	return out;

err:
	free(out);
	return NULL;
}

int pt_validate(struct pt_context *ctx, unsigned variant, const char *s)
{
	size_t slen, i;

	if (!variant || variant > 3 || !s || !(slen = strlen(s)) || slen & 3)
		goto err;

	for (i = 0; i < slen >> 2; i++) {
		if ((unsigned)s[3 + (i << 2)] - '0' != ((unsigned)floor((ms_rand(ctx->time) / 32678.0f) * 10.0f) & 7))
			goto err;
		ctx->time = ms_seed(ctx->time);
	}

	return 1;

err:
	return 0;

}

