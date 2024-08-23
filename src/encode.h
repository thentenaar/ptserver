/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef ENCODE_H
#define ENCODE_H

#include "packet.h"

/**
 * Maximum length of a to-be-encoded/decoded string
 */
#define ENCODE_MAX_LEN 128
#define DECODE_MAX_LEN (128<< 2)

/**
 * Encode a string with the given variant of the algorithm, with the
 * context challenge key.
 *
 * Produces an encoding string with 4 digits for each character
 * in the input string. The first three being the encoded representation
 * of the input, the fourth serving as a check digit.
 *
 * \param c Paltalk context
 * \param v Encoding algorithm variant (1 - 3)
 * \param s String to encode
 * \return A newly-allocated string, or NULL on error.
 */
#define pt_encode(c,v,s) pt_encode_with_challenge((c), (v), (c)->challenge, (s))

/**
 * Decode a string with the given variant of the algorithm, with the
 * context challenge key.
 *
 * \param c Paltalk context
 * \param v Encoding algorithm variant (1 - 3)
 * \param s String to encode
 * \return A newly-allocated string, or NULL on error.
 */
#define pt_decode(c,v,s) pt_decode_with_challenge((c), (v), (c)->challenge, (s))

/**
 * Write the given unsigned short as a string into the supplied
 * buffer with the given number of digits.
 */
void ustoa(unsigned char *buf, unsigned short u, size_t len);

/**
 * Generate the codebook used in the wrapper they added in 8.2
 */
void pt_encode_cook_codebook(struct pt_context *ctx);

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
 * \param s         String to encode
 * \return A newly-allocated string, or NULL on error.
 */
char *pt_encode_with_challenge(struct pt_context *ctx, unsigned variant, unsigned short challenge, const char *s);

/**
 * Decode a string with the given variant of the algorithm, using
 * the supplied challenge key.
 *
 * \param ctx       Paltalk context
 * \param variant   Encoding algorithm variant (1 - 3)
 * \param challenge Challenge key to use
 * \param s         String to decode
 * \return A newly-allocated string, or NULL on error.
 */
char *pt_decode_with_challenge(struct pt_context *ctx, unsigned variant, unsigned short challenge, const char *s);

/**
 * Validate the check digits in the encoded string
 *
 * \return 0 on failure, non-zero on success
 */
int pt_validate(struct pt_context *ctx, unsigned variant, const char *s);

#endif /* ENCODE_H */
