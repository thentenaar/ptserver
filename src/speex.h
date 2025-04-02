/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef SPEEX_H
#define SPEEX_H

#include "codec.h"

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
              short *out, unsigned long out_len, int rate_out);

extern const struct codec speex_factory;

#endif /* SPEEX_H */
