/*
 * Copyright (c) 2014 Thomas Gerbet <thomas@gerbet.me>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HEADER_SALSA20_H
#define HEADER_SALSA20_H

#include <openssl/opensslconf.h>

#if defined(OPENSSL_NO_SALSA20)
#error Salsa20 is disabled.
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int input[16];
	unsigned char keystream[64];
	size_t available;
} Salsa20_ctx;

void Salsa20_set_key(Salsa20_ctx *ctx, const unsigned char *key,
    uint32_t keybits);
void Salsa20_set_iv(Salsa20_ctx *ctx, const unsigned char *iv,
    unsigned char *counter);
void Salsa20_set_counter(Salsa20_ctx *ctx, unsigned char *counter);
void Salsa20_8(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len);
void Salsa20_12(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len);
void Salsa20(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len);
void Salsa20_rounds(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len, const uint8_t rounds);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_SALSA20_H */
