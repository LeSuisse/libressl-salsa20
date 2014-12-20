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

#include <stdint.h>

#include <openssl/salsa20.h>

#include "salsa20-merged.c"

void
Salsa20_set_key(Salsa20_ctx *ctx, const unsigned char *key, uint32_t keybits)
{
	salsa20_keysetup((salsa20_ctx *)ctx, key, keybits);
	ctx->available = 0;
}

void
Salsa20_set_iv(Salsa20_ctx *ctx, const unsigned char *iv,
    unsigned char *counter)
{
	salsa20_ivsetup((salsa20_ctx *)ctx, iv, counter);
	ctx->available = 0;
}

void
Salsa20_set_counter(Salsa20_ctx *ctx, unsigned char *counter)
{
	salsa20_set_counter((salsa20_ctx *)ctx, counter);
	ctx->available = 0;
}

inline void
Salsa20_8(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
	Salsa20_rounds(ctx, out, in, len, 8);
}

inline void
Salsa20_12(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
	Salsa20_rounds(ctx, out, in, len, 12);
}

inline void
Salsa20(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
	Salsa20_rounds(ctx, out, in, len, 20);
}

void
Salsa20_rounds(Salsa20_ctx *ctx, unsigned char *out, const unsigned char *in,
    size_t len, const uint8_t rounds)
{
	unsigned char *k;
	size_t l;
	int i;

	if (ctx->available > 0) {
		k = ctx->keystream + 64 - ctx->available;
		l = (len > ctx->available) ? ctx->available : len;
		for (i = 0; i < l; i++)
			*(out++) = *(in++) ^ *(k++);
		ctx->available -= l;
		len -= l;
	}
	salsa20_encrypt_bytes((salsa20_ctx *)ctx, in, out, (uint32_t)len, rounds);
}
