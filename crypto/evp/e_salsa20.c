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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SALSA20

#include <openssl/salsa20.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "evp_locl.h"

static int salsa_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len);
static int salsa_cipher_12(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len);
static int salsa_cipher_8(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len);
static int salsa_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc);

static const EVP_CIPHER salsa20_cipher = {
	.nid = NID_salsa20,
	.block_size = 1,
	.key_len = 32,
	.iv_len = 8,
	.flags = EVP_CIPH_STREAM_CIPHER,
	.init = salsa_init,
	.do_cipher = salsa_cipher,
	.ctx_size = sizeof(Salsa20_ctx)
};

static const EVP_CIPHER salsa20_12_cipher = {
	.nid = NID_salsa20_12,
	.block_size = 1,
	.key_len = 32,
	.iv_len = 8,
	.flags = EVP_CIPH_STREAM_CIPHER,
	.init = salsa_init,
	.do_cipher = salsa_cipher_12,
	.ctx_size = sizeof(Salsa20_ctx)
};

static const EVP_CIPHER salsa20_8_cipher = {
	.nid = NID_salsa20_8,
	.block_size = 1,
	.key_len = 32,
	.iv_len = 8,
	.flags = EVP_CIPH_STREAM_CIPHER,
	.init = salsa_init,
	.do_cipher = salsa_cipher_8,
	.ctx_size = sizeof(Salsa20_ctx)
};

const EVP_CIPHER *
EVP_salsa20(void)
{
	return (&salsa20_cipher);
}

const EVP_CIPHER *
EVP_salsa20_12(void)
{
	return (&salsa20_12_cipher);
}

const EVP_CIPHER *
EVP_salsa20_8(void)
{
	return (&salsa20_8_cipher);
}

static int
salsa_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
	Salsa20_set_key((Salsa20_ctx *)ctx->cipher_data, key,
	    EVP_CIPHER_CTX_key_length(ctx) * 8);
	if (iv != NULL)
		Salsa20_set_iv((Salsa20_ctx *)ctx->cipher_data, iv, NULL);
	return 1;
}

static int
salsa_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
	Salsa20((Salsa20_ctx *)ctx->cipher_data, out, in, len);
	return 1;
}

static int
salsa_cipher_12(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
	Salsa20_12((Salsa20_ctx *)ctx->cipher_data, out, in, len);
	return 1;
}

static int
salsa_cipher_8(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
	Salsa20_8((Salsa20_ctx *)ctx->cipher_data, out, in, len);
	return 1;
}
#endif
