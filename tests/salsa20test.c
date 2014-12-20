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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/salsa20.h>

#define KEY_SIZE 128
#define IV_SIZE 64
#define INPUT_SIZE 512
#define OUTPUT_SIZE 64

struct salsa20_tv {
	const char *comment;
	const char *key;
	const char *iv;
	const char *out;
};

/*
 * Test vectors extracted from the ECRYPT project
 * 20-verified.test-vectors
 */
struct salsa20_tv salsa20_test_vectors[] = {
	{
		"Set 1, vector#0",
		"80000000000000000000000000000000",
		"0000000000000000",
		"4DFA5E481DA23EA09A31022050859936"\
		"DA52FCEE218005164F267CB65F5CFD7F"\
		"2B4F97E0FF16924A52DF269515110A07"\
		"F9E460BC65EF95DA58F740B7D1DBB0AA",
	},
	{
		"Set 1, vector# 9",
		"00400000000000000000000000000000",
		"0000000000000000",
		"0471076057830FB99202291177FBFE5D"\
		"38C888944DF8917CAB82788B91B53D1C"\
		"FB06D07A304B18BB763F888A61BB6B75"\
		"5CD58BEC9C4CFB7569CB91862E79C459",
	},
	{
		"Set 1, vector# 18",
		"00002000000000000000000000000000",
		"0000000000000000",
		"BACFE4145E6D4182EA4A0F59D4076C7E"\
		"83FFD17E7540E5B7DE70EEDDF9552006"\
		"B291B214A43E127EED1DA1540F33716D"\
		"83C3AD7D711CD03251B78B2568F2C844",
	},
};

#define N_VECTORS (sizeof(salsa20_test_vectors) / sizeof(*salsa20_test_vectors))

static void
hex2byte(const char *hex, uint8_t *byte)
{
	while (*hex) {
		sscanf(hex, "%2hhx", byte++);
		hex += 2;
	}
}

/* Single-shot Salsa20 using the Salsa20 interface. */
static void
salsa20_ctx_full_test(unsigned char *key, unsigned char *iv, unsigned char *out,
    unsigned char *in)
{
	Salsa20_ctx ctx;

	Salsa20_set_key(&ctx, key, KEY_SIZE);
	Salsa20_set_iv(&ctx, iv, NULL);
	Salsa20(&ctx, out, in, OUTPUT_SIZE);
}

/* Salsa20 with partial writes using the Salsa20 interface. */
static void
salsa20_ctx_partial_test(unsigned char *key, unsigned char *iv, unsigned char *out,
    unsigned char *in)
{
	Salsa20_ctx ctx;
	int len, size = 0;

	Salsa20_set_key(&ctx, key, KEY_SIZE);
	Salsa20_set_iv(&ctx, iv, NULL);
	len = OUTPUT_SIZE - 1;
	while (len > 1) {
		size = len / 2;
		Salsa20(&ctx, out, in, size);
		in += size;
		out += size;
		len -= size;
	}
	Salsa20(&ctx, out, in, len + 1);
}

/* Salsa20 with single byte writes using the Salsa20 interface. */
static void
salsa20_ctx_single_test(unsigned char *key, unsigned char *iv, unsigned char *out,
    unsigned char *in)
{
	Salsa20_ctx ctx;
	size_t i;

	Salsa20_set_key(&ctx, key, KEY_SIZE);
	Salsa20_set_iv(&ctx, iv, NULL);
	for (i = 0; i < OUTPUT_SIZE; i++)
		Salsa20(&ctx, out + i, in + i, 1);
}

struct salsa20_test_function {
	char *name;
	void (*func)(unsigned char *, unsigned char *, unsigned char *, unsigned char *);
};

struct salsa20_test_function salsa20_test_functions[] = {
	{"salsa20_ctx_full_test", salsa20_ctx_full_test},
	{"salsa20_ctx_partial_test", salsa20_ctx_partial_test},
	{"salsa20_ctx_single_test", salsa20_ctx_single_test},
};

#define N_FUNCS (sizeof(salsa20_test_functions) / sizeof(*salsa20_test_functions))

int
main(int argc, char **argv)
{
	size_t i, j, k;
	struct salsa20_tv *tv;
	unsigned char *in, *out;
	unsigned char key_tv[KEY_SIZE/8];
	unsigned char iv_tv[IV_SIZE/8];
	unsigned char out_tv[OUTPUT_SIZE];
	int failed = 0;

	for (i = 0; i < N_VECTORS; i++) {
		tv = &salsa20_test_vectors[i];
		hex2byte(tv->key, key_tv);
		hex2byte(tv->iv, iv_tv);
		hex2byte(tv->out, out_tv);

		for (j = 0; j < N_FUNCS; j++) {
			in = calloc(1, INPUT_SIZE);
			if (in == NULL)
				errx(1, "calloc in");
			out = calloc(1, OUTPUT_SIZE);
			if (out == NULL)
				errx(1, "calloc out");

			salsa20_test_functions[j].func(key_tv, iv_tv, out, in);

			if (memcmp(out, out_tv, OUTPUT_SIZE) != 0) {
				printf("Salsa20 %s failed for \"%s\"\n",
				    salsa20_test_functions[j].name, tv->comment);

				printf("Got:\t");
				for (k = 0; k < OUTPUT_SIZE; k++)
					printf("%2.2x", out[k]);
				printf("\n");

				printf("Want:\t");
				for (k = 0; k < OUTPUT_SIZE; k++)
					printf("%2.2x", out_tv[k]);
				printf("\n");

				failed = 1;
			}

			free(in);
			free(out);
		}
	}

	return failed;
}
