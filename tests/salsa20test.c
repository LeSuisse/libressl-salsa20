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
#define N_VECTORS_20 (sizeof(salsa20_test_vectors) / sizeof(*salsa20_test_vectors))
/*
 * Test vectors extracted from the ECRYPT project
 * 12-verified.test-vectors
 */
struct salsa20_tv salsa20_12_test_vectors[] = {
	{
		"Set 1, vector#0",
		"80000000000000000000000000000000",
		"0000000000000000",
		"FC207DBFC76C5E1774961E7A5AAD0906"\
		"9B2225AC1CE0FE7A0CE77003E7E5BDF8"\
		"B31AF821000813E6C56B8C1771D6EE70"\
		"39B2FBD0A68E8AD70A3944B677937897",
	},
	{
		"Set 1, vector# 9",
		"00400000000000000000000000000000",
		"0000000000000000",
		"6C11A3F95FEC7F48D9C16F93CC901EEC"\
		"8D347BEA4C64B63F3E1CD88DF4F03A59"\
		"5ACC0500EFC616DCFEBA3E839F0F72C5"\
		"A54A0801B90C864EEAA7F48CF37DC365",
	},
	{
		"Set 1, vector# 18",
		"00002000000000000000000000000000",
		"0000000000000000",
		"E27E394CC6B72EB535FD92D1BDF9F5D6"\
		"24671D5BFC9EF233F6B51F12BF338AE1"\
		"72DC8B7F4CE899BD5FF85B0546F022DE"\
		"B91FEA1ABAC32EE1F7B671E7D6DBF9D6",
	},
};
#define N_VECTORS_12 (sizeof(salsa20_test_vectors) / sizeof(*salsa20_12_test_vectors))
/*
 * Test vectors extracted from the ECRYPT project
 * 8-verified.test-vectors
 */
struct salsa20_tv salsa20_8_test_vectors[] = {
	{
		"Set 1, vector#0",
		"80000000000000000000000000000000",
		"0000000000000000",
		"A9C9F888AB552A2D1BBFF9F36BEBEB33"\
		"7A8B4B107C75B63BAE26CB9A235BBA9D"\
		"784F38BEFC3ADF4CD3E266687EA7B9F0"\
		"9BA650AE81EAC6063AE31FF12218DDC5",
	},
	{
		"Set 1, vector# 9",
		"00400000000000000000000000000000",
		"0000000000000000",
		"EEB20BFB12025D2EE2BF33356644DCEF"\
		"467D377176FA74B3C110377A40CFF1BF"\
		"37EBD52A51750FB04B80C50AFD082354"\
		"9230B006F5994EBAAA521C7788F5E31C",
	},
	{
		"Set 1, vector# 18",
		"00002000000000000000000000000000",
		"0000000000000000",
		"714DA982330B4B52E88CD0AC151E77AB"\
		"72EECEA2023139DA39FCCC3ABC12F83F"\
		"455733EDC22808318F10499EA0FCEEB4"\
		"0F61EF121C39F62D92CA62DA885BDF21",
	},
};
#define N_VECTORS_8 (sizeof(salsa20_test_vectors) / sizeof(*salsa20_8_test_vectors))

typedef void (*salsa_encrypt)(Salsa20_ctx *, unsigned char *,
    const unsigned char *, size_t);
struct salsa20_tv_function {
	const char *name;
	struct salsa20_tv *tv;
	const size_t nb_tv;
	salsa_encrypt encrypt_func;
};
struct salsa20_tv_function salsa20_tv_functions[] = {
	{"Salsa20", salsa20_test_vectors, N_VECTORS_20, Salsa20},
	{"Salsa20/12", salsa20_12_test_vectors, N_VECTORS_12, Salsa20_12},
	{"Salsa20/8", salsa20_8_test_vectors, N_VECTORS_8, Salsa20_8},
};
#define N_TV_FUNCTIONS (sizeof(salsa20_tv_functions) / sizeof(*salsa20_tv_functions))

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
salsa20_ctx_full_test(salsa_encrypt encrypt_func, unsigned char *key,
    unsigned char *iv, unsigned char *out, unsigned char *in)
{
	Salsa20_ctx ctx;

	Salsa20_set_key(&ctx, key, KEY_SIZE);
	Salsa20_set_iv(&ctx, iv, NULL);
	encrypt_func(&ctx, out, in, OUTPUT_SIZE);
}

/* Salsa20 with partial writes using the Salsa20 interface. */
static void
salsa20_ctx_partial_test(salsa_encrypt encrypt_func, unsigned char *key,
    unsigned char *iv, unsigned char *out, unsigned char *in)
{
	Salsa20_ctx ctx;
	int len, size = 0;

	Salsa20_set_key(&ctx, key, KEY_SIZE);
	Salsa20_set_iv(&ctx, iv, NULL);
	len = OUTPUT_SIZE - 1;
	while (len > 1) {
		size = len / 2;
		encrypt_func(&ctx, out, in, size);
		in += size;
		out += size;
		len -= size;
	}
	encrypt_func(&ctx, out, in, len + 1);
}

/* Salsa20 with single byte writes using the Salsa20 interface. */
static void
salsa20_ctx_single_test(salsa_encrypt encrypt_func, unsigned char *key,
    unsigned char *iv, unsigned char *out, unsigned char *in)
{
	Salsa20_ctx ctx;
	size_t i;

	Salsa20_set_key(&ctx, key, KEY_SIZE);
	Salsa20_set_iv(&ctx, iv, NULL);
	for (i = 0; i < OUTPUT_SIZE; i++)
		encrypt_func(&ctx, out + i, in + i, 1);
}

struct salsa20_test_function {
	char *name;
	void (*func)(salsa_encrypt, unsigned char *, unsigned char *,
        unsigned char *, unsigned char *);
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
	size_t i, j, k, m;
	struct salsa20_tv_function *tv_function;
	struct salsa20_tv *tv;
	unsigned char *in, *out;
	unsigned char key_tv[KEY_SIZE/8];
	unsigned char iv_tv[IV_SIZE/8];
	unsigned char out_tv[OUTPUT_SIZE];
	int failed = 0;

	for (i = 0; i < N_TV_FUNCTIONS; i++) {
		tv_function = &salsa20_tv_functions[i];

		for (j = 0; j < tv_function->nb_tv; j++) {
			tv = &tv_function->tv[j];
			hex2byte(tv->key, key_tv);
			hex2byte(tv->iv, iv_tv);
			hex2byte(tv->out, out_tv);

			for (k = 0; k < N_FUNCS; k++) {
				in = calloc(1, INPUT_SIZE);
				if (in == NULL)
					errx(1, "calloc in");
				out = calloc(1, OUTPUT_SIZE);
				if (out == NULL)
					errx(1, "calloc out");

				salsa20_test_functions[k].func(tv_function->encrypt_func,
				    key_tv, iv_tv, out, in);

				if (memcmp(out, out_tv, OUTPUT_SIZE) != 0) {
					printf("%s %s failed for \"%s\"\n",
					    tv_function->name, salsa20_test_functions[j].name,
					    tv->comment);

					printf("Got:\t");
					for (m = 0; m < OUTPUT_SIZE; m++)
						printf("%2.2x", out[k]);
					printf("\n");

					printf("Want:\t");
					for (m = 0; m < OUTPUT_SIZE; m++)
						printf("%2.2x", out_tv[m]);
					printf("\n");

					failed = 1;
				}

				free(in);
				free(out);
			}
		}
	}

	return failed;
}
