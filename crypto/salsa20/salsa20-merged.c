/*
salsa20-merged.c version 20051118
D. J. Bernstein
Public domain.
*/

#include <sys/types.h>

#include <stdint.h>

#define SALSA20_MINKEYLEN 	16
#define SALSA20_NONCELEN	8
#define SALSA20_CTRLEN		8
#define SALSA20_BLOCKLEN	64

struct salsa20_ctx {
	u_int input[16];
	uint8_t keystream[SALSA20_BLOCKLEN];
	size_t available;
};

static inline void salsa20_keysetup(struct salsa20_ctx *x, const u_char *k,
    u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, SALSA20_MINKEYLEN)));
static inline void salsa20_ivsetup(struct salsa20_ctx *x, const u_char *iv,
    u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, SALSA20_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
static inline void salsa20_set_counter(struct salsa20_ctx *x, u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
static inline void salsa20_encrypt_bytes(struct salsa20_ctx *x, const u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct salsa20_ctx salsa20_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
    (((u32)((p)[0])) | \
    ((u32)((p)[1]) <<  8) | \
    ((u32)((p)[2]) << 16) | \
    ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
    do { \
    	(p)[0] = U8V((v)); \
    	(p)[1] = U8V((v) >>  8); \
    	(p)[2] = U8V((v) >> 16); \
    	(p)[3] = U8V((v) >> 24); \
    } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

static inline void
salsa20_keysetup(salsa20_ctx *x, const u8 *k, u32 kbits)
{
	const char *constants;

	x->input[1] = U8TO32_LITTLE(k + 0);
	x->input[2] = U8TO32_LITTLE(k + 4);
	x->input[3] = U8TO32_LITTLE(k + 8);
	x->input[4] = U8TO32_LITTLE(k + 12);
	if (kbits == 256) { /* recommended */
		k += 16;
		constants = sigma;
	} else { /* kbits == 128 */
		constants = tau;
	}
	x->input[11] = U8TO32_LITTLE(k + 0);
	x->input[12] = U8TO32_LITTLE(k + 4);
	x->input[13] = U8TO32_LITTLE(k + 8);
	x->input[14] = U8TO32_LITTLE(k + 12);
	x->input[0] = U8TO32_LITTLE(constants + 0);
	x->input[5] = U8TO32_LITTLE(constants + 4);
	x->input[10] = U8TO32_LITTLE(constants + 8);
	x->input[15] = U8TO32_LITTLE(constants + 12);
}

static inline void
salsa20_ivsetup(salsa20_ctx *x, const u8 *iv, u8* counter)
{
	x->input[6] = U8TO32_LITTLE(iv + 0);
	x->input[7] = U8TO32_LITTLE(iv + 4);
	salsa20_set_counter(x, counter);
}

static inline void
salsa20_set_counter(salsa20_ctx *x, u8* counter)
{
	//x8 and x9 are a counter. This is a block cipher in CTR mode
	x->input[8] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);
	x->input[9] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 4);
}

static inline void
salsa20_encrypt_bytes(salsa20_ctx *x, const u8 *m, u8 *c, u32 bytes)
{
	u32 x0, x1, x2, x3, x4, x5, x6, x7;
	u32 x8, x9, x10, x11, x12, x13, x14, x15;
	u32 j0, j1, j2, j3, j4, j5, j6, j7;
	u32 j8, j9, j10, j11, j12, j13, j14, j15;
	u8 *ctarget = NULL;
	u8 tmp[64];
	u_int i;

	if (!bytes)
		return;

	j0 = x->input[0];
	j1 = x->input[1];
	j2 = x->input[2];
	j3 = x->input[3];
	j4 = x->input[4];
	j5 = x->input[5];
	j6 = x->input[6];
	j7 = x->input[7];
	j8 = x->input[8];
	j9 = x->input[9];
	j10 = x->input[10];
	j11 = x->input[11];
	j12 = x->input[12];
	j13 = x->input[13];
	j14 = x->input[14];
	j15 = x->input[15];

	for (;;) {
		if (bytes < 64) {
			for (i = 0; i < bytes; ++i)
				tmp[i] = m[i];
			m = tmp;
			ctarget = c;
			c = tmp;
		}
		x0 = j0;
		x1 = j1;
		x2 = j2;
		x3 = j3;
		x4 = j4;
		x5 = j5;
		x6 = j6;
		x7 = j7;
		x8 = j8;
		x9 = j9;
		x10 = j10;
		x11 = j11;
		x12 = j12;
		x13 = j13;
		x14 = j14;
		x15 = j15;
		for (i = 20; i > 0; i -= 2) {
			x4 = XOR(x4, ROTATE(PLUS(x0, x12), 7));
			x8 = XOR(x8, ROTATE(PLUS(x4, x0), 9));
			x12 = XOR(x12, ROTATE(PLUS(x8, x4),13));
			x0 = XOR(x0, ROTATE(PLUS(x12, x8),18));
			x9 = XOR(x9, ROTATE(PLUS(x5, x1), 7));
			x13 = XOR(x13, ROTATE(PLUS(x9, x5), 9));
			x1 = XOR(x1, ROTATE(PLUS(x13, x9), 13));
			x5 = XOR(x5, ROTATE(PLUS(x1,x13), 18));
			x14 = XOR(x14, ROTATE(PLUS(x10, x6), 7));
			x2 = XOR(x2, ROTATE(PLUS(x14,x10), 9));
			x6 = XOR(x6, ROTATE(PLUS(x2,x14), 13));
			x10 = XOR(x10, ROTATE(PLUS(x6, x2), 18));
			x3 = XOR(x3, ROTATE(PLUS(x15, x11), 7));
			x7 = XOR(x7, ROTATE(PLUS(x3, x15), 9));
			x11 = XOR(x11, ROTATE(PLUS(x7, x3), 13));
			x15 = XOR(x15, ROTATE(PLUS(x11, x7), 18));
			x1 = XOR(x1, ROTATE(PLUS(x0, x3), 7));
			x2 = XOR(x2, ROTATE(PLUS(x1, x0), 9));
			x3 = XOR(x3, ROTATE(PLUS(x2, x1), 13));
			x0 = XOR(x0, ROTATE(PLUS(x3, x2), 18));
			x6 = XOR(x6, ROTATE(PLUS(x5, x4), 7));
			x7 = XOR(x7, ROTATE(PLUS(x6, x5), 9));
			x4 = XOR(x4, ROTATE(PLUS(x7, x6), 13));
			x5 = XOR(x5, ROTATE(PLUS(x4, x7), 18));
			x11 = XOR(x11, ROTATE(PLUS(x10, x9), 7));
			x8 = XOR(x8, ROTATE(PLUS(x11, x10), 9));
			x9 = XOR(x9, ROTATE(PLUS(x8, x11), 13));
			x10 = XOR(x10, ROTATE(PLUS(x9, x8), 18));
			x12 = XOR(x12, ROTATE(PLUS(x15, x14), 7));
			x13 = XOR(x13, ROTATE(PLUS(x12, x15), 9));
			x14 = XOR(x14, ROTATE(PLUS(x13, x12), 13));
			x15 = XOR(x15, ROTATE(PLUS(x14, x13), 18));
		}
		x0 = PLUS(x0, j0);
		x1 = PLUS(x1, j1);
		x2 = PLUS(x2, j2);
		x3 = PLUS(x3, j3);
		x4 = PLUS(x4, j4);
		x5 = PLUS(x5, j5);
		x6 = PLUS(x6, j6);
		x7 = PLUS(x7, j7);
		x8 = PLUS(x8, j8);
		x9 = PLUS(x9, j9);
		x10 = PLUS(x10, j10);
		x11 = PLUS(x11, j11);
		x12 = PLUS(x12, j12);
		x13 = PLUS(x13, j13);
		x14 = PLUS(x14, j14);
		x15 = PLUS(x15, j15);

		if (bytes < 64) {
			U32TO8_LITTLE(x->keystream + 0, x0);
			U32TO8_LITTLE(x->keystream + 4, x1);
			U32TO8_LITTLE(x->keystream + 8, x2);
			U32TO8_LITTLE(x->keystream + 12, x3);
			U32TO8_LITTLE(x->keystream + 16, x4);
			U32TO8_LITTLE(x->keystream + 20, x5);
			U32TO8_LITTLE(x->keystream + 24, x6);
			U32TO8_LITTLE(x->keystream + 28, x7);
			U32TO8_LITTLE(x->keystream + 32, x8);
			U32TO8_LITTLE(x->keystream + 36, x9);
			U32TO8_LITTLE(x->keystream + 40, x10);
			U32TO8_LITTLE(x->keystream + 44, x11);
			U32TO8_LITTLE(x->keystream + 48, x12);
			U32TO8_LITTLE(x->keystream + 52, x13);
			U32TO8_LITTLE(x->keystream + 56, x14);
			U32TO8_LITTLE(x->keystream + 60, x15);
		}

		x0 = XOR(x0, U8TO32_LITTLE(m + 0));
		x1 = XOR(x1, U8TO32_LITTLE(m + 4));
		x2 = XOR(x2, U8TO32_LITTLE(m + 8));
		x3 = XOR(x3, U8TO32_LITTLE(m + 12));
		x4 = XOR(x4, U8TO32_LITTLE(m + 16));
		x5 = XOR(x5, U8TO32_LITTLE(m + 20));
		x6 = XOR(x6, U8TO32_LITTLE(m + 24));
		x7 = XOR(x7, U8TO32_LITTLE(m + 28));
		x8 = XOR(x8, U8TO32_LITTLE(m + 32));
		x9 = XOR(x9, U8TO32_LITTLE(m + 36));
		x10 = XOR(x10, U8TO32_LITTLE(m + 40));
		x11 = XOR(x11, U8TO32_LITTLE(m + 44));
		x12 = XOR(x12, U8TO32_LITTLE(m + 48));
		x13 = XOR(x13, U8TO32_LITTLE(m + 52));
		x14 = XOR(x14, U8TO32_LITTLE(m + 56));
		x15 = XOR(x15, U8TO32_LITTLE(m + 60));

		j8 = PLUSONE(j8);
		if (!j8) {
			j9 = PLUSONE(j9);
			/* stopping at 2^70 bytes per nonce is user's responsibility */
		}

		U32TO8_LITTLE(c + 0, x0);
		U32TO8_LITTLE(c + 4, x1);
		U32TO8_LITTLE(c + 8, x2);
		U32TO8_LITTLE(c + 12, x3);
		U32TO8_LITTLE(c + 16, x4);
		U32TO8_LITTLE(c + 20, x5);
		U32TO8_LITTLE(c + 24, x6);
		U32TO8_LITTLE(c + 28, x7);
		U32TO8_LITTLE(c + 32, x8);
		U32TO8_LITTLE(c + 36, x9);
		U32TO8_LITTLE(c + 40, x10);
		U32TO8_LITTLE(c + 44, x11);
		U32TO8_LITTLE(c + 48, x12);
		U32TO8_LITTLE(c + 52, x13);
		U32TO8_LITTLE(c + 56, x14);
		U32TO8_LITTLE(c + 60, x15);

		if (bytes <= 64) {
			if (bytes < 64) {
				for (i = 0;i < bytes;++i)
					ctarget[i] = c[i];
			}
			x->input[8] = j8;
			x->input[9] = j9;
			x->available = 64 - bytes;
			return;
		}
		bytes -= 64;
		c += 64;
		m += 64;
	}
}
