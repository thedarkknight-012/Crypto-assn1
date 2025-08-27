/*
  salsa20-ref.cpp (patched version to match modern 64-bit counter implementation)

  Based on:
  salsa20-ref.c version 20051118
  D. J. Bernstein
  Public domain.
*/

#include <stdint.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint32_t u32;

/* rotate left */
#define ROTATE(v,c) ((v << c) | (v >> (32 - c)))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) ((u32)((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

/* little-endian load/store */
#define U8TO32_LITTLE(p) \
  (((u32)(p)[0]) | ((u32)(p)[1] << 8) | ((u32)(p)[2] << 16) | ((u32)(p)[3] << 24))

#define U32TO8_LITTLE(p, v)      \
  do {                           \
    (p)[0] = (u8)((v));          \
    (p)[1] = (u8)((v) >> 8);     \
    (p)[2] = (u8)((v) >> 16);    \
    (p)[3] = (u8)((v) >> 24);    \
  } while (0)

typedef struct {
  u32 input[16];
} ECRYPT_ctx;

/* core hash */
static void salsa20_wordtobyte(u8 output[64], const u32 input[16]) {
  u32 x[16];
  int i;

  for (i = 0; i < 16; ++i) x[i] = input[i];
  for (i = 20; i > 0; i -= 2) {
    x[ 4] ^= ROTATE(PLUS(x[ 0],x[12]), 7);
    x[ 8] ^= ROTATE(PLUS(x[ 4],x[ 0]), 9);
    x[12] ^= ROTATE(PLUS(x[ 8],x[ 4]),13);
    x[ 0] ^= ROTATE(PLUS(x[12],x[ 8]),18);
    x[ 9] ^= ROTATE(PLUS(x[ 5],x[ 1]), 7);
    x[13] ^= ROTATE(PLUS(x[ 9],x[ 5]), 9);
    x[ 1] ^= ROTATE(PLUS(x[13],x[ 9]),13);
    x[ 5] ^= ROTATE(PLUS(x[ 1],x[13]),18);
    x[14] ^= ROTATE(PLUS(x[10],x[ 6]), 7);
    x[ 2] ^= ROTATE(PLUS(x[14],x[10]), 9);
    x[ 6] ^= ROTATE(PLUS(x[ 2],x[14]),13);
    x[10] ^= ROTATE(PLUS(x[ 6],x[ 2]),18);
    x[ 3] ^= ROTATE(PLUS(x[15],x[11]), 7);
    x[ 7] ^= ROTATE(PLUS(x[ 3],x[15]), 9);
    x[11] ^= ROTATE(PLUS(x[ 7],x[ 3]),13);
    x[15] ^= ROTATE(PLUS(x[11],x[ 7]),18);
    x[ 1] ^= ROTATE(PLUS(x[ 0],x[ 3]), 7);
    x[ 2] ^= ROTATE(PLUS(x[ 1],x[ 0]), 9);
    x[ 3] ^= ROTATE(PLUS(x[ 2],x[ 1]),13);
    x[ 0] ^= ROTATE(PLUS(x[ 3],x[ 2]),18);
    x[ 6] ^= ROTATE(PLUS(x[ 5],x[ 4]), 7);
    x[ 7] ^= ROTATE(PLUS(x[ 6],x[ 5]), 9);
    x[ 4] ^= ROTATE(PLUS(x[ 7],x[ 6]),13);
    x[ 5] ^= ROTATE(PLUS(x[ 4],x[ 7]),18);
    x[11] ^= ROTATE(PLUS(x[10],x[ 9]), 7);
    x[ 8] ^= ROTATE(PLUS(x[11],x[10]), 9);
    x[ 9] ^= ROTATE(PLUS(x[ 8],x[11]),13);
    x[10] ^= ROTATE(PLUS(x[ 9],x[ 8]),18);
    x[12] ^= ROTATE(PLUS(x[15],x[14]), 7);
    x[13] ^= ROTATE(PLUS(x[12],x[15]), 9);
    x[14] ^= ROTATE(PLUS(x[13],x[12]),13);
    x[15] ^= ROTATE(PLUS(x[14],x[13]),18);
  }
  for (i = 0; i < 16; ++i) x[i] = PLUS(x[i], input[i]);
  for (i = 0; i < 16; ++i) U32TO8_LITTLE(output + 4 * i, x[i]);
}

void ECRYPT_init(void) {
  return;
}

static const char sigma[16] = { 'e','x','p','a','n','d',' ',
                                '3','2','-','b','y','t','e',' ','k' };

void ECRYPT_keysetup(ECRYPT_ctx *x, const u8 *k, u32 /*kbits*/, u32 /*ivbits*/) {
  // Always assume 32-byte key
  x->input[1]  = U8TO32_LITTLE(k + 0);
  x->input[2]  = U8TO32_LITTLE(k + 4);
  x->input[3]  = U8TO32_LITTLE(k + 8);
  x->input[4]  = U8TO32_LITTLE(k + 12);

  k += 16;
  x->input[11] = U8TO32_LITTLE(k + 0);
  x->input[12] = U8TO32_LITTLE(k + 4);
  x->input[13] = U8TO32_LITTLE(k + 8);
  x->input[14] = U8TO32_LITTLE(k + 12);

  x->input[0]  = U8TO32_LITTLE(sigma + 0);
  x->input[5]  = U8TO32_LITTLE(sigma + 4);
  x->input[10] = U8TO32_LITTLE(sigma + 8);
  x->input[15] = U8TO32_LITTLE(sigma + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x, const u8 *iv) {
  x->input[6] = U8TO32_LITTLE(iv + 0);
  x->input[7] = U8TO32_LITTLE(iv + 4);
  x->input[8] = 0;  // counter low
  x->input[9] = 0;  // counter high
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x, const u8 *m, u8 *c, u32 bytes) {
  u8 output[64];
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output, x->input);

    // increment 64-bit counter
    uint64_t ctr = ((uint64_t)x->input[9] << 32) | x->input[8];
    ctr++;
    x->input[8] = (u32)(ctr & 0xffffffff);
    x->input[9] = (u32)(ctr >> 32);

    if (bytes <= 64) {
      for (i = 0; i < (int)bytes; ++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0; i < 64; ++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void ECRYPT_decrypt_bytes(ECRYPT_ctx *x, const u8 *c, u8 *m, u32 bytes) {
  ECRYPT_encrypt_bytes(x, c, m, bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x, u8 *stream, u32 bytes) {
  u32 i;
  for (i = 0; i < bytes; ++i) stream[i] = 0;
  ECRYPT_encrypt_bytes(x, stream, stream, bytes);
}