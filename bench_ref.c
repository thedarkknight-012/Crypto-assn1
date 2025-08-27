/*
  benchmark.c
  Benchmarks Salsa20 and ChaCha20 on 100 MB buffer
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// From salsa20-ref.cpp / chacha-ref.c
typedef uint8_t  u8;
typedef uint32_t u32;

typedef struct {
    u32 input[16];
} ECRYPT_ctx;

void ECRYPT_init(void);
void ECRYPT_keysetup(ECRYPT_ctx *x, const u8 *k, u32 kbits, u32 ivbits);
void ECRYPT_ivsetup(ECRYPT_ctx *x, const u8 *iv);
void ECRYPT_encrypt_bytes(ECRYPT_ctx *x, const u8 *m, u8 *c, u32 bytes);

// Timing util
static double elapsed_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) +
           (end.tv_nsec - start.tv_nsec) / 1e9;
}

#define DATA_SIZE   (100 * 1024 * 1024) // 100 MB
#define KEY_SIZE    32
#define NONCE_SIZE  8

// Helper to run one cipher benchmark
static void run_cipher(const char *name,
                       void (*init)(void),
                       void (*keysetup)(ECRYPT_ctx*, const u8*, u32, u32),
                       void (*ivsetup)(ECRYPT_ctx*, const u8*),
                       void (*encrypt)(ECRYPT_ctx*, const u8*, u8*, u32),
                       const u8 *key, const u8 *iv,
                       const u8 *in, u8 *out) {
    ECRYPT_ctx ctx;
    struct timespec start, end;

    init();
    keysetup(&ctx, key, 256, 64);
    ivsetup(&ctx, iv);

    clock_gettime(CLOCK_MONOTONIC, &start);
    encrypt(&ctx, in, out, DATA_SIZE);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double t = elapsed_time(start, end);
    printf("%s: Encrypted 100 MB in %.6f seconds (%.2f MB/s)\n",
           name, t, 100.0 / t);
}

int main() {
    uint8_t *plaintext   = malloc(DATA_SIZE);
    uint8_t *ciphertext  = malloc(DATA_SIZE);

    if (!plaintext || !ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Fill test data
    for (size_t i = 0; i < DATA_SIZE; i++) {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }

    uint8_t key[KEY_SIZE]   = {0};
    uint8_t nonce[NONCE_SIZE] = {0};

    // ---- Run Salsa20 ----
    // compile this file with salsa20-ref.cpp first
    run_cipher("Salsa20",
               ECRYPT_init, ECRYPT_keysetup, ECRYPT_ivsetup, ECRYPT_encrypt_bytes,
               key, nonce, plaintext, ciphertext);

    // ---- Run ChaCha20 ----
    // compile again with chacha-ref.c
    run_cipher("ChaCha20",
               ECRYPT_init, ECRYPT_keysetup, ECRYPT_ivsetup, ECRYPT_encrypt_bytes,
               key, nonce, plaintext, ciphertext);

    free(plaintext);
    free(ciphertext);
    return 0;
}
