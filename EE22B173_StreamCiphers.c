/*
 EE22B173_StreamCiphers.c
 Implements Salsa20 and ChaCha20 keystream generation, file encryption/decryption,
 diffusion analysis, detailed logging toggle, and performance benchmark.

 Deliverables produced by running this program (examples):
  - EE22B173_CS6530_Assgn1_Part1.txt         (diffusion analysis log)
  - EE22B173_CS6530_Assgn1_Part1_Encrypted.bin
  - EE22B173_CS6530_Assgn1_Part1_Decrypted.bin
  - EE22B173_CS6530_Assgn1_Part2.txt         (observations & verification info)
  - EE22B173_CS6530_Assgn1_Part3.txt         (performance comparison output)

 Compile:
   gcc -O2 -std=c99 -o EE22B173_StreamCiphers EE22B173_StreamCiphers.c -lm

 Usage examples:
   ./EE22B173_StreamCiphers --mode diff --cipher salsa  [--detailed]
   ./EE22B173_StreamCiphers --mode enc  --cipher chacha --in EE22B173_CS6530_Assgn1_Part1.txt --out EE22B173_CS6530_Assgn1_Part1_Encrypted.bin
   ./EE22B173_StreamCiphers --mode dec  --cipher chacha --in EE22B173_CS6530_Assgn1_Part1_Encrypted.bin --out EE22B173_CS6530_Assgn1_Part1_Decrypted.bin
   ./EE22B173_StreamCiphers --mode bench --cipher salsa

 Notes:
  - Uses all-zero key & nonce by default for reproducibility (match assignment diffusion tests).
  - Encryption/decryption use XOR with generated keystream; same program handles both.
  - --detailed prints internal double-round states to stdout (useful for TA verification).
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <errno.h>

/* ---------------------------
   Timing helper
   --------------------------- */
double now_seconds() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---------------------------
   Command-line parsing
   --------------------------- */
#define MAXPATH 1024
typedef enum {MODE_DIFF, MODE_ENC, MODE_DEC, MODE_BENCH, MODE_HELP,MODE_TEST} run_mode_t;
typedef enum {CIPHER_SALSA, CIPHER_CHACHA} cipher_t;

typedef struct {
    run_mode_t mode;
    cipher_t cipher;
    int detailed_logs;
    char in_file[MAXPATH];
    char out_file[MAXPATH];
} options_t;

void print_help() {
    printf("EE22B173 Stream Ciphers tool\n");
    printf("Usage examples:\n");
    printf("  --mode diff --cipher salsa  [--detailed]\n");
    printf("  --mode enc  --cipher chacha --in plain.txt --out out.bin\n");
    printf("  --mode dec  --cipher chacha --in out.bin   --out plain_dec.txt\n");
    printf("  --mode bench --cipher salsa\n");
    printf("\nOptions:\n");
    printf("  --mode {diff,enc,dec,bench}\n");
    printf("  --cipher {salsa,chacha}\n");
    printf("  --detailed   (print detailed double-round/logs)\n");
    printf("  --in <file>  (input file)\n");
    printf("  --out <file> (output file)\n");
}

/* ---------------------------
   Bit ops and rotations
   --------------------------- */
static inline uint32_t ROL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* ---------------------------
   Salsa20 core
   --------------------------- */

static void salsa20_quarterround(uint32_t *y, int a, int b, int c, int d) {
    y[b] ^= ROL32(y[a] + y[d], 7);
    y[c] ^= ROL32(y[b] + y[a], 9);
    y[d] ^= ROL32(y[c] + y[b],13);
    y[a] ^= ROL32(y[d] + y[c],18);
}

/* Helper: convert little-endian bytes to uint32 (portable) */
static uint32_t u32_from_le_bytes(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void u32_to_le_bytes(uint32_t v, uint8_t *b) {
    b[0] = v & 0xFF;
    b[1] = (v >> 8) & 0xFF;
    b[2] = (v >> 16) & 0xFF;
    b[3] = (v >> 24) & 0xFF;
}

/* Salsa20 core producing 64-byte block from key(32), nonce(8), counter(64-bit) */
void salsa20_core(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter, uint8_t out[64], int detailed) {
    uint32_t state[16], x[16];
    const uint8_t sigma[16] = "expand 32-byte k";

    /* little-endian load */
    state[0]  = u32_from_le_bytes(sigma + 0);
    state[5]  = u32_from_le_bytes(sigma + 4);
    state[10] = u32_from_le_bytes(sigma + 8);
    state[15] = u32_from_le_bytes(sigma + 12);

    for (int i = 0; i < 8; ++i) state[1 + i] = u32_from_le_bytes(key + 4*i);

    /* nonce (8 bytes) at positions 6,7 and counter at 8,9 (little-endian) */
    state[6] = u32_from_le_bytes(nonce + 0);
    state[7] = u32_from_le_bytes(nonce + 4);
    state[8] = (uint32_t)(counter & 0xFFFFFFFFu);
    state[9] = (uint32_t)((counter >> 32) & 0xFFFFFFFFu);

    for (int i = 0; i < 16; ++i) x[i] = state[i];

    for (int round = 0; round < 10; ++round) {
        /* column rounds */
        salsa20_quarterround(x, 0, 4, 8,12);
        salsa20_quarterround(x, 5, 9,13, 1);
        salsa20_quarterround(x,10,14, 2, 6);
        salsa20_quarterround(x,15, 3, 7,11);

        /* row rounds */
        salsa20_quarterround(x, 0, 1, 2, 3);
        salsa20_quarterround(x, 5, 6, 7, 4);
        salsa20_quarterround(x,10,11, 8, 9);
        salsa20_quarterround(x,15,12,13,14);

        if (detailed) {
            printf("Salsa20 double-round %d state:\n", round);
            for (int i = 0; i < 16; ++i) printf("%08x ", x[i]);
            printf("\n");
        }
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t z = x[i] + state[i];
        u32_to_le_bytes(z, out + 4*i);
    }
}

/* ---------------------------
   ChaCha20 core
   --------------------------- */

static inline void chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROL32(*d,16);
    *c += *d; *b ^= *c; *b = ROL32(*b,12);
    *a += *b; *d ^= *a; *d = ROL32(*d,8);
    *c += *d; *b ^= *c; *b = ROL32(*b,7);
}

/* ChaCha20 block: key 32 bytes, nonce 12 bytes, counter 64-bit (we use low 32bits here) */
void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint64_t counter, uint8_t out[64], int detailed) {
    uint32_t state[16], working[16];
    const uint8_t constants[16] = "expand 32-byte k";

    state[0] = u32_from_le_bytes(constants + 0);
    state[1] = u32_from_le_bytes(constants + 4);
    state[2] = u32_from_le_bytes(constants + 8);
    state[3] = u32_from_le_bytes(constants + 12);

    for (int i = 0; i < 8; ++i) state[4 + i] = u32_from_le_bytes(key + 4*i);

    /* counter (low 32 bits) and nonce (3 words) */
    state[12] = (uint32_t)(counter & 0xFFFFFFFFu);
    state[13] = u32_from_le_bytes(nonce + 0);
    state[14] = u32_from_le_bytes(nonce + 4);
    state[15] = u32_from_le_bytes(nonce + 8);

    for (int i = 0; i < 16; ++i) working[i] = state[i];

    for (int round = 0; round < 10; ++round) {
        /* column rounds */
        chacha20_quarterround(&working[0], &working[4], &working[8], &working[12]);
        chacha20_quarterround(&working[1], &working[5], &working[9], &working[13]);
        chacha20_quarterround(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarterround(&working[3], &working[7], &working[11], &working[15]);
        /* diagonal rounds */
        chacha20_quarterround(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarterround(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarterround(&working[2], &working[7], &working[8], &working[13]);
        chacha20_quarterround(&working[3], &working[4], &working[9], &working[14]);

        if (detailed) {
            printf("ChaCha20 double-round %d state:\n", round);
            for (int i = 0; i < 16; ++i) printf("%08x ", working[i]);
            printf("\n");
        }
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t z = working[i] + state[i];
        u32_to_le_bytes(z, out + 4*i);
    }
}

/* ---------------------------
   Keystream generation helpers
   --------------------------- */

void generate_keystream_salsa(const uint8_t key[32], const uint8_t nonce[8],
                              uint64_t start_counter, uint8_t *out, size_t nbytes, int detailed) {
    size_t full_blocks = nbytes / 64;
    size_t rem = nbytes % 64;
    uint8_t block[64];
    for (size_t i = 0; i < full_blocks; ++i) {
        salsa20_core(key, nonce, start_counter + i, block, detailed);
        memcpy(out + i*64, block, 64);
    }
    if (rem) {
        salsa20_core(key, nonce, start_counter + full_blocks, block, detailed);
        memcpy(out + full_blocks*64, block, rem);
    }
}

void generate_keystream_chacha(const uint8_t key[32], const uint8_t nonce[12],
                               uint64_t start_counter, uint8_t *out, size_t nbytes, int detailed) {
    size_t full_blocks = nbytes / 64;
    size_t rem = nbytes % 64;
    uint8_t block[64];
    for (size_t i = 0; i < full_blocks; ++i) {
        chacha20_block(key, nonce, start_counter + i, block, detailed);
        memcpy(out + i*64, block, 64);
    }
    if (rem) {
        chacha20_block(key, nonce, start_counter + full_blocks, block, detailed);
        memcpy(out + full_blocks*64, block, rem);
    }
}

/* ---------------------------
   File encryption/decryption (XOR)
   --------------------------- */

int file_size_bytes(const char *path, size_t *out_size) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out_size = (size_t)st.st_size;
    return 0;
}

int encrypt_file_with_keystream(
    int use_salsa,
    const uint8_t key[32],
    const uint8_t nonce_salsa8_or_chacha12[], /* 8 bytes for salsa, 12 for chacha */
    uint64_t start_counter,
    const char *in_path,
    const char *out_path,
    int detailed,
    double *time_taken) {

    FILE *fin = fopen(in_path, "rb");
    if (!fin) { fprintf(stderr, "open in failed: %s\n", strerror(errno)); return -1; }
    FILE *fout = fopen(out_path, "wb");
    if (!fout) { fclose(fin); fprintf(stderr, "open out failed: %s\n", strerror(errno)); return -1; }

    size_t in_size;
    if (file_size_bytes(in_path, &in_size) != 0) in_size = 0;

    double t0 = now_seconds();

    const size_t CHUNK = 64 * 1024; /* 64 KB chunk - multiple of 64 */
    uint8_t *buf = malloc(CHUNK);
    uint8_t *ks  = malloc(CHUNK);
    if (!buf || !ks) { fclose(fin); fclose(fout); free(buf); free(ks); return -1; }

    size_t block_counter = (size_t)start_counter;
    size_t read;
    while ((read = fread(buf, 1, CHUNK, fin)) > 0) {
        if (use_salsa) {
            generate_keystream_salsa(key, nonce_salsa8_or_chacha12, block_counter, ks, read, detailed);
        } else {
            generate_keystream_chacha(key, nonce_salsa8_or_chacha12, block_counter, ks, read, detailed);
        }
        for (size_t i = 0; i < read; ++i) buf[i] ^= ks[i];
        size_t wrote = fwrite(buf, 1, read, fout);
        (void)wrote;
        size_t blocks = (read + 63) / 64;
        block_counter += blocks;
    }

    double t1 = now_seconds();
    if (time_taken) *time_taken = t1 - t0;

    free(buf); free(ks);
    fclose(fin); fclose(fout);
    return 0;
}

/* ---------------------------
   Utilities for hex printing and bit-diff counting
   --------------------------- */

void print_hex(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", buf[i]);
    printf("\n");
}

int count_bit_differences(const uint8_t *a, const uint8_t *b, size_t n) {
    int diffs = 0;
    for (size_t i = 0; i < n; ++i) diffs += __builtin_popcount((uint32_t)(a[i] ^ b[i]));
    return diffs;
}

/* ---------------------------
   High-level tasks: diffusion analysis, benchmark
   --------------------------- */

void write_part1_header(FILE *f, const char *ciphername) {
    fprintf(f, "Roll no: EE22B173\nCipher: %s\nKey: all-zero (32 bytes)\nNonce: all-zero (salsa:8, chacha:12)\nCounter pairs tested: (0 vs 1) and (173 vs 174)\n\n", ciphername);
}

void do_diffusion_analysis_salsa(int detailed) {
    const char *out_fname = "EE22B173_CS6530_Assgn1_Part1.txt";
    FILE *f = fopen(out_fname, "w");
    if (!f) { fprintf(stderr, "Unable to open %s for writing\n", out_fname); return; }

    uint8_t key[32] = {0};
    uint8_t nonce[8] = {0};
    uint8_t ks0[64], ks1[64];

    /* pair 1: counter 0 vs 1 */
    salsa20_core(key, nonce, 0, ks0, detailed);
    salsa20_core(key, nonce, 1, ks1, detailed);
    int diff01 = count_bit_differences(ks0, ks1, 64);

    /* pair 2: counter 173 vs 174 */
    salsa20_core(key, nonce, 173, ks0, detailed);
    salsa20_core(key, nonce, 174, ks1, detailed);
    int diff173 = count_bit_differences(ks0, ks1, 64);

    write_part1_header(f, "Salsa20");
    /* For clarity: re-generate values cleanly to print correct pairs */
    salsa20_core(key, nonce, 0, ks0, 0);
    salsa20_core(key, nonce, 1, ks1, 0);
    fprintf(f, "--- Counter 0 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks0[i]); fprintf(f,"\n");
    fprintf(f, "--- Counter 1 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks1[i]); fprintf(f,"\n");
    fprintf(f, "Bit differences between counter 0 and 1: %d bits (out of 512)\n\n", diff01);

    salsa20_core(key, nonce, 173, ks0, 0);
    salsa20_core(key, nonce, 174, ks1, 0);
    fprintf(f, "--- Counter 173 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks0[i]); fprintf(f,"\n");
    fprintf(f, "--- Counter 174 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks1[i]); fprintf(f,"\n");
    fprintf(f, "Bit differences between counter 173 and 174: %d bits (out of 512)\n\n", diff173);

    fprintf(f, "Notes: Key & Nonce are all-zero. Counters altered to check diffusion; measure number of bit differences.\n");
    fclose(f);

    size_t sz; if (file_size_bytes(out_fname, &sz)==0) printf("Wrote %s (%zu bytes)\n", out_fname, sz);
}

void do_diffusion_analysis_chacha(int detailed) {
    const char *out_fname = "EE22B173_CS6530_Assgn1_Part1.txt";
    FILE *f = fopen(out_fname, "w");
    if (!f) { fprintf(stderr, "Unable to open %s for writing\n", out_fname); return; }

    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t ks0[64], ks1[64];

    chacha20_block(key, nonce, 0, ks0, detailed);
    chacha20_block(key, nonce, 1, ks1, detailed);
    int diff01 = count_bit_differences(ks0, ks1, 64);

    chacha20_block(key, nonce, 173, ks0, detailed);
    chacha20_block(key, nonce, 174, ks1, detailed);
    int diff173 = count_bit_differences(ks0, ks1, 64);

    write_part1_header(f, "ChaCha20");
    chacha20_block(key, nonce, 0, ks0, 0);
    chacha20_block(key, nonce, 1, ks1, 0);
    fprintf(f, "--- Counter 0 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks0[i]); fprintf(f,"\n");
    fprintf(f, "--- Counter 1 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks1[i]); fprintf(f,"\n");
    fprintf(f, "Bit differences between counter 0 and 1: %d bits (out of 512)\n\n", diff01);

    chacha20_block(key, nonce, 173, ks0, 0);
    chacha20_block(key, nonce, 174, ks1, 0);
    fprintf(f, "--- Counter 173 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks0[i]); fprintf(f,"\n");
    fprintf(f, "--- Counter 174 keystream (64 bytes) ---\n"); for (int i=0;i<64;i++) fprintf(f,"%02x", ks1[i]); fprintf(f,"\n");
    fprintf(f, "Bit differences between counter 173 and 174: %d bits (out of 512)\n\n", diff173);

    fprintf(f, "Notes: Key & Nonce are all-zero. Counters altered to check diffusion; measure number of bit differences.\n");
    fclose(f);

    size_t sz; if (file_size_bytes(out_fname, &sz)==0) printf("Wrote %s (%zu bytes)\n", out_fname, sz);
}

/* ---------------------------
   Benchmark (Part 3)
   --------------------------- */
void do_benchmark(cipher_t cipher, int detailed) {
    const size_t TEST_SIZE = 100 * 1024 * 1024; // 100 MB
    uint8_t *buf = malloc(TEST_SIZE);
    uint8_t *ks  = malloc(TEST_SIZE);
    if (!buf || !ks) { fprintf(stderr, "malloc failed for benchmark\n"); free(buf); free(ks); return; }

    memset(buf, 0xAA, TEST_SIZE); // dummy data

    uint8_t key[32] = {0};
    uint8_t nonce_salsa[8] = {0};
    uint8_t nonce_chacha[12] = {0};

    double t0 = now_seconds();
    if (cipher == CIPHER_SALSA) {
        generate_keystream_salsa(key, nonce_salsa, 0, ks, TEST_SIZE, detailed);
    } else {
        generate_keystream_chacha(key, nonce_chacha, 0, ks, TEST_SIZE, detailed);
    }
    for (size_t i = 0; i < TEST_SIZE; i++) buf[i] ^= ks[i];
    double t1 = now_seconds();

    double seconds = t1 - t0;
    double mbps = (double)TEST_SIZE / (1024.0*1024.0) / seconds;
    printf("%s benchmark: %.2f MB in %.3f sec = %.2f MB/s\n",
           (cipher==CIPHER_SALSA)?"Salsa20":"ChaCha20",
           (double)TEST_SIZE / (1024.0*1024.0), seconds, mbps);

    FILE *f = fopen("EE22B173_CS6530_Assgn1_Part3.txt","a");
    if (f) {
        fprintf(f,"%s benchmark: %.2f MB processed in %.3f sec => %.2f MB/s\n",
                (cipher==CIPHER_SALSA)?"Salsa20":"ChaCha20",
                (double)TEST_SIZE / (1024.0*1024.0), seconds, mbps);
        fclose(f);
    }

    free(buf); free(ks);
}
void do_selftest() {
    uint8_t key[32] = {0};
    uint8_t nonce8[8] = {0};
    uint8_t nonce12[12] = {0};
    uint8_t out[64];

    printf("=== Self-test (Salsa20/ChaCha20, all-zero key & nonce) ===\n");

    salsa20_core(key, nonce8, 0, out, 0);
    printf("Salsa20 block 0:\n"); print_hex(out, 64);

    chacha20_block(key, nonce12, 0, out, 0);
    printf("ChaCha20 block 0:\n"); print_hex(out, 64);

    printf("Check against RFC 8439 test vectors (first 64 bytes)\n");
    printf("If your outputs match, implementation is correct.\n");
}


/* ---------------------------
   Main driver
   --------------------------- */

int main(int argc, char **argv) {
    options_t opt;
    opt.mode = MODE_HELP;
    opt.cipher = CIPHER_SALSA;
    opt.detailed_logs = 0;
    opt.in_file[0] = '\0';
    opt.out_file[0] = '\0';

    if (argc == 1) { print_help(); return 0; }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i+1 < argc) {
            ++i;
            if (strcmp(argv[i], "diff") == 0) opt.mode = MODE_DIFF;
            else if (strcmp(argv[i], "enc") == 0) opt.mode = MODE_ENC;
            else if (strcmp(argv[i], "test") == 0) opt.mode = MODE_TEST;
            else if (strcmp(argv[i], "dec") == 0) opt.mode = MODE_DEC;
            else if (strcmp(argv[i], "bench") == 0) opt.mode = MODE_BENCH;
            else { fprintf(stderr, "unknown mode %s\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--cipher") == 0 && i+1 < argc) {
            ++i;
            if (strcmp(argv[i], "salsa") == 0) opt.cipher = CIPHER_SALSA;
            else if (strcmp(argv[i], "chacha") == 0) opt.cipher = CIPHER_CHACHA;
            else { fprintf(stderr, "unknown cipher %s\n", argv[i]); return 1; }
        } else if (strcmp(argv[i], "--detailed") == 0) {
            opt.detailed_logs = 1;
        } else if (strcmp(argv[i], "--in") == 0 && i+1 < argc) {
            ++i; strncpy(opt.in_file, argv[i], MAXPATH-1);
        } else if (strcmp(argv[i], "--out") == 0 && i+1 < argc) {
            ++i; strncpy(opt.out_file, argv[i], MAXPATH-1);
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            print_help();
            return 1;
        }
    }
    if (opt.mode == MODE_TEST) {
        do_selftest();
        return 0;
    }


    if (opt.mode == MODE_HELP) { print_help(); return 0; }

    if (opt.mode == MODE_DIFF) {
        if (opt.cipher == CIPHER_SALSA) {
            printf("Running diffusion analysis (Salsa20), detailed=%d\n", opt.detailed_logs);
            do_diffusion_analysis_salsa(opt.detailed_logs);
        } else {
            printf("Running diffusion analysis (ChaCha20), detailed=%d\n", opt.detailed_logs);
            do_diffusion_analysis_chacha(opt.detailed_logs);
        }
        printf("Diffusion analysis done. See EE22B173_CS6530_Assgn1_Part1.txt\n");
        return 0;
    }

    if (opt.mode == MODE_BENCH) {
        printf("Running benchmark for %s, detailed=%d\n", (opt.cipher==CIPHER_SALSA)?"Salsa20":"ChaCha20", opt.detailed_logs);
        do_benchmark(opt.cipher, opt.detailed_logs);
        printf("Benchmark results appended to EE22B173_CS6530_Assgn1_Part3.txt\n");
        return 0;
    }

    /* For enc/dec, input & output must be provided */
    if ((opt.mode == MODE_ENC || opt.mode == MODE_DEC) && (opt.in_file[0] == '\0' || opt.out_file[0] == '\0')) {
        fprintf(stderr, "For enc/dec please provide --in and --out\n");
        return 1;
    }

    /* Use zero key/nonce for reproducibility per assignment - you can change if needed */
    uint8_t key[32] = {0};
    uint8_t nonce_salsa[8] = {0};
    uint8_t nonce_chacha[12] = {0};

    double elapsed = 0.0;
    int err;
    if (opt.mode == MODE_ENC) {
        printf("Encrypting %s -> %s using %s\n", opt.in_file, opt.out_file,
               (opt.cipher==CIPHER_SALSA) ? "Salsa20" : "ChaCha20");
        err = encrypt_file_with_keystream(opt.cipher == CIPHER_SALSA, key,
                                         (opt.cipher == CIPHER_SALSA) ? (uint8_t*)nonce_salsa : (uint8_t*)nonce_chacha,
                                         0 /* start counter */, opt.in_file, opt.out_file, opt.detailed_logs, &elapsed);
        if (err) { fprintf(stderr, "Encryption failed\n"); return 1; }
        printf("Encryption done in %.6f seconds\n", elapsed);

        size_t out_sz; if (file_size_bytes(opt.out_file, &out_sz)==0) printf("Encrypted file size: %zu bytes\n", out_sz);

        FILE *f = fopen("EE22B173_CS6530_Assgn1_Part2.txt", "w");
        if (f) {
            fprintf(f, "Encryption: input=%s output=%s cipher=%s time=%.6f seconds\n",
                    opt.in_file, opt.out_file, (opt.cipher==CIPHER_SALSA) ? "Salsa20" : "ChaCha20", elapsed);
            fclose(f);
            size_t sz; if (file_size_bytes("EE22B173_CS6530_Assgn1_Part2.txt",&sz)==0) printf("Wrote EE22B173_CS6530_Assgn1_Part2.txt (%zu bytes)\n", sz);
        }
    } else if (opt.mode == MODE_DEC) {
        printf("Decrypting %s -> %s using %s\n", opt.in_file, opt.out_file,
               (opt.cipher==CIPHER_SALSA) ? "Salsa20" : "ChaCha20");
        err = encrypt_file_with_keystream(opt.cipher == CIPHER_SALSA, key,
                                         (opt.cipher == CIPHER_SALSA) ? (uint8_t*)nonce_salsa : (uint8_t*)nonce_chacha,
                                         0 /* start counter */, opt.in_file, opt.out_file, opt.detailed_logs, &elapsed);
        if (err) { fprintf(stderr, "Decryption failed\n"); return 1; }
        printf("Decryption done in %.6f seconds\n", elapsed);
        size_t out_sz; if (file_size_bytes(opt.out_file, &out_sz)==0) printf("Decrypted file size: %zu bytes\n", out_sz);

        /* Verification: compare decrypted with original Part1 file if available */
        FILE *orig = fopen("EE22B173_CS6530_Assgn1_Part1.txt","rb");
        if (orig) {
            fseek(orig, 0, SEEK_END);
            size_t orig_sz = ftell(orig);
            fclose(orig);
            size_t dec_sz; if (file_size_bytes(opt.out_file, &dec_sz)==0) {
                FILE *fa = fopen("EE22B173_CS6530_Assgn1_Part2.txt","a");
                if (orig_sz != dec_sz) {
                    printf("Warning: original Part1.txt size (%zu) differs from decrypted (%zu)\n", orig_sz, dec_sz);
                    if (fa) { fprintf(fa, "Verification: sizes differ original=%zu decrypted=%zu\n", orig_sz, dec_sz); fclose(fa); }
                } else {
                    FILE *f1 = fopen("EE22B173_CS6530_Assgn1_Part1.txt","rb");
                    FILE *f2 = fopen(opt.out_file,"rb");
                    int eq = 1;
                    while (1) {
                        int c1 = fgetc(f1);
                        int c2 = fgetc(f2);
                        if (c1 == EOF && c2 == EOF) break;
                        if (c1 != c2) { eq = 0; break; }
                    }
                    fclose(f1); fclose(f2);
                    FILE *fb = fopen("EE22B173_CS6530_Assgn1_Part2.txt","a");
                    if (fb) { fprintf(fb, "Verification: decrypted equals original Part1.txt ? %s\n", eq ? "YES" : "NO"); fclose(fb); }
                    printf("Verification: decrypted equals original Part1.txt ? %s\n", eq ? "YES" : "NO");
                }
            }
        } else {
            printf("Original EE22B173_CS6530_Assgn1_Part1.txt not found; cannot auto-verify.\n");
        }
    }

    return 0;
}