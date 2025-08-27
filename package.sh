#!/bin/bash
# ============================================================
# EE22B173 - CS6530 Applied Cryptography Assignment 1
# Automation script to generate outputs and package submission
# ============================================================

set -e  # stop if any command fails

BIN=EE22B173_StreamCiphers
SRC=EE22B173_StreamCiphers.c
README=EE22B173_CS6530_Assgn1_Part1_Readme.txt
ZIP=EE22B173_CS6530_Assgn1_Submission.zip

# 1. Compile
echo "[*] Compiling..."
gcc -O2 -std=c99 -Wall -o $BIN $SRC -lm

# 2. Part 1: Diffusion Analysis
echo "[*] Running Part 1 (Diffusion)..."
./$BIN --mode diff --cipher salsa   > EE22B173_CS6530_Assgn1_Part1_Salsa.txt
./$BIN --mode diff --cipher chacha > EE22B173_CS6530_Assgn1_Part1_ChaCha.txt

# 3. Part 2: Encryption & Decryption
echo "[*] Running Part 2 (Enc/Dec)..."
./$BIN --mode enc --cipher salsa \
  --in EE22B173_CS6530_Assgn1_Part1_Salsa.txt \
  --out EE22B173_CS6530_Assgn1_Part1_Salsa_Encrypted.bin

./$BIN --mode dec --cipher salsa \
  --in EE22B173_CS6530_Assgn1_Part1_Salsa_Encrypted.bin \
  --out EE22B173_CS6530_Assgn1_Part1_Salsa_Decrypted.txt

./$BIN --mode enc --cipher chacha \
  --in EE22B173_CS6530_Assgn1_Part1_ChaCha.txt \
  --out EE22B173_CS6530_Assgn1_Part1_ChaCha_Encrypted.bin

./$BIN --mode dec --cipher chacha \
  --in EE22B173_CS6530_Assgn1_Part1_ChaCha_Encrypted.bin \
  --out EE22B173_CS6530_Assgn1_Part1_ChaCha_Decrypted.txt

# 4. Part 3: Benchmark
echo "[*] Running Part 3 (Benchmark)..."
./$BIN --mode bench --cipher salsa   > EE22B173_CS6530_Assgn1_Part3_Salsa.txt
./$BIN --mode bench --cipher chacha  > EE22B173_CS6530_Assgn1_Part3_ChaCha.txt

# 5. Package into zip
echo "[*] Creating final zip package: $ZIP"
zip -r $ZIP $SRC $BIN $README \
   EE22B173_CS6530_Assgn1_Part1_Salsa.txt \
   EE22B173_CS6530_Assgn1_Part1_ChaCha.txt \
   EE22B173_CS6530_Assgn1_Part1_Salsa_Encrypted.bin \
   EE22B173_CS6530_Assgn1_Part1_Salsa_Decrypted.txt \
   EE22B173_CS6530_Assgn1_Part1_ChaCha_Encrypted.bin \
   EE22B173_CS6530_Assgn1_Part1_ChaCha_Decrypted.txt \
   EE22B173_CS6530_Assgn1_Part3_Salsa.txt \
   EE22B173_CS6530_Assgn1_Part3_ChaCha.txt

echo "[*] Done. Submission ready: $ZIP"
