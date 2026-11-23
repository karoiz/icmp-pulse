/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * icmp-pulse - ChaCha20-Poly1305 AEAD (RFC 8439), no external libraries
 *
 * Key 32 bytes, nonce 12 bytes, tag 16 bytes.
 * Portable (MIPS BE/LE, ARM, x86) and constant-time.
 *
 * Copyright (C) 2026 Karol Dudek <karoiz@sli.pl>
 */
#ifndef ICMP_PULSE_CHACHAPOLY_H
#define ICMP_PULSE_CHACHAPOLY_H

#include <stdint.h>
#include <stddef.h>

#define CP_KEY_LEN   32
#define CP_NONCE_LEN 12
#define CP_TAG_LEN   16

/* One ChaCha20 block (64 bytes of keystream) for the given counter and nonce. */
void chacha20_block(const uint8_t key[CP_KEY_LEN], uint32_t counter,
                    const uint8_t nonce[CP_NONCE_LEN], uint8_t out[64]);

/* ChaCha20 encryption/decryption (XOR with keystream) starting at `counter`.
 * `in` and `out` may point to the same buffer. */
void chacha20_xor(const uint8_t key[CP_KEY_LEN], uint32_t counter,
                  const uint8_t nonce[CP_NONCE_LEN],
                  const uint8_t *in, uint8_t *out, size_t len);

/* Poly1305 with a 32-byte one-time key. */
void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len,
                  uint8_t tag[CP_TAG_LEN]);

/* AEAD: encrypts `len` bytes from `pt` into `ct` (may be the same buffer)
 * and computes the tag over `aad` and the ciphertext. */
void cp_encrypt(const uint8_t key[CP_KEY_LEN], const uint8_t nonce[CP_NONCE_LEN],
                const uint8_t *aad, size_t aad_len,
                const uint8_t *pt, size_t len, uint8_t *ct,
                uint8_t tag[CP_TAG_LEN]);

/* AEAD: verifies the tag and only then decrypts. Returns 0 if the tag is
 * valid, -1 otherwise (`pt` is not written in that case). */
int cp_decrypt(const uint8_t key[CP_KEY_LEN], const uint8_t nonce[CP_NONCE_LEN],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *ct, size_t len, const uint8_t tag[CP_TAG_LEN],
               uint8_t *pt);

/* Constant-time comparison: returns 0 if equal. */
int cp_memeq_ct(const void *a, const void *b, size_t len);

/* Memory wipe that the compiler will not optimise away. */
void cp_wipe(void *p, size_t len);

#endif
