// SPDX-License-Identifier: GPL-2.0-only
/*
 * icmp-pulse - ChaCha20-Poly1305 AEAD as specified in RFC 8439
 *
 * ChaCha20: 20 rounds, 4x4 state of 32-bit words, little-endian output.
 * Poly1305: arithmetic modulo 2^130 - 5 on five 26-bit limbs ("donna-32"
 * variant), 32x32->64-bit multiplications only - runs on any CPU.
 *
 * All multi-byte loads/stores go through ld32/st32, so the code does not
 * depend on byte order or memory alignment.
 *
 * Copyright (C) 2026 Karol Dudek <karoiz@sli.pl>
 */
#include <string.h>
#include "chachapoly.h"

static uint32_t ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	       (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void st64(uint8_t *p, uint64_t v)
{
	st32(p, (uint32_t)v);
	st32(p + 4, (uint32_t)(v >> 32));
}

void cp_wipe(void *p, size_t len)
{
	volatile uint8_t *v = p;
	while (len--)
		*v++ = 0;
}

int cp_memeq_ct(const void *a, const void *b, size_t len)
{
	const uint8_t *x = a, *y = b;
	uint8_t d = 0;
	size_t i;

	for (i = 0; i < len; i++)
		d |= x[i] ^ y[i];
	return d;   /* 0 = equal */
}

/* ------------------------------------------------------------ ChaCha20 */

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d) do { \
	a += b; d ^= a; d = ROTL(d, 16); \
	c += d; b ^= c; b = ROTL(b, 12); \
	a += b; d ^= a; d = ROTL(d, 8);  \
	c += d; b ^= c; b = ROTL(b, 7);  \
} while (0)

void chacha20_block(const uint8_t key[CP_KEY_LEN], uint32_t counter,
                    const uint8_t nonce[CP_NONCE_LEN], uint8_t out[64])
{
	uint32_t s[16], x[16];
	int i;

	s[0] = 0x61707865; s[1] = 0x3320646e;    /* "expand 32-byte k" */
	s[2] = 0x79622d32; s[3] = 0x6b206574;
	for (i = 0; i < 8; i++)
		s[4 + i] = ld32(key + 4 * i);
	s[12] = counter;
	s[13] = ld32(nonce);
	s[14] = ld32(nonce + 4);
	s[15] = ld32(nonce + 8);

	memcpy(x, s, sizeof(x));
	for (i = 0; i < 10; i++) {
		QR(x[0], x[4], x[8],  x[12]);   /* columns */
		QR(x[1], x[5], x[9],  x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		QR(x[0], x[5], x[10], x[15]);   /* diagonals */
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8],  x[13]);
		QR(x[3], x[4], x[9],  x[14]);
	}
	for (i = 0; i < 16; i++)
		st32(out + 4 * i, x[i] + s[i]);

	cp_wipe(s, sizeof(s));
	cp_wipe(x, sizeof(x));
}

void chacha20_xor(const uint8_t key[CP_KEY_LEN], uint32_t counter,
                  const uint8_t nonce[CP_NONCE_LEN],
                  const uint8_t *in, uint8_t *out, size_t len)
{
	uint8_t ks[64];
	size_t i, n;

	while (len) {
		chacha20_block(key, counter++, nonce, ks);
		n = len < 64 ? len : 64;
		for (i = 0; i < n; i++)
			out[i] = in[i] ^ ks[i];
		in += n;
		out += n;
		len -= n;
	}
	cp_wipe(ks, sizeof(ks));
}

/* ------------------------------------------------------------ Poly1305 */

struct poly1305 {
	uint32_t r[5], h[5], pad[4];
	uint8_t  buf[16];
	size_t   buflen;
};

static void poly_init(struct poly1305 *st, const uint8_t key[32])
{
	/* r, clamped as required by RFC 8439, split into 26-bit limbs */
	st->r[0] = (ld32(key + 0)) & 0x3ffffff;
	st->r[1] = (ld32(key + 3) >> 2) & 0x3ffff03;
	st->r[2] = (ld32(key + 6) >> 4) & 0x3ffc0ff;
	st->r[3] = (ld32(key + 9) >> 6) & 0x3f03fff;
	st->r[4] = (ld32(key + 12) >> 8) & 0x00fffff;
	memset(st->h, 0, sizeof(st->h));
	st->pad[0] = ld32(key + 16);
	st->pad[1] = ld32(key + 20);
	st->pad[2] = ld32(key + 24);
	st->pad[3] = ld32(key + 28);
	st->buflen = 0;
}

/* Processes full 16-byte blocks; hibit = 1<<24 for regular blocks. */
static void poly_blocks(struct poly1305 *st, const uint8_t *m, size_t len,
                        uint32_t hibit)
{
	const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2],
	               r3 = st->r[3], r4 = st->r[4];
	const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2],
	         h3 = st->h[3], h4 = st->h[4];
	uint64_t d0, d1, d2, d3, d4;
	uint32_t c;

	while (len >= 16) {
		h0 += (ld32(m + 0)) & 0x3ffffff;
		h1 += (ld32(m + 3) >> 2) & 0x3ffffff;
		h2 += (ld32(m + 6) >> 4) & 0x3ffffff;
		h3 += (ld32(m + 9) >> 6) & 0x3ffffff;
		h4 += (ld32(m + 12) >> 8) | hibit;

		d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
		     (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
		d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
		     (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
		d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
		     (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
		d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
		     (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
		d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
		     (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

		c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
		d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
		d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
		d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
		d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
		h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
		h1 += c;

		m += 16;
		len -= 16;
	}
	st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly_update(struct poly1305 *st, const uint8_t *m, size_t len)
{
	size_t n;

	if (st->buflen) {
		n = 16 - st->buflen;
		if (n > len)
			n = len;
		memcpy(st->buf + st->buflen, m, n);
		st->buflen += n;
		m += n;
		len -= n;
		if (st->buflen < 16)
			return;
		poly_blocks(st, st->buf, 16, 1u << 24);
		st->buflen = 0;
	}
	if (len >= 16) {
		n = len & ~(size_t)15;
		poly_blocks(st, m, n, 1u << 24);
		m += n;
		len -= n;
	}
	if (len) {
		memcpy(st->buf, m, len);
		st->buflen = len;
	}
}

static void poly_finish(struct poly1305 *st, uint8_t tag[16])
{
	uint32_t h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, c, mask;
	uint64_t f;

	if (st->buflen) {       /* last partial block: append 1 and zeros */
		st->buf[st->buflen] = 1;
		memset(st->buf + st->buflen + 1, 0, 16 - st->buflen - 1);
		poly_blocks(st, st->buf, 16, 0);
	}

	h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];

	/* full carry */
	c = h1 >> 26; h1 &= 0x3ffffff;
	h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
	h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
	h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
	h1 += c;

	/* g = h - p = h + 5 - 2^130 */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1u << 26);

	/* select h or g without branches: g4 negative -> keep h */
	mask = (g4 >> 31) - 1;
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h to 128 bits */
	h0 = (h0) | (h1 << 26);
	h1 = (h1 >> 6) | (h2 << 20);
	h2 = (h2 >> 12) | (h3 << 14);
	h3 = (h3 >> 18) | (h4 << 8);

	/* tag = (h + pad) mod 2^128 */
	f = (uint64_t)h0 + st->pad[0];             h0 = (uint32_t)f;
	f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
	f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
	f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

	st32(tag + 0, h0);
	st32(tag + 4, h1);
	st32(tag + 8, h2);
	st32(tag + 12, h3);

	cp_wipe(st, sizeof(*st));
}

void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len,
                  uint8_t tag[CP_TAG_LEN])
{
	struct poly1305 st;
	poly_init(&st, key);
	poly_update(&st, msg, len);
	poly_finish(&st, tag);
}

/* ------------------------------------------------------------ AEAD */

static void aead_tag(const uint8_t key[CP_KEY_LEN], const uint8_t nonce[CP_NONCE_LEN],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t len, uint8_t tag[CP_TAG_LEN])
{
	static const uint8_t zeros[16];
	uint8_t block[64], lens[16];
	struct poly1305 st;

	chacha20_block(key, 0, nonce, block);   /* Poly1305 key = block 0 */
	poly_init(&st, block);
	cp_wipe(block, sizeof(block));

	poly_update(&st, aad, aad_len);
	if (aad_len % 16)
		poly_update(&st, zeros, 16 - aad_len % 16);
	poly_update(&st, ct, len);
	if (len % 16)
		poly_update(&st, zeros, 16 - len % 16);
	st64(lens, (uint64_t)aad_len);
	st64(lens + 8, (uint64_t)len);
	poly_update(&st, lens, 16);
	poly_finish(&st, tag);
}

void cp_encrypt(const uint8_t key[CP_KEY_LEN], const uint8_t nonce[CP_NONCE_LEN],
                const uint8_t *aad, size_t aad_len,
                const uint8_t *pt, size_t len, uint8_t *ct,
                uint8_t tag[CP_TAG_LEN])
{
	chacha20_xor(key, 1, nonce, pt, ct, len);   /* data starts at counter 1 */
	aead_tag(key, nonce, aad, aad_len, ct, len, tag);
}

int cp_decrypt(const uint8_t key[CP_KEY_LEN], const uint8_t nonce[CP_NONCE_LEN],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *ct, size_t len, const uint8_t tag[CP_TAG_LEN],
               uint8_t *pt)
{
	uint8_t calc[CP_TAG_LEN];
	int bad;

	aead_tag(key, nonce, aad, aad_len, ct, len, calc);
	bad = cp_memeq_ct(calc, tag, CP_TAG_LEN);
	cp_wipe(calc, sizeof(calc));
	if (bad)
		return -1;
	chacha20_xor(key, 1, nonce, ct, pt, len);
	return 0;
}
