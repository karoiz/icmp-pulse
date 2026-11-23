// SPDX-License-Identifier: GPL-2.0-only
/*
 * icmp-pulse - self tests run by "make test" (on the router and on the server)
 *
 *  1. ChaCha20, Poly1305 and AEAD: official test vectors from RFC 8439.
 *  2. key_id: reference vector.
 *  3. Plaintext frame: reference bytes (checks byte order on this CPU).
 *  4. Encrypted frame: reference bytes, decryption, rejection of modified
 *     packets and of a packet checked with a different key.
 *
 * Reference vectors were computed with an independent implementation
 * (Python "cryptography" package).
 *
 * Copyright (C) 2026 Karol Dudek <karoiz@sli.pl>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "proto.h"

static int fails;

static void unhex(const char *s, uint8_t *o, size_t *n)
{
	size_t i, l = strlen(s) / 2;
	for (i = 0; i < l; i++) {
		char b[3] = { s[2 * i], s[2 * i + 1], 0 };
		o[i] = (uint8_t)strtoul(b, NULL, 16);
	}
	if (n)
		*n = l;
}

static void tohex(const uint8_t *b, size_t n, char *o)
{
	size_t i;
	for (i = 0; i < n; i++)
		sprintf(o + 2 * i, "%02x", b[i]);
	o[2 * n] = 0;
}

static void check(const char *name, int ok)
{
	printf("%-48s %s\n", name, ok ? "OK" : "FAIL");
	if (!ok)
		fails++;
}

static void check_hex(const char *name, const uint8_t *b, size_t n, const char *exp)
{
	static char hex[2 * LG_MAX_PKT + 1];
	tohex(b, n, hex);
	check(name, !strcmp(hex, exp));
	if (strcmp(hex, exp))
		printf("   got:      %s\n   expected: %s\n", hex, exp);
}

static const char *SUNSCREEN =
	"Ladies and Gentlemen of the class of '99: If I could offer you only "
	"one tip for the future, sunscreen would be it.";

static void test_rfc8439(void)
{
	uint8_t key[32], nonce[12], aad[12], out[256], tag[16], back[256], pk[32];
	size_t n = strlen(SUNSCREEN), i;

	/* 2.4.2: ChaCha20 encryption */
	for (i = 0; i < 32; i++)
		key[i] = (uint8_t)i;
	unhex("000000000000004a00000000", nonce, NULL);
	chacha20_xor(key, 1, nonce, (const uint8_t *)SUNSCREEN, out, n);
	check_hex("RFC 8439 2.4.2 ChaCha20", out, n,
		"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
		"f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
		"07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
		"5af90bbf74a35be6b40b8eedf2785e42874d");

	/* 2.5.2: Poly1305 */
	unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
	      pk, NULL);
	poly1305_mac(pk, (const uint8_t *)"Cryptographic Forum Research Group", 34, tag);
	check_hex("RFC 8439 2.5.2 Poly1305", tag, 16, "a8061dc1305136c6c22b8baf0c0127a9");

	/* 2.8.2: AEAD */
	for (i = 0; i < 32; i++)
		key[i] = (uint8_t)(0x80 + i);
	unhex("070000004041424344454647", nonce, NULL);
	unhex("50515253c0c1c2c3c4c5c6c7", aad, NULL);
	cp_encrypt(key, nonce, aad, 12, (const uint8_t *)SUNSCREEN, n, out, tag);
	check_hex("RFC 8439 2.8.2 AEAD ciphertext", out, n,
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
		"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
		"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
		"3ff4def08e4b7a9de576d26586cec64b6116");
	check_hex("RFC 8439 2.8.2 AEAD tag", tag, 16, "1ae10b594f09e26a7e902ecbd0600691");
	check("RFC 8439 2.8.2 AEAD decryption",
	      cp_decrypt(key, nonce, aad, 12, out, n, tag, back) == 0 &&
	      !memcmp(back, SUNSCREEN, n));
	tag[15] ^= 0x01;
	check("RFC 8439 2.8.2 AEAD rejects bad tag",
	      cp_decrypt(key, nonce, aad, 12, out, n, tag, back) != 0);
}

static void build_packet(struct lg_packet *p)
{
	memset(p, 0, sizeof(*p));
	p->h.boot_id = 0x7f3a0c9e12b4d655ull;
	p->h.pkt_ctr = 0xa3;
	p->h.seq = 0x3f;
	p->h.mono_ns = 0x00004e3a1b2c0f00ull;
	strcpy(p->name, "earth");
	p->probe_idx = 0;
	p->probe_interval_s = 10;
	p->reply_ttl = 52;
	p->uptime_cs = 8604317;
	p->kboot_id = 0x3f2b9c1e;
	p->rtt_last_us = 8600;
	p->rtt_min_us = 8300;
	p->rtt_avg_us = 8650;
	p->rtt_max_us = 9000;
	p->probe_sent = 99;
	p->probe_recv = 98;
	p->cpu_busy_x100 = 1234;
	p->cpu_softirq_x100 = 321;
	p->load1_x100 = 42;
	p->mem_total_kb = 245760;
	p->mem_avail_kb = 150000;
	p->ct_count = 523;
	p->ct_max = 16384;
	p->n_if = 2;

	strcpy(p->ifs[0].name, "pppoe-wan");
	p->ifs[0].state = 0x06;
	p->ifs[0].rflags = 0x07;
	p->ifs[0].speed = 0xFFFF;
	p->ifs[0].c[C_RX_BYTES] = 12917330867ull;
	p->ifs[0].c[C_RX_PACKETS] = 12951026;
	p->ifs[0].c[C_TX_BYTES] = 1056159950ull;
	p->ifs[0].c[C_TX_PACKETS] = 7028240;

	strcpy(p->ifs[1].name, "eth1");
	p->ifs[1].state = 0x9E;
	p->ifs[1].speed = 1000;
	p->ifs[1].carrier_changes = 3;
	p->ifs[1].c[C_RX_BYTES] = 0x1122334455667788ull;
	p->ifs[1].c[C_RX_PACKETS] = 1;
	p->ifs[1].c[C_RX_ERRS] = 2;
	p->ifs[1].c[C_TX_BYTES] = 0x8877665544332211ull;
	p->ifs[1].c[C_TX_PACKETS] = 4;
	p->ifs[1].c[C_TX_ERRS] = 5;
}

static const char *EXP_PLAIN =
	"0000010300000000000000007f3a0c9e12b4d655000000a30000003f00004e3a"
	"1b2c0f006561727468000000000000000000000000000a340000000000834a9d"
	"3f2b9c1e000021980000206c000021ca00002328000000630000006204d20141"
	"002a0003c000000249f00000020b00004000027070706f652d77616e00000000"
	"0000000607ffff000000000000000301eed3b30000000000c59df20000000000"
	"000000000000003ef3b8ce00000000006b3e1000000000000000006574683100"
	"00000000000000000000009e0003e80000000311223344556677880000000000"
	"0000010000000000000002887766554433221100000000000000040000000000"
	"000005";

static const char *EXP_ENC =
	"000101132781d1c655ae513f7f3a0c9e12b4d655000000a30000003f00004e3a"
	"1b2c0f00c70c6c74049db44eb9c2919355d303695f55915c7068d40a08756ff9"
	"d127d59c333d5664bc7c83e6aedefe3e8aa273bdd04d35e356728edfbf90afb4"
	"ca2980c2bc65a215fa366e26fd6368d9f6227f5d968a59519a641561ad5761bb"
	"e337248d5c1629f3ab0da96db4b46432bff3eb4f94e2ab73f5a99cab2c1212a4"
	"2a0571415c892b75f9fe0815bdac91aac4bb19bf5daa1b4eb9ae2d1e75afd255"
	"7858f312cc66891947079484bd44a0c14e9568059de8bba8ae15223fa05d4f7d"
	"0d455d332ac3d3ca7f829bade2b1ac8ae974e126c26cc892d78464f7faa7d4c4"
	"e89d9d4b61da95a4c9b7c3e8da462a0472aaa6";

static void test_frame(void)
{
	struct lg_packet a, b;
	struct lg_hdr h;
	uint8_t buf[LG_MAX_PKT], key[32], key2[32], kid[8];
	size_t n, i;
	int rc;

	for (i = 0; i < 32; i++)
		key[i] = (uint8_t)i;
	lg_key_id(key, kid);
	check_hex("key_id for key 00..1f", kid, 8, "2781d1c655ae513f");

	/* plaintext frame */
	build_packet(&a);
	n = lg_encode(&a, NULL, buf, sizeof(buf));
	check("plaintext frame: length 259 B", n == 259);
	check_hex("plaintext frame: bytes (byte order)", buf, n, EXP_PLAIN);
	rc = lg_decode(buf, n, NULL, &b);
	check("plaintext frame: decoding", rc == 0 && !strcmp(b.name, "earth") &&
	      b.h.boot_id == a.h.boot_id && b.ifs[0].c[C_RX_BYTES] == 12917330867ull &&
	      b.ifs[1].c[C_TX_BYTES] == 0x8877665544332211ull && b.ct_max == 16384 &&
	      b.reply_ttl == 52 && !strcmp(b.ifs[1].name, "eth1"));

	/* encrypted frame */
	build_packet(&a);
	n = lg_encode(&a, key, buf, sizeof(buf));
	check("encrypted frame: length 275 B", n == 275);
	check_hex("encrypted frame: bytes", buf, n, EXP_ENC);
	check("encrypted frame: header readable without key", lg_peek(buf, n, &h) == 0 &&
	      !memcmp(h.key_id, kid, 8) && h.pkt_ctr == 0xa3);
	check("encrypted frame: no key -> refused",
	      lg_decode(buf, n, NULL, &b) == LG_E_NOKEY);
	rc = lg_decode(buf, n, key, &b);
	check("encrypted frame: decryption", rc == 0 && !strcmp(b.name, "earth") &&
	      b.ifs[0].c[C_TX_PACKETS] == 7028240 && b.mem_avail_kb == 150000);

	buf[25] ^= 0x01;   /* modify seq in the plaintext header */
	check("encrypted frame: modified header -> rejected",
	      lg_decode(buf, n, key, &b) == LG_E_TAG);
	buf[25] ^= 0x01;
	buf[60] ^= 0x80;   /* modify the ciphertext */
	check("encrypted frame: modified payload -> rejected",
	      lg_decode(buf, n, key, &b) == LG_E_TAG);
	buf[60] ^= 0x80;
	memcpy(key2, key, 32);
	key2[0] ^= 1;
	check("encrypted frame: other key -> rejected",
	      lg_decode(buf, n, key2, &b) == LG_E_TAG);
}

int main(void)
{
	union { uint32_t u; uint8_t c[4]; } e = { 0x01020304 };

	printf("architecture: %s-endian, %d-bit\n", e.c[0] == 1 ? "big" : "little",
	       (int)(8 * sizeof(void *)));
	test_rfc8439();
	test_frame();
	printf("%s\n", fails ? "RESULT: FAILED" : "RESULT: all tests passed");
	return fails ? 1 : 0;
}
