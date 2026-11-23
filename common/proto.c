// SPDX-License-Identifier: GPL-2.0-only
/*
 * icmp-pulse - wire format serialisation (big-endian, field by field)
 *              and payload encryption with ChaCha20-Poly1305
 *
 * Copyright (C) 2026 Karol Dudek <karoiz@sli.pl>
 */
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "proto.h"

/* ---- big-endian store/load ---- */

static uint8_t *put8(uint8_t *p, uint8_t v)   { *p++ = v; return p; }
static uint8_t *put16(uint8_t *p, uint16_t v) { *p++ = (uint8_t)(v >> 8); *p++ = (uint8_t)v; return p; }
static uint8_t *put32(uint8_t *p, uint32_t v)
{
	*p++ = (uint8_t)(v >> 24); *p++ = (uint8_t)(v >> 16);
	*p++ = (uint8_t)(v >> 8);  *p++ = (uint8_t)v;
	return p;
}
static uint8_t *put64(uint8_t *p, uint64_t v)
{
	p = put32(p, (uint32_t)(v >> 32));
	return put32(p, (uint32_t)v);
}
static uint8_t *putstr(uint8_t *p, const char *s, size_t n)
{
	size_t l = strnlen(s, n);
	memcpy(p, s, l);
	memset(p + l, 0, n - l);
	return p + n;
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) << 32 | get32(p + 4); }
static void getstr(char *dst, const uint8_t *p, size_t n)
{
	memcpy(dst, p, n);
	dst[n] = 0;
}

/* ---- keys ---- */

void lg_key_id(const uint8_t key[LG_KEY_LEN], uint8_t out[LG_KEYID_LEN])
{
	uint8_t nonce[CP_NONCE_LEN], block[64];

	memset(nonce, 0xFF, sizeof(nonce));
	chacha20_block(key, 0, nonce, block);
	memcpy(out, block, LG_KEYID_LEN);
	cp_wipe(block, sizeof(block));
}

int lg_key_from_hex(const char *hex, uint8_t key[LG_KEY_LEN])
{
	int i;

	if (strlen(hex) != 2 * LG_KEY_LEN)
		return -1;
	for (i = 0; i < 2 * LG_KEY_LEN; i++)
		if (!isxdigit((unsigned char)hex[i]))
			return -1;
	for (i = 0; i < LG_KEY_LEN; i++) {
		char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
		key[i] = (uint8_t)strtoul(b, NULL, 16);
	}
	return 0;
}

/* ---- header ---- */

static uint8_t *put_hdr(uint8_t *p, const struct lg_hdr *h)
{
	p = put8(p, h->ver);
	p = put8(p, h->flags);
	p = put16(p, h->len);
	memcpy(p, h->key_id, LG_KEYID_LEN);
	p += LG_KEYID_LEN;
	p = put64(p, h->boot_id);
	p = put32(p, h->pkt_ctr);
	p = put32(p, h->seq);
	p = put64(p, h->mono_ns);
	return p;
}

int lg_peek(const uint8_t *b, size_t len, struct lg_hdr *h)
{
	if (len < LG_HDR_LEN)
		return LG_E_SHORT;
	h->ver = b[0];
	h->flags = b[1];
	h->len = get16(b + 2);
	memcpy(h->key_id, b + 4, LG_KEYID_LEN);
	h->boot_id = get64(b + 12);
	h->pkt_ctr = get32(b + 20);
	h->seq = get32(b + 24);
	h->mono_ns = get64(b + 28);
	if (h->ver != LG_VER)
		return LG_E_VER;
	if (h->len > len || h->len < LG_HDR_LEN + LG_PAYLOAD_FIXED)
		return LG_E_LEN;
	return 0;
}

static void nonce_from_hdr(const uint8_t *hdr, uint8_t nonce[CP_NONCE_LEN])
{
	memcpy(nonce, hdr + 12, 8);     /* boot_id */
	memcpy(nonce + 8, hdr + 20, 4); /* pkt_ctr */
}

/* ---- encoding ---- */

size_t lg_encode(struct lg_packet *pk, const uint8_t *key, uint8_t *buf, size_t cap)
{
	size_t plen, len;
	uint8_t *p;
	int i, j;

	if (pk->n_if > LG_MAX_IF)
		return 0;
	plen = LG_PAYLOAD_FIXED + (size_t)pk->n_if * LG_IFREC_LEN;
	len = LG_HDR_LEN + plen + (key ? LG_TAG_LEN : 0);
	if (len > cap)
		return 0;

	pk->h.ver = LG_VER;
	pk->h.len = (uint16_t)len;
	if (key) {
		pk->h.flags |= LG_FLAG_ENCRYPTED;
		lg_key_id(key, pk->h.key_id);
	} else {
		pk->h.flags &= (uint8_t)~LG_FLAG_ENCRYPTED;
		memset(pk->h.key_id, 0, LG_KEYID_LEN);
	}
	p = put_hdr(buf, &pk->h);

	p = putstr(p, pk->name, LG_NAME_LEN);
	p = put8(p, pk->probe_idx);
	p = put16(p, pk->probe_interval_s);
	p = put8(p, pk->reply_ttl);
	p = put64(p, pk->uptime_cs);
	p = put32(p, pk->kboot_id);
	p = put32(p, pk->rtt_last_us);
	p = put32(p, pk->rtt_min_us);
	p = put32(p, pk->rtt_avg_us);
	p = put32(p, pk->rtt_max_us);
	p = put32(p, pk->probe_sent);
	p = put32(p, pk->probe_recv);
	p = put16(p, pk->cpu_busy_x100);
	p = put16(p, pk->cpu_softirq_x100);
	p = put16(p, pk->load1_x100);
	p = put32(p, pk->mem_total_kb);
	p = put32(p, pk->mem_avail_kb);
	p = put32(p, pk->ct_count);
	p = put32(p, pk->ct_max);
	p = put8(p, pk->n_if);

	for (i = 0; i < pk->n_if; i++) {
		const struct lg_ifrec *r = &pk->ifs[i];
		p = putstr(p, r->name, LG_IFNAME_LEN);
		p = put8(p, r->state);
		p = put8(p, r->rflags);
		p = put16(p, r->speed);
		p = put32(p, r->carrier_changes);
		for (j = 0; j < C_NUM; j++)
			p = put64(p, r->c[j]);
	}

	if (key) {
		uint8_t nonce[CP_NONCE_LEN];
		nonce_from_hdr(buf, nonce);
		cp_encrypt(key, nonce, buf, LG_HDR_LEN, buf + LG_HDR_LEN, plen,
		           buf + LG_HDR_LEN, p);
		p += LG_TAG_LEN;
	}
	return (size_t)(p - buf);
}

/* ---- decoding ---- */

int lg_decode(const uint8_t *b, size_t len, const uint8_t *key, struct lg_packet *pk)
{
	uint8_t pl[LG_PAYLOAD_FIXED + LG_MAX_IF * LG_IFREC_LEN];
	const uint8_t *p;
	size_t plen, need;
	int rc, i, j;

	memset(pk, 0, sizeof(*pk));
	rc = lg_peek(b, len, &pk->h);
	if (rc)
		return rc;

	plen = pk->h.len - LG_HDR_LEN;
	if (pk->h.flags & LG_FLAG_ENCRYPTED) {
		uint8_t nonce[CP_NONCE_LEN];
		if (!key)
			return LG_E_NOKEY;
		if (plen < LG_PAYLOAD_FIXED + LG_TAG_LEN)
			return LG_E_LEN;
		plen -= LG_TAG_LEN;
		if (plen > sizeof(pl))
			return LG_E_LEN;
		nonce_from_hdr(b, nonce);
		if (cp_decrypt(key, nonce, b, LG_HDR_LEN, b + LG_HDR_LEN, plen,
		               b + LG_HDR_LEN + plen, pl) != 0)
			return LG_E_TAG;
	} else {
		if (plen > sizeof(pl))
			return LG_E_LEN;
		memcpy(pl, b + LG_HDR_LEN, plen);
	}

	p = pl;
	getstr(pk->name, p, LG_NAME_LEN);
	pk->probe_idx = p[16];
	pk->probe_interval_s = get16(p + 17);
	pk->reply_ttl = p[19];
	pk->uptime_cs = get64(p + 20);
	pk->kboot_id = get32(p + 28);
	pk->rtt_last_us = get32(p + 32);
	pk->rtt_min_us = get32(p + 36);
	pk->rtt_avg_us = get32(p + 40);
	pk->rtt_max_us = get32(p + 44);
	pk->probe_sent = get32(p + 48);
	pk->probe_recv = get32(p + 52);
	pk->cpu_busy_x100 = get16(p + 56);
	pk->cpu_softirq_x100 = get16(p + 58);
	pk->load1_x100 = get16(p + 60);
	pk->mem_total_kb = get32(p + 62);
	pk->mem_avail_kb = get32(p + 66);
	pk->ct_count = get32(p + 70);
	pk->ct_max = get32(p + 74);
	pk->n_if = p[78];
	if (pk->n_if > LG_MAX_IF)
		return LG_E_FORMAT;
	need = LG_PAYLOAD_FIXED + (size_t)pk->n_if * LG_IFREC_LEN;
	if (plen != need)
		return LG_E_FORMAT;

	p += LG_PAYLOAD_FIXED;
	for (i = 0; i < pk->n_if; i++) {
		struct lg_ifrec *r = &pk->ifs[i];
		getstr(r->name, p, LG_IFNAME_LEN);
		r->state = p[16];
		r->rflags = p[17];
		r->speed = get16(p + 18);
		r->carrier_changes = get32(p + 20);
		for (j = 0; j < C_NUM; j++)
			r->c[j] = get64(p + 24 + 8 * j);
		p += LG_IFREC_LEN;
	}
	cp_wipe(pl, sizeof(pl));
	return 0;
}

/* ---- helpers ---- */

uint16_t lg_icmp_csum(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += (uint32_t)(p[0] << 8 | p[1]);
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)(p[0] << 8);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)~sum;
}

const char *lg_oper_str(unsigned oper)
{
	static const char *s[] = { "unknown", "notpresent", "down",
		"lowerlayerdown", "testing", "dormant", "up", "?" };
	return s[oper & 7];
}
