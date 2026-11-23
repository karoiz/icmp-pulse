/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * icmp-pulse - wire format, protocol version 0 (development) (full description: docs/PROTOCOL.md)
 *
 * | header 36 B (plaintext, authenticated) | payload 79 B + n_if*72 B | tag 16 B |
 *
 * All multi-byte fields are big-endian and serialised field by field.
 * flags bit0 = payload encrypted with ChaCha20-Poly1305, tag appended.
 * Nonce = boot_id (8 B) || pkt_ctr (4 B), exactly the header bytes.
 *
 * Copyright (C) 2026 Karol Dudek <karoiz@sli.pl>
 */
#ifndef ICMP_PULSE_PROTO_H
#define ICMP_PULSE_PROTO_H

#include <stdint.h>
#include <stddef.h>
#include "chachapoly.h"

#define LG_VER            0
#define LG_HDR_LEN        36
#define LG_PAYLOAD_FIXED  79
#define LG_IFREC_LEN      72
#define LG_TAG_LEN        CP_TAG_LEN
#define LG_KEY_LEN        CP_KEY_LEN
#define LG_KEYID_LEN      8
#define LG_NAME_LEN       16
#define LG_IFNAME_LEN     16
#define LG_MAX_IF         12
#define LG_MAX_PKT        (LG_HDR_LEN + LG_PAYLOAD_FIXED + LG_MAX_IF * LG_IFREC_LEN + LG_TAG_LEN)

#define LG_FLAG_ENCRYPTED 0x01

#define LG_PROBE_NONE     0xFF
#define LG_U16_NONE       0xFFFF
#define LG_U32_NONE       0xFFFFFFFFu
#define LG_SPEED_NONE     0xFFFF

/* operstate (RFC 2863): bits 0-2 of the state field */
enum {
	LG_OPER_UNKNOWN = 0, LG_OPER_NOTPRESENT = 1, LG_OPER_DOWN = 2,
	LG_OPER_LOWERLAYERDOWN = 3, LG_OPER_TESTING = 4, LG_OPER_DORMANT = 5,
	LG_OPER_UP = 6,
};
#define LG_ST_OPER_MASK     0x07
#define LG_ST_ADMIN_UP      0x08
#define LG_ST_CARRIER       0x10
#define LG_ST_CARRIER_UNK   0x20
#define LG_ST_DUPLEX_SHIFT  6        /* 0 unknown, 1 half, 2 full */

#define LG_RF_DEFAULT_ACTIVE 0x01
#define LG_RF_DEFAULT_ANY    0x02
#define LG_RF_PROBED         0x04

enum { C_RX_BYTES, C_RX_PACKETS, C_RX_ERRS,
       C_TX_BYTES, C_TX_PACKETS, C_TX_ERRS, C_NUM };

struct lg_ifrec {
	char     name[LG_IFNAME_LEN + 1];
	uint8_t  state;
	uint8_t  rflags;
	uint16_t speed;
	uint32_t carrier_changes;
	uint64_t c[C_NUM];
};

struct lg_hdr {
	uint8_t  ver;
	uint8_t  flags;
	uint16_t len;
	uint8_t  key_id[LG_KEYID_LEN];
	uint64_t boot_id;
	uint32_t pkt_ctr;
	uint32_t seq;
	uint64_t mono_ns;
};

struct lg_packet {
	struct lg_hdr h;

	char     name[LG_NAME_LEN + 1];
	uint8_t  probe_idx;
	uint16_t probe_interval_s;
	uint8_t  reply_ttl;          /* TTL of the last reply on this link, 0 = none */
	uint64_t uptime_cs;
	uint32_t kboot_id;
	uint32_t rtt_last_us;
	uint32_t rtt_min_us, rtt_avg_us, rtt_max_us;
	uint32_t probe_sent, probe_recv;
	uint16_t cpu_busy_x100, cpu_softirq_x100, load1_x100;
	uint32_t mem_total_kb, mem_avail_kb;
	uint32_t ct_count, ct_max;
	uint8_t  n_if;
	struct lg_ifrec ifs[LG_MAX_IF];
};

/* Encodes a packet. key == NULL: plaintext mode (key_id = 0, no tag).
 * h.len and h.flags (and h.key_id when key != NULL) are filled in.
 * Returns the length, or 0 on error. */
size_t lg_encode(struct lg_packet *p, const uint8_t *key, uint8_t *buf, size_t cap);

/* Parses the header only (no verification). Returns 0 on success. */
int lg_peek(const uint8_t *buf, size_t len, struct lg_hdr *h);

/* Full decode. An encrypted packet requires the key and its tag is verified.
 * Returns 0 on success, LG_E_* on error. */
int lg_decode(const uint8_t *buf, size_t len, const uint8_t *key, struct lg_packet *p);

#define LG_E_SHORT   -1
#define LG_E_VER     -2
#define LG_E_LEN     -3
#define LG_E_NOKEY   -4
#define LG_E_TAG     -5
#define LG_E_FORMAT  -6

/* key_id = first 8 bytes of the ChaCha20 keystream (router key, nonce 12 x 0xFF,
 * counter 0). The all-0xFF nonce is never used for data (boot_id != 0xFF..FF). */
void lg_key_id(const uint8_t key[LG_KEY_LEN], uint8_t out[LG_KEYID_LEN]);

/* Parses a key from 64 hex characters. Returns 0 on success. */
int lg_key_from_hex(const char *hex, uint8_t key[LG_KEY_LEN]);

uint16_t lg_icmp_csum(const void *data, size_t len);
const char *lg_oper_str(unsigned oper);

#endif
