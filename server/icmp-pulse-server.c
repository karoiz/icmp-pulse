// SPDX-License-Identifier: GPL-2.0-only
/*
 * icmp-pulse-server - receiver for icmp-pulse reports (server side)
 *
 * Listens on a raw ICMP socket, verifies and decrypts Echo Requests sent by
 * routers (ChaCha20-Poly1305, keys from a file) and reports:
 *   - 3 consecutive missing packets from an uplink / from the whole router,
 *   - router reboot (kernel boot_id change) or icmp-pulse restart,
 *   - public IP address change of an uplink, PPPoE session re-establishment,
 *   - hop count (TTL) change in both directions,
 *   - interface state changes, link flapping, active default route change,
 *   - interface counter resets,
 *   - high RAM and conntrack table usage,
 *   - forged, replayed and unknown-key packets.
 * Interface throughput is computed from counter differences.
 *
 * Echo Replies are sent by the server kernel (net.ipv4.icmp_echo_ignore_all=0).
 *
 * Copyright (C) 2026 Karol Dudek <karoiz@sli.pl>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <getopt.h>

#include "proto.h"
#include "version.h"

#ifndef SOL_RAW
#define SOL_RAW 255
#endif
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif
#define ICMP_ECHO_REQ 8

#define DEFAULT_KEYS  "/etc/icmp-pulse/keys"

#define MAX_KEYS      4096
#define MAX_ROUTERS   4096
#define MAX_LINKS     (LG_MAX_IF + 1)
#define MAX_ENDED     64
#define MISS_LIMIT    3
#define MARGIN_S      12
#define REPLAY_WIN    64
#define MEM_HI        9000    /* % x 100 */
#define MEM_LO        8500
#define CT_HI         8000
#define CT_LO         7000

/* ======================================================= data structures */

struct srv_key {
	uint8_t key[LG_KEY_LEN];
	uint8_t kid[LG_KEYID_LEN];
	char    label[48];
};

struct srv_link {
	int      used;
	uint8_t  idx;
	char     name[LG_IFNAME_LEN + 1];
	uint16_t interval_s;
	time_t   last_seen;
	int      down;
	char     src[INET_ADDRSTRLEN];
	int      hops_fwd, hops_back;           /* -1 = unknown */
	int      pend_fwd, pend_fwd_n, pend_back, pend_back_n;
};

struct srv_if {
	int      valid;
	char     name[LG_IFNAME_LEN + 1];
	uint8_t  state, rflags;
	uint32_t carrier_changes;
	uint64_t c[C_NUM];
	double   rx_mbps, tx_mbps;
	int      rate_ok;
	int      reset;                         /* counter reset seen in this packet */
};

struct router {
	int      used;
	const struct srv_key *k;                /* NULL = plaintext mode */
	char     name[LG_NAME_LEN + 1];
	/* restarts and replay protection */
	uint64_t boot_id;
	uint32_t kboot_id;
	uint32_t max_ctr;
	uint64_t win;                           /* bit i = packet max_ctr - i accepted */
	uint64_t last_mono;
	uint64_t ended[MAX_ENDED];
	int      n_ended, ended_pos;
	/* state */
	time_t   last_seen;
	int      down;
	int      mem_hi, ct_hi;
	uint32_t last_seq;
	int      have_seq;
	uint64_t seq_mono;                      /* mono_ns of the first packet of the cycle */
	struct srv_link links[MAX_LINKS];
	struct srv_if ifs[LG_MAX_IF];
};

static struct srv_key keys[MAX_KEYS];
static int n_keys;
static struct router routers[MAX_ROUTERS];
static int quiet, verbose, allow_plain;
static volatile sig_atomic_t stop;

/* rejected packet counters (reported every 60 s) */
static unsigned long rej_unknown, rej_tag, rej_replay, rej_plain, rej_format;
static time_t rej_last;

/* ======================================================= output */

static void ts(char *buf, size_t len)
{
	time_t t = time(NULL);
	strftime(buf, len, "%Y-%m-%d %H:%M:%S", localtime(&t));
}

#define EVENT(fmt, ...) do { char _t[32]; ts(_t, sizeof(_t)); \
	printf("%s ** " fmt "\n", _t, ##__VA_ARGS__); fflush(stdout); } while (0)
#define INFO(fmt, ...) do { if (!quiet) { char _t[32]; ts(_t, sizeof(_t)); \
	printf("%s    " fmt "\n", _t, ##__VA_ARGS__); fflush(stdout); } } while (0)
#define DBG(fmt, ...) do { if (verbose) { char _t[32]; ts(_t, sizeof(_t)); \
	printf("%s .. " fmt "\n", _t, ##__VA_ARGS__); fflush(stdout); } } while (0)

static void on_signal(int s) { (void)s; stop = 1; }

static const char *derived_state(uint8_t st)
{
	unsigned oper = st & LG_ST_OPER_MASK;

	if (oper == LG_OPER_NOTPRESENT) return "ABSENT";
	if (!(st & LG_ST_ADMIN_UP)) return "ADMIN_DOWN";
	switch (oper) {
	case LG_OPER_UP:             return "UP";
	case LG_OPER_DOWN:           return "NO_CARRIER";
	case LG_OPER_LOWERLAYERDOWN: return "LOWER_DOWN";
	case LG_OPER_DORMANT:        return "DORMANT";
	case LG_OPER_TESTING:        return "TESTING";
	default:
		if (!(st & LG_ST_CARRIER_UNK) && !(st & LG_ST_CARRIER) &&
		    (st & LG_ST_ADMIN_UP))
			return "NO_CARRIER";
		return "UNKNOWN";
	}
}

static void hex8(const uint8_t *b, char *out)
{
	int i;
	for (i = 0; i < LG_KEYID_LEN; i++)
		sprintf(out + 2 * i, "%02x", b[i]);
}

/* ======================================================= keys */

static int load_keys(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[512];
	int ln = 0;

	if (!f) {
		perror(path);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char hex[128] = "", label[128] = "";
		ln++;
		if (sscanf(line, " %127s %127s", hex, label) < 1 || hex[0] == '#')
			continue;
		if (n_keys >= MAX_KEYS) {
			fprintf(stderr, "%s: too many keys (max %d)\n", path, MAX_KEYS);
			break;
		}
		if (lg_key_from_hex(hex, keys[n_keys].key) != 0) {
			fprintf(stderr, "%s:%d: key must be 64 hex characters\n", path, ln);
			fclose(f);
			return -1;
		}
		lg_key_id(keys[n_keys].key, keys[n_keys].kid);
		snprintf(keys[n_keys].label, sizeof(keys[n_keys].label), "%s",
		         label[0] ? label : "-");
		n_keys++;
	}
	fclose(f);
	cp_wipe(line, sizeof(line));
	return 0;
}

static const struct srv_key *find_key(const uint8_t kid[LG_KEYID_LEN])
{
	int i;
	for (i = 0; i < n_keys; i++)
		if (!memcmp(keys[i].kid, kid, LG_KEYID_LEN))
			return &keys[i];
	return NULL;
}

/* ======================================================= routers */

static struct router *find_router(const struct srv_key *k, const char *plain_name)
{
	struct router *fr = NULL;
	int i;

	for (i = 0; i < MAX_ROUTERS; i++) {
		struct router *r = &routers[i];
		if (!r->used) {
			if (!fr)
				fr = r;
			continue;
		}
		if (k && r->k == k)
			return r;
		if (!k && !r->k && !strcmp(r->name, plain_name))
			return r;
	}
	if (fr) {
		memset(fr, 0, sizeof(*fr));
		fr->used = 1;
		fr->k = k;
		if (!k)
			snprintf(fr->name, sizeof(fr->name), "%s", plain_name);
	}
	return fr;
}

static int boot_ended(const struct router *r, uint64_t b)
{
	int i;
	for (i = 0; i < r->n_ended; i++)
		if (r->ended[i] == b)
			return 1;
	return 0;
}

static void end_boot(struct router *r, uint64_t b)
{
	r->ended[r->ended_pos] = b;
	r->ended_pos = (r->ended_pos + 1) % MAX_ENDED;
	if (r->n_ended < MAX_ENDED)
		r->n_ended++;
}

/* Replay protection. 0 = accept, -1 = reject.
 * *restart: 0 none, 1 icmp-pulse restart, 2 router reboot, 3 first packet. */
static int replay_check(struct router *r, const struct lg_packet *pk, int *restart)
{
	uint32_t ctr = pk->h.pkt_ctr;

	*restart = 0;
	if (!r->boot_id && !r->last_seen) {
		*restart = 3;
		goto new_boot;
	}
	if (pk->h.boot_id != r->boot_id) {
		if (boot_ended(r, pk->h.boot_id))
			return -1;          /* packet from a finished run */
		if (pk->kboot_id == r->kboot_id) {
			/* same kernel boot: a new run must be later in time */
			if (pk->h.mono_ns <= r->last_mono)
				return -1;
			*restart = 1;
		} else {
			*restart = 2;
		}
		end_boot(r, r->boot_id);
		goto new_boot;
	}
	if (ctr > r->max_ctr) {
		uint32_t d = ctr - r->max_ctr;
		r->win = d >= REPLAY_WIN ? 1 : (r->win << d) | 1;
		r->max_ctr = ctr;
		return 0;
	}
	{
		uint32_t d = r->max_ctr - ctr;
		if (d >= REPLAY_WIN || (r->win >> d) & 1)
			return -1;
		r->win |= (uint64_t)1 << d;
		return 0;
	}
new_boot:
	r->boot_id = pk->h.boot_id;
	r->kboot_id = pk->kboot_id;
	r->max_ctr = ctr;
	r->win = 1;
	r->have_seq = 0;
	return 0;
}

static struct srv_link *find_link(struct router *r, uint8_t idx)
{
	struct srv_link *fl = NULL;
	int i;

	for (i = 0; i < MAX_LINKS; i++) {
		if (r->links[i].used && r->links[i].idx == idx)
			return &r->links[i];
		if (!r->links[i].used && !fl)
			fl = &r->links[i];
	}
	if (fl) {
		memset(fl, 0, sizeof(*fl));
		fl->used = 1;
		fl->idx = idx;
		fl->hops_fwd = fl->hops_back = -1;
	}
	return fl;
}

/* TTL -> hop count, assuming a typical initial TTL */
static int ttl_hops(int ttl)
{
	if (ttl <= 0)
		return -1;
	if (ttl <= 64)
		return 64 - ttl;
	if (ttl <= 128)
		return 128 - ttl;
	return 255 - ttl;
}

/* a hop count change is reported once the new value is seen twice */
static void hops_update(const char *rname, const char *lname, const char *dir,
                        int *cur, int *pend, int *pend_n, int v)
{
	if (v < 0)
		return;
	if (*cur < 0) {
		*cur = v;
		return;
	}
	if (v == *cur) {
		*pend_n = 0;
		return;
	}
	if (*pend_n && *pend == v) {
		if (++*pend_n >= 2) {
			EVENT("%s: uplink %s route change %s: %d -> %d hops",
			      rname, lname, dir, *cur, v);
			*cur = v;
			*pend_n = 0;
		}
	} else {
		*pend = v;
		*pend_n = 1;
	}
}

/* ======================================================= packet handling */

static void check_ifs(struct router *r, const struct lg_packet *pk, int rebooted,
                      int new_cycle, double dt)
{
	int i, j;

	for (i = 0; i < pk->n_if; i++) {
		const struct lg_ifrec *f = &pk->ifs[i];
		struct srv_if *o = &r->ifs[i];
		int same = o->valid && !strcmp(o->name, f->name);
		int was_absent = (o->state & LG_ST_OPER_MASK) == LG_OPER_NOTPRESENT;

		o->reset = 0;
		if (same) {
			if (strcmp(derived_state(o->state), derived_state(f->state)))
				EVENT("%s: %s %s -> %s", r->name, f->name,
				      derived_state(o->state), derived_state(f->state));
			if (f->carrier_changes > o->carrier_changes && !was_absent && !rebooted)
				EVENT("%s: %s FLAPPING (+%u link changes)", r->name, f->name,
				      f->carrier_changes - o->carrier_changes);
			if ((f->rflags & LG_RF_DEFAULT_ACTIVE) &&
			    !(o->rflags & LG_RF_DEFAULT_ACTIVE))
				EVENT("%s: active default route via %s", r->name, f->name);

			if (new_cycle) {
				int dec = 0;
				for (j = 0; j < C_NUM; j++)
					if (f->c[j] < o->c[j])
						dec = 1;
				if (dec) {
					o->reset = 1;
					o->rate_ok = 0;
					if (!rebooted && !was_absent &&
					    (f->state & LG_ST_OPER_MASK) != LG_OPER_NOTPRESENT &&
					    strncmp(f->name, "pppoe-", 6))
						EVENT("%s: %s counters reset", r->name, f->name);
				} else if (dt <= 0.5) {
					o->rate_ok = 0;
				} else {
					o->rx_mbps = (double)(f->c[C_RX_BYTES] - o->c[C_RX_BYTES]) * 8 / dt / 1e6;
					o->tx_mbps = (double)(f->c[C_TX_BYTES] - o->c[C_TX_BYTES]) * 8 / dt / 1e6;
					o->rate_ok = 1;
				}
			}
		} else {
			o->rate_ok = 0;
		}
		if (new_cycle || !same) {
			memcpy(o->c, f->c, sizeof(o->c));
		}
		snprintf(o->name, sizeof(o->name), "%s", f->name);
		o->state = f->state;
		o->rflags = f->rflags;
		o->carrier_changes = f->carrier_changes;
		o->valid = 1;
	}
	for (; i < LG_MAX_IF; i++)
		r->ifs[i].valid = 0;
}

static void check_resources(struct router *r, const struct lg_packet *pk)
{
	if (pk->mem_total_kb != LG_U32_NONE && pk->mem_avail_kb != LG_U32_NONE &&
	    pk->mem_total_kb > 0) {
		unsigned used = (unsigned)(((uint64_t)pk->mem_total_kb - pk->mem_avail_kb) *
		                           10000 / pk->mem_total_kb);
		if (!r->mem_hi && used >= MEM_HI) {
			r->mem_hi = 1;
			EVENT("%s: WARNING RAM usage %u%%", r->name, used / 100);
		} else if (r->mem_hi && used < MEM_LO) {
			r->mem_hi = 0;
			EVENT("%s: RAM usage back to normal (%u%%)", r->name, used / 100);
		}
	}
	if (pk->ct_count != LG_U32_NONE && pk->ct_max != LG_U32_NONE && pk->ct_max > 0) {
		unsigned used = (unsigned)((uint64_t)pk->ct_count * 10000 / pk->ct_max);
		if (!r->ct_hi && used >= CT_HI) {
			r->ct_hi = 1;
			EVENT("%s: WARNING conntrack table %u/%u (%u%%)", r->name,
			      pk->ct_count, pk->ct_max, used / 100);
		} else if (r->ct_hi && used < CT_LO) {
			r->ct_hi = 0;
			EVENT("%s: conntrack table back to normal (%u/%u)", r->name,
			      pk->ct_count, pk->ct_max);
		}
	}
}

static void print_info(const struct router *r, const struct srv_link *l,
                       const struct lg_packet *pk, const char *src)
{
	char line[2048], tmp[64];
	size_t off = 0;
	int i;

#define ADD(...) off += (size_t)snprintf(line + off, sizeof(line) - off, __VA_ARGS__)
	ADD("%s via %s %s", r->name, l->name, src);
	if (l->hops_fwd >= 0)
		ADD(" hops %d/%s", l->hops_fwd,
		    l->hops_back >= 0 ? (snprintf(tmp, sizeof(tmp), "%d", l->hops_back), tmp) : "-");
	ADD(" seq=%u up=%llus", pk->h.seq, (unsigned long long)(pk->uptime_cs / 100));
	if (pk->rtt_last_us != LG_U32_NONE)
		ADD(" rtt %.1f", pk->rtt_last_us / 1000.0);
	else
		ADD(" rtt -");
	if (pk->rtt_avg_us != LG_U32_NONE)
		ADD(" (%.1f/%.1f/%.1f)", pk->rtt_min_us / 1000.0, pk->rtt_avg_us / 1000.0,
		    pk->rtt_max_us / 1000.0);
	ADD(" ms probes %u/%u", pk->probe_recv, pk->probe_sent);
	if (pk->cpu_busy_x100 != LG_U16_NONE)
		ADD(" cpu %u%%/si %u%%", pk->cpu_busy_x100 / 100, pk->cpu_softirq_x100 / 100);
	if (pk->load1_x100 != LG_U16_NONE)
		ADD(" load %u.%02u", pk->load1_x100 / 100, pk->load1_x100 % 100);
	if (pk->mem_total_kb && pk->mem_total_kb != LG_U32_NONE &&
	    pk->mem_avail_kb != LG_U32_NONE)
		ADD(" ram %u%%", (unsigned)(((uint64_t)pk->mem_total_kb - pk->mem_avail_kb) *
		                            100 / pk->mem_total_kb));
	if (pk->ct_count != LG_U32_NONE)
		ADD(" ct %u/%u", pk->ct_count, pk->ct_max);
	for (i = 0; i < pk->n_if && off < sizeof(line) - 128; i++) {
		const struct lg_ifrec *f = &pk->ifs[i];
		const struct srv_if *o = &r->ifs[i];
		ADD(" | %s %s", f->name, derived_state(f->state));
		if (f->speed != LG_SPEED_NONE)
			ADD(" %uM", f->speed);
		if (f->rflags & LG_RF_DEFAULT_ACTIVE)
			ADD(" *def");
		if (o->rate_ok)
			ADD(" rx %.2f tx %.2f Mb/s", o->rx_mbps, o->tx_mbps);
		if (f->c[C_RX_ERRS] || f->c[C_TX_ERRS])
			ADD(" err %llu/%llu", (unsigned long long)f->c[C_RX_ERRS],
			    (unsigned long long)f->c[C_TX_ERRS]);
	}
#undef ADD
	INFO("%s", line);
}

static void handle_packet(const uint8_t *data, size_t len, const char *src, int ttl)
{
	struct lg_packet pk;
	struct lg_hdr h;
	const struct srv_key *k = NULL;
	struct router *r;
	struct srv_link *l;
	time_t now = time(NULL);
	char kidhex[2 * LG_KEYID_LEN + 1];
	int rc, restart, rebooted, new_cycle, pppoe_reset = 0, i;
	double dt = 0;

	if (lg_peek(data, len, &h) != 0)
		return;     /* not our packet (e.g. a regular ping) */

	if (h.flags & LG_FLAG_ENCRYPTED) {
		k = find_key(h.key_id);
		if (!k) {
			rej_unknown++;
			hex8(h.key_id, kidhex);
			DBG("unknown key_id %s from %s", kidhex, src);
			return;
		}
	} else if (n_keys && !allow_plain) {
		rej_plain++;
		DBG("plaintext packet rejected from %s", src);
		return;
	}

	rc = lg_decode(data, len, k ? k->key : NULL, &pk);
	if (rc == LG_E_TAG) {
		rej_tag++;
		DBG("bad packet tag from %s (key %s)", src, k ? k->label : "-");
		return;
	}
	if (rc != 0) {
		rej_format++;
		return;
	}

	r = find_router(k, pk.name);
	if (!r) {
		EVENT("router table full, ignoring '%s'", pk.name);
		return;
	}

	if (replay_check(r, &pk, &restart) != 0) {
		rej_replay++;
		DBG("replayed packet %s ctr=%u from %s", pk.name, pk.h.pkt_ctr, src);
		return;
	}

	/* router name (from the encrypted part) */
	if (strcmp(r->name, pk.name)) {
		if (r->name[0])
			EVENT("%s: router renamed to '%s'", r->name, pk.name);
		snprintf(r->name, sizeof(r->name), "%s", pk.name);
	}
	if (restart == 3) {
		if (k) {
			hex8(k->kid, kidhex);
			EVENT("%s: new router (key %s, key_id %s), uptime %llu s", r->name,
			      k->label, kidhex, (unsigned long long)(pk.uptime_cs / 100));
		} else {
			EVENT("%s: new router (PLAINTEXT, no encryption), uptime %llu s",
			      r->name, (unsigned long long)(pk.uptime_cs / 100));
		}
	} else if (restart == 2) {
		EVENT("%s: ROUTER REBOOTED (uptime %llu s)", r->name,
		      (unsigned long long)(pk.uptime_cs / 100));
	} else if (restart == 1) {
		EVENT("%s: icmp-pulse restarted (router uptime %llu s)", r->name,
		      (unsigned long long)(pk.uptime_cs / 100));
	}
	rebooted = (restart == 2);
	if (pk.h.mono_ns > r->last_mono || restart)
		r->last_mono = pk.h.mono_ns;

	if (r->down) {
		EVENT("%s: ROUTER BACK after %ld s", r->name, (long)(now - r->last_seen));
		r->down = 0;
	}
	r->last_seen = now;

	/* new cycle -> interface counters for throughput */
	new_cycle = !r->have_seq || pk.h.seq != r->last_seq;
	if (new_cycle) {
		if (r->have_seq && !restart && pk.h.mono_ns > r->seq_mono)
			dt = (double)(pk.h.mono_ns - r->seq_mono) / 1e9;
		r->last_seq = pk.h.seq;
		r->seq_mono = pk.h.mono_ns;
		r->have_seq = 1;
	}
	check_ifs(r, &pk, rebooted || restart == 3, new_cycle, dt);

	/* uplink */
	l = find_link(r, pk.probe_idx);
	if (!l)
		return;
	if (pk.probe_idx != LG_PROBE_NONE && pk.probe_idx < pk.n_if) {
		snprintf(l->name, sizeof(l->name), "%s", pk.ifs[pk.probe_idx].name);
		pppoe_reset = r->ifs[pk.probe_idx].reset && !rebooted &&
		              !strncmp(l->name, "pppoe-", 6);
	} else {
		snprintf(l->name, sizeof(l->name), "(routing)");
	}
	/* PPPoE: counters reset = session re-established */
	for (i = 0; i < pk.n_if; i++)
		if (r->ifs[i].reset && !rebooted && restart != 3 &&
		    !strncmp(pk.ifs[i].name, "pppoe-", 6) &&
		    !(pk.probe_idx == i && strcmp(l->src, src) && l->src[0]))
			EVENT("%s: %s PPPoE session re-established", r->name, pk.ifs[i].name);

	l->interval_s = pk.probe_interval_s ? pk.probe_interval_s : 10;
	/* a packet received over the uplink proves it works: recover at once */
	if (l->down) {
		EVENT("%s: uplink %s UP again", r->name, l->name);
		l->down = 0;
	}
	if (strcmp(l->src, src)) {
		if (l->src[0]) {
			if (pppoe_reset)
				EVENT("%s: %s PPPoE session re-established, new address %s -> %s",
				      r->name, l->name, l->src, src);
			else
				EVENT("%s: uplink %s address change %s -> %s", r->name, l->name,
				      l->src, src);
		}
		snprintf(l->src, sizeof(l->src), "%s", src);
	}
	l->last_seen = now;

	hops_update(r->name, l->name, "to server", &l->hops_fwd, &l->pend_fwd,
	            &l->pend_fwd_n, ttl_hops(ttl));
	hops_update(r->name, l->name, "from server", &l->hops_back, &l->pend_back,
	            &l->pend_back_n, pk.reply_ttl ? ttl_hops(pk.reply_ttl) : -1);

	check_resources(r, &pk);
	print_info(r, l, &pk, src);
}

static void check_timeouts(void)
{
	time_t now = time(NULL);
	int i, j;

	for (i = 0; i < MAX_ROUTERS; i++) {
		struct router *r = &routers[i];
		int n_used = 0, n_stale = 0;
		if (!r->used)
			continue;

		/* every uplink is judged by its own interval */
		for (j = 0; j < MAX_LINKS; j++) {
			struct srv_link *l = &r->links[j];
			int stale;
			if (!l->used)
				continue;
			n_used++;
			stale = now - l->last_seen >
			        (time_t)MISS_LIMIT * l->interval_s + MARGIN_S;
			if (stale)
				n_stale++;
			if (stale && !l->down) {
				l->down = 1;
				EVENT("%s: UPLINK %s DOWN (%d packets missing, %ld s)",
				      r->name, l->name, MISS_LIMIT, (long)(now - l->last_seen));
			}
		}

		/* router down: every uplink has timed out (each by its own interval).
		 * Staleness is taken from the time of the last packet on each uplink. */
		if (n_used && !r->down && n_stale == n_used) {
			r->down = 1;
			EVENT("%s: ROUTER DOWN (no packets for %ld s, all uplinks timed out)",
			      r->name, (long)(now - r->last_seen));
		}
	}

	if (now - rej_last >= 60) {
		if (rej_unknown || rej_tag || rej_replay || rej_plain || rej_format)
			EVENT("rejected packets (60 s): unknown key %lu, bad tag %lu, "
			      "replayed %lu, plaintext %lu, malformed %lu",
			      rej_unknown, rej_tag, rej_replay, rej_plain, rej_format);
		rej_unknown = rej_tag = rej_replay = rej_plain = rej_format = 0;
		rej_last = now;
	}
}

/* ======================================================= main */

static void usage(const char *p, FILE *out)
{
	fprintf(out,
	        "Usage: %s [options]\n"
	        "  -k, --keys FILE     router keys, one per line: 64 hex chars and an\n"
	        "                      optional label (default %s)\n"
	        "  -P, --allow-plain   also accept plaintext packets when keys are loaded\n"
	        "  -q, --quiet         print events and alarms only\n"
	        "  -v, --verbose       also print details of rejected packets\n"
	        "  -V, --version       print version and exit\n"
	        "  -h, --help          print this help and exit\n"
	        "Without a keys file only plaintext packets are accepted.\n",
	        p, DEFAULT_KEYS);
}

int main(int argc, char **argv)
{
	static const struct option lopts[] = {
		{ "keys",        required_argument, NULL, 'k' },
		{ "allow-plain", no_argument,       NULL, 'P' },
		{ "quiet",       no_argument,       NULL, 'q' },
		{ "verbose",     no_argument,       NULL, 'v' },
		{ "version",     no_argument,       NULL, 'V' },
		{ "help",        no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int sock, opt, filt;
	const char *keyfile = NULL;
	struct sigaction sa;

	while ((opt = getopt_long(argc, argv, "k:PqvVh", lopts, NULL)) != -1) {
		switch (opt) {
		case 'k': keyfile = optarg; break;
		case 'P': allow_plain = 1; break;
		case 'q': quiet = 1; break;
		case 'v': verbose = 1; break;
		case 'V': printf("icmp-pulse-server %s\n", ICMP_PULSE_VERSION); return 0;
		case 'h': usage(argv[0], stdout); return 0;
		default: usage(argv[0], stderr); return 2;
		}
	}
	if (keyfile) {
		if (load_keys(keyfile) != 0)
			return 1;
	} else if (access(DEFAULT_KEYS, F_OK) == 0) {
		keyfile = DEFAULT_KEYS;
		if (load_keys(keyfile) != 0)
			return 1;
	}

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		perror("socket(SOCK_RAW) - root or CAP_NET_RAW required");
		return 1;
	}
	filt = ~(1 << ICMP_ECHO_REQ);
	if (setsockopt(sock, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt)) != 0)
		perror("ICMP_FILTER");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	rej_last = time(NULL);
	EVENT("icmp-pulse-server %s started: keys %d (%s), plaintext packets %s",
	      ICMP_PULSE_VERSION, n_keys, keyfile ? keyfile : "no keys file",
	      (!n_keys || allow_plain) ? "accepted" : "rejected");

	while (!stop) {
		struct pollfd pfd = { .fd = sock, .events = POLLIN };

		if (poll(&pfd, 1, 1000) > 0 && (pfd.revents & POLLIN)) {
			for (;;) {
				uint8_t buf[2048];
				struct sockaddr_in from;
				socklen_t fl = sizeof(from);
				char src[INET_ADDRSTRLEN];
				ssize_t n;
				size_t ihl;

				n = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
				             (struct sockaddr *)&from, &fl);
				if (n < 0)
					break;
				if (n < 28)
					continue;
				ihl = (size_t)(buf[0] & 0x0F) * 4;
				if ((size_t)n < ihl + 8 || buf[ihl] != ICMP_ECHO_REQ)
					continue;
				inet_ntop(AF_INET, &from.sin_addr, src, sizeof(src));
				handle_packet(buf + ihl + 8, (size_t)n - ihl - 8, src, buf[8]);
			}
		}
		check_timeouts();
	}
	cp_wipe(keys, sizeof(keys));
	close(sock);
	return 0;
}
