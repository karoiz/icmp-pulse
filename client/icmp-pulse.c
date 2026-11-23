// SPDX-License-Identifier: GPL-2.0-only
/*
 * icmp-pulse - health reporting agent for OpenWrt routers
 *
 * Every `interval` seconds it collects:
 *   - uptime, kernel boot_id, CPU (/proc/stat), load average, RAM, conntrack,
 *   - for the configured interfaces: rx/tx counters (bytes, packets, errors)
 *     from /proc/net/dev, link state from /sys/class/net, default route
 *     from /proc/net/route,
 * and sends them to the server in an ICMP Echo Request (format: docs/PROTOCOL.md).
 * The payload is encrypted with ChaCha20-Poly1305 when `option key` is set.
 *
 * Interfaces with "option probe 1" get their own packet, sent through a socket
 * bound to the interface (SO_BINDTODEVICE), so every uplink is tested separately.
 * If no scheduled uplink is healthy, the packet is sent through another one
 * (failover). The server kernel returns an Echo Reply with the same payload;
 * icmp-pulse verifies its tag, measures the RTT and records the reply TTL.
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
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <getopt.h>

#include "proto.h"
#include "version.h"

#ifndef SOL_RAW
#define SOL_RAW 255
#endif
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif

#define ICMP_ECHO_REQ   8
#define ICMP_ECHO_REPLY 0
#define RING            10      /* RTT min/avg/max window per uplink */
#define DNS_REFRESH     60      /* re-resolve the server name every N cycles */

#define DEFAULT_CONFIG   "/etc/config/icmp-pulse"
#define UCI_SECTION      "icmp-pulse"
#define SYSLOG_IDENT     "icmp-pulse"
#define DEFAULT_INTERVAL 10

/* ======================================================= configuration */

struct ifcfg {
	char dev[LG_IFNAME_LEN + 1];
	int  probe;
	int  probe_interval;
};

struct config {
	char server[256];
	int  interval;
	char router_id[128];
	char key_hex[128];
	struct ifcfg ifs[LG_MAX_IF];
	int  n_if;
};

/* ======================================================= uplink state */

struct slot {
	int      used;
	uint32_t pkt_ctr;
	int64_t  rtt_us;            /* -1 = no reply */
};

struct link {
	uint8_t  idx;               /* interface record index; 0xFF = not bound */
	const char *dev;            /* NULL = not bound (follows routing) */
	int      every;
	uint16_t interval_s;
	struct slot ring[RING];
	int      pos;
	int      last_pos;          /* ring slot of the last probe, -1 = none */
	uint32_t sent, recv;        /* cumulative counters */
	uint8_t  last_ttl;
	int      fail;              /* consecutive failures: no reply or send error */
};

static struct config cfg;
static struct link links[LG_MAX_IF];
static int n_links;
static char my_name[LG_NAME_LEN + 1];
static uint8_t key[LG_KEY_LEN];
static uint8_t key_id[LG_KEYID_LEN];
static int have_key;
static uint64_t boot_id;
static uint32_t pkt_ctr;
static uint16_t icmp_ident;
static int verbose;
static volatile sig_atomic_t stop;

static struct sockaddr_in srv_addr;
static int srv_ok;

/* ======================================================= helpers */

static uint64_t mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int read_file(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = 0;
	return (int)n;
}

static int read_sysfs(const char *dev, const char *attr, char *buf, size_t len)
{
	char path[128];
	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", dev, attr);
	return read_file(path, buf, len);
}

static int read_u32_file(const char *path, uint32_t *out)
{
	char buf[32];
	if (read_file(path, buf, sizeof(buf)) <= 0)
		return -1;
	*out = (uint32_t)strtoul(buf, NULL, 10);
	return 0;
}

static int random_bytes(void *p, size_t n)
{
	int fd = open("/dev/urandom", O_RDONLY);
	ssize_t r;

	if (fd < 0)
		return -1;
	r = read(fd, p, n);
	close(fd);
	return r == (ssize_t)n ? 0 : -1;
}

/* ======================================================= UCI file parser */

static int next_token(char **pp, char *out, size_t outlen)
{
	char *p = *pp;
	size_t n = 0;

	while (*p && isspace((unsigned char)*p))
		p++;
	if (!*p || *p == '#')
		return 0;
	if (*p == '\'' || *p == '"') {
		char q = *p++;
		while (*p && *p != q) {
			if (n + 1 < outlen)
				out[n++] = *p;
			p++;
		}
		if (*p == q)
			p++;
	} else {
		while (*p && !isspace((unsigned char)*p)) {
			if (n + 1 < outlen)
				out[n++] = *p;
			p++;
		}
	}
	out[n] = 0;
	*pp = p;
	return 1;
}

static int parse_int(const char *s, int *out)
{
	char *end;
	long v = strtol(s, &end, 10);
	if (*s == 0 || *end != 0 || v < 0 || v > 86400)
		return -1;
	*out = (int)v;
	return 0;
}

static int is_true(const char *v)
{
	return !strcmp(v, "1") || !strcmp(v, "yes") || !strcmp(v, "on") ||
	       !strcmp(v, "true");
}

static int load_config(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[512], kw[32], k[64], v[256];
	enum { SEC_NONE, SEC_MAIN, SEC_IF } sec = SEC_NONE;
	struct ifcfg *cur = NULL;
	int ln = 0, i;

	memset(&cfg, 0, sizeof(cfg));
	cfg.interval = DEFAULT_INTERVAL;
	if (!f) {
		syslog(LOG_ERR, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		ln++;
		if (!next_token(&p, kw, sizeof(kw)))
			continue;
		if (!strcmp(kw, "config")) {
			if (!next_token(&p, k, sizeof(k))) {
				syslog(LOG_ERR, "%s:%d: missing section type", path, ln);
				goto err;
			}
			if (!strcmp(k, UCI_SECTION)) {
				sec = SEC_MAIN;
			} else if (!strcmp(k, "interface")) {
				if (cfg.n_if >= LG_MAX_IF) {
					syslog(LOG_ERR, "%s:%d: too many interfaces (max %d)",
					       path, ln, LG_MAX_IF);
					goto err;
				}
				sec = SEC_IF;
				cur = &cfg.ifs[cfg.n_if++];
				memset(cur, 0, sizeof(*cur));
			} else {
				sec = SEC_NONE;
			}
			continue;
		}
		if (strcmp(kw, "option") && strcmp(kw, "list"))
			continue;
		if (!next_token(&p, k, sizeof(k)) || !next_token(&p, v, sizeof(v))) {
			syslog(LOG_ERR, "%s:%d: incomplete option", path, ln);
			goto err;
		}
		if (sec == SEC_MAIN) {
			if (!strcmp(k, "server"))
				snprintf(cfg.server, sizeof(cfg.server), "%s", v);
			else if (!strcmp(k, "interval")) {
				if (parse_int(v, &cfg.interval) || cfg.interval < 1) {
					syslog(LOG_ERR, "%s:%d: invalid interval", path, ln);
					goto err;
				}
			} else if (!strcmp(k, "router_id"))
				snprintf(cfg.router_id, sizeof(cfg.router_id), "%s", v);
			else if (!strcmp(k, "key"))
				snprintf(cfg.key_hex, sizeof(cfg.key_hex), "%s", v);
		} else if (sec == SEC_IF) {
			if (!strcmp(k, "device")) {
				if (strlen(v) > LG_IFNAME_LEN - 1) {
					syslog(LOG_ERR, "%s:%d: interface name longer than 15 characters",
					       path, ln);
					goto err;
				}
				snprintf(cur->dev, sizeof(cur->dev), "%s", v);
			} else if (!strcmp(k, "probe")) {
				cur->probe = is_true(v);
			} else if (!strcmp(k, "probe_interval")) {
				if (parse_int(v, &cur->probe_interval)) {
					syslog(LOG_ERR, "%s:%d: invalid probe_interval", path, ln);
					goto err;
				}
			}
		}
	}
	fclose(f);

	if (!cfg.server[0]) {
		syslog(LOG_ERR, "missing 'option server' in %s", path);
		return -1;
	}
	for (i = 0; i < cfg.n_if; i++)
		if (!cfg.ifs[i].dev[0]) {
			syslog(LOG_ERR, "interface section #%d has no 'option device'", i + 1);
			return -1;
		}
	return 0;
err:
	fclose(f);
	return -1;
}

/* ======================================================= name and key */

static int setup_name(void)
{
	char host[128];

	if (cfg.router_id[0]) {
		if (strlen(cfg.router_id) > LG_NAME_LEN) {
			syslog(LOG_ERR, "router_id '%s' is longer than %d characters",
			       cfg.router_id, LG_NAME_LEN);
			return -1;
		}
		snprintf(my_name, sizeof(my_name), "%s", cfg.router_id);
		return 0;
	}
	if (read_file("/proc/sys/kernel/hostname", host, sizeof(host)) <= 0 &&
	    (gethostname(host, sizeof(host)) != 0 || !host[0])) {
		syslog(LOG_ERR, "cannot read hostname");
		return -1;
	}
	if (strlen(host) > LG_NAME_LEN)
		syslog(LOG_WARNING, "hostname '%s' is longer than %d characters - truncated",
		       host, LG_NAME_LEN);
	memcpy(my_name, host, LG_NAME_LEN);
	my_name[LG_NAME_LEN] = 0;
	if (!strcmp(my_name, "OpenWrt"))
		syslog(LOG_WARNING, "router name is the default 'OpenWrt' - change the hostname "
		       "or set router_id");
	return 0;
}

static int setup_key(void)
{
	if (!cfg.key_hex[0]) {
		syslog(LOG_WARNING, "no 'option key' - packets will be sent UNENCRYPTED "
		       "(for testing only)");
		return 0;
	}
	if (lg_key_from_hex(cfg.key_hex, key) != 0) {
		syslog(LOG_ERR, "'option key' must be 64 hex characters (32 bytes)");
		return -1;
	}
	cp_wipe(cfg.key_hex, sizeof(cfg.key_hex));
	lg_key_id(key, key_id);
	have_key = 1;
	return 0;
}

/* ======================================================= server address */

static void resolve_server(void)
{
	struct addrinfo hints, *res = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;
	rc = getaddrinfo(cfg.server, NULL, &hints, &res);
	if (rc != 0 || !res) {
		if (!srv_ok)
			syslog(LOG_WARNING, "cannot resolve '%s': %s",
			       cfg.server, gai_strerror(rc));
		return;
	}
	if (!srv_ok || memcmp(&srv_addr, res->ai_addr, sizeof(srv_addr)))
		syslog(LOG_INFO, "server: %s",
		       inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr));
	memcpy(&srv_addr, res->ai_addr, sizeof(srv_addr));
	srv_ok = 1;
	freeaddrinfo(res);
}

/* ======================================================= router data */

static uint64_t read_uptime_cs(void)
{
	char buf[64], *p;
	uint64_t s, cs = 0;

	if (read_file("/proc/uptime", buf, sizeof(buf)) <= 0)
		return 0;
	s = strtoull(buf, &p, 10);
	if (*p == '.' && isdigit((unsigned char)p[1])) {
		cs = (uint64_t)(p[1] - '0') * 10;
		if (isdigit((unsigned char)p[2]))
			cs += (uint64_t)(p[2] - '0');
	}
	return s * 100 + cs;
}

/* first 4 bytes (8 hex characters) of /proc/sys/kernel/random/boot_id */
static uint32_t read_kboot_id(void)
{
	char buf[64];
	if (read_file("/proc/sys/kernel/random/boot_id", buf, sizeof(buf)) < 8)
		return 0;
	buf[8] = 0;
	return (uint32_t)strtoul(buf, NULL, 16);
}

/* "0.42 0.30 ..." -> 42 */
static uint16_t read_load1(void)
{
	char buf[128], *p;
	unsigned long ip, fr = 0;

	if (read_file("/proc/loadavg", buf, sizeof(buf)) <= 0)
		return LG_U16_NONE;
	ip = strtoul(buf, &p, 10);
	if (*p == '.' && isdigit((unsigned char)p[1])) {
		fr = (unsigned long)(p[1] - '0') * 10;
		if (isdigit((unsigned char)p[2]))
			fr += (unsigned long)(p[2] - '0');
	}
	ip = ip * 100 + fr;
	return ip >= LG_U16_NONE ? LG_U16_NONE - 1 : (uint16_t)ip;
}

static void read_meminfo(uint32_t *total, uint32_t *avail)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[128];
	unsigned long v;

	*total = *avail = LG_U32_NONE;
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "MemTotal: %lu", &v) == 1)
			*total = (uint32_t)v;
		else if (sscanf(line, "MemAvailable: %lu", &v) == 1)
			*avail = (uint32_t)v;
	}
	fclose(f);
}

/* CPU usage since the previous call (the "cpu" line of /proc/stat). */
static void read_cpu(uint16_t *busy, uint16_t *softirq)
{
	static unsigned long long p_total, p_idle, p_soft;
	static int have_prev;
	unsigned long long u, n, s, i, w, q, sq, st = 0, total, idle, dt;
	char line[256];
	FILE *f = fopen("/proc/stat", "r");
	int k;

	*busy = *softirq = LG_U16_NONE;
	if (!f)
		return;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return;
	}
	fclose(f);
	k = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
	           &u, &n, &s, &i, &w, &q, &sq, &st);
	if (k < 7)
		return;
	total = u + n + s + i + w + q + sq + st;
	idle = i + w;
	if (have_prev && total > p_total) {
		dt = total - p_total;
		*busy = (uint16_t)((dt - (idle - p_idle)) * 10000 / dt);
		*softirq = (uint16_t)((sq - p_soft) * 10000 / dt);
	}
	p_total = total;
	p_idle = idle;
	p_soft = sq;
	have_prev = 1;
}

/* ======================================================= interface data */

static void read_proc_net_dev(struct lg_ifrec *recs, int n)
{
	FILE *f = fopen("/proc/net/dev", "r");
	char line[512];
	int i;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *colon = strchr(line, ':'), *name = line;
		unsigned long long v[16];
		if (!colon)
			continue;
		*colon = 0;
		while (*name == ' ')
			name++;
		if (sscanf(colon + 1,
		           "%llu %llu %llu %llu %llu %llu %llu %llu "
		           "%llu %llu %llu %llu %llu %llu %llu %llu",
		           &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7],
		           &v[8], &v[9], &v[10], &v[11], &v[12], &v[13], &v[14],
		           &v[15]) < 11)
			continue;
		for (i = 0; i < n; i++) {
			if (strcmp(recs[i].name, name))
				continue;
			recs[i].c[C_RX_BYTES]   = v[0];
			recs[i].c[C_RX_PACKETS] = v[1];
			recs[i].c[C_RX_ERRS]    = v[2];
			recs[i].c[C_TX_BYTES]   = v[8];
			recs[i].c[C_TX_PACKETS] = v[9];
			recs[i].c[C_TX_ERRS]    = v[10];
		}
	}
	fclose(f);
}

static void read_link_state(struct lg_ifrec *r)
{
	char buf[64];
	unsigned oper = LG_OPER_UNKNOWN, duplex = 0;
	struct stat st;

	snprintf(buf, sizeof(buf), "/sys/class/net/%s", r->name);
	if (stat(buf, &st) != 0) {
		r->state = LG_OPER_NOTPRESENT;
		r->speed = LG_SPEED_NONE;
		return;
	}
	if (read_sysfs(r->name, "operstate", buf, sizeof(buf)) > 0) {
		if (!strcmp(buf, "up")) oper = LG_OPER_UP;
		else if (!strcmp(buf, "down")) oper = LG_OPER_DOWN;
		else if (!strcmp(buf, "lowerlayerdown")) oper = LG_OPER_LOWERLAYERDOWN;
		else if (!strcmp(buf, "dormant")) oper = LG_OPER_DORMANT;
		else if (!strcmp(buf, "testing")) oper = LG_OPER_TESTING;
		else if (!strcmp(buf, "notpresent")) oper = LG_OPER_NOTPRESENT;
	}
	r->state = (uint8_t)oper;
	if (read_sysfs(r->name, "flags", buf, sizeof(buf)) > 0 &&
	    (strtoul(buf, NULL, 16) & 0x1))
		r->state |= LG_ST_ADMIN_UP;
	if (read_sysfs(r->name, "carrier", buf, sizeof(buf)) > 0) {
		if (buf[0] == '1')
			r->state |= LG_ST_CARRIER;
	} else {
		r->state |= LG_ST_CARRIER_UNK;
	}
	if (read_sysfs(r->name, "duplex", buf, sizeof(buf)) > 0) {
		if (!strcmp(buf, "half")) duplex = 1;
		else if (!strcmp(buf, "full")) duplex = 2;
	}
	r->state |= (uint8_t)(duplex << LG_ST_DUPLEX_SHIFT);
	r->speed = LG_SPEED_NONE;
	if (read_sysfs(r->name, "speed", buf, sizeof(buf)) > 0) {
		long s = strtol(buf, NULL, 10);
		if (s > 0)
			r->speed = s >= LG_SPEED_NONE ? LG_SPEED_NONE - 1 : (uint16_t)s;
	}
	if (read_sysfs(r->name, "carrier_changes", buf, sizeof(buf)) > 0)
		r->carrier_changes = (uint32_t)strtoul(buf, NULL, 10);
}

static void read_routes(struct lg_ifrec *recs, int n)
{
	FILE *f = fopen("/proc/net/route", "r");
	char line[256], ifn[32], best_if[32] = "";
	unsigned long dst, gw, mask;
	unsigned flags;
	int refcnt, use, metric, best = -1, i;

	if (!f)
		return;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%31s %lx %lx %x %d %d %d %lx",
		           ifn, &dst, &gw, &flags, &refcnt, &use, &metric, &mask) != 8)
			continue;
		if (dst != 0 || mask != 0 || !(flags & 0x1))
			continue;
		for (i = 0; i < n; i++)
			if (!strcmp(recs[i].name, ifn))
				recs[i].rflags |= LG_RF_DEFAULT_ANY;
		if (best < 0 || metric < best) {
			best = metric;
			snprintf(best_if, sizeof(best_if), "%s", ifn);
		}
	}
	fclose(f);
	for (i = 0; i < n; i++)
		if (best >= 0 && !strcmp(recs[i].name, best_if))
			recs[i].rflags |= LG_RF_DEFAULT_ACTIVE;
}

static void collect(struct lg_packet *pk)
{
	int i;

	pk->n_if = (uint8_t)cfg.n_if;
	for (i = 0; i < cfg.n_if; i++) {
		memset(&pk->ifs[i], 0, sizeof(pk->ifs[i]));
		snprintf(pk->ifs[i].name, sizeof(pk->ifs[i].name), "%s", cfg.ifs[i].dev);
		if (cfg.ifs[i].probe)
			pk->ifs[i].rflags |= LG_RF_PROBED;
	}
	read_proc_net_dev(pk->ifs, pk->n_if);
	for (i = 0; i < pk->n_if; i++)
		read_link_state(&pk->ifs[i]);
	read_routes(pk->ifs, pk->n_if);

	pk->uptime_cs = read_uptime_cs();
	pk->kboot_id = read_kboot_id();
	read_cpu(&pk->cpu_busy_x100, &pk->cpu_softirq_x100);
	pk->load1_x100 = read_load1();
	read_meminfo(&pk->mem_total_kb, &pk->mem_avail_kb);
	if (read_u32_file("/proc/sys/net/netfilter/nf_conntrack_count", &pk->ct_count))
		pk->ct_count = LG_U32_NONE;
	if (read_u32_file("/proc/sys/net/netfilter/nf_conntrack_max", &pk->ct_max))
		pk->ct_max = LG_U32_NONE;
}

/* ======================================================= uplinks */

static void setup_links(void)
{
	int i, pi;
	struct link *l;

	n_links = 0;
	for (i = 0; i < cfg.n_if; i++) {
		if (!cfg.ifs[i].probe)
			continue;
		l = &links[n_links++];
		memset(l, 0, sizeof(*l));
		l->idx = (uint8_t)i;
		l->dev = cfg.ifs[i].dev;
		pi = cfg.ifs[i].probe_interval > 0 ? cfg.ifs[i].probe_interval : cfg.interval;
		l->every = (pi + cfg.interval - 1) / cfg.interval;
		if (l->every < 1)
			l->every = 1;
		l->interval_s = (uint16_t)(l->every * cfg.interval);
		l->last_pos = -1;
	}
	if (n_links == 0) {
		l = &links[n_links++];
		memset(l, 0, sizeof(*l));
		l->idx = LG_PROBE_NONE;
		l->every = 1;
		l->interval_s = (uint16_t)cfg.interval;
		l->last_pos = -1;
	}
}

static void link_fill(const struct link *l, struct lg_packet *pk)
{
	int i, recv = 0;
	int64_t mn = -1, mx = -1, sum = 0;

	for (i = 0; i < RING; i++) {
		const struct slot *s = &l->ring[i];
		if (!s->used || s->rtt_us < 0)
			continue;
		recv++;
		sum += s->rtt_us;
		if (mn < 0 || s->rtt_us < mn) mn = s->rtt_us;
		if (s->rtt_us > mx) mx = s->rtt_us;
	}
	if (recv) {
		pk->rtt_min_us = (uint32_t)mn;
		pk->rtt_max_us = (uint32_t)mx;
		pk->rtt_avg_us = (uint32_t)(sum / recv);
	} else {
		pk->rtt_min_us = pk->rtt_avg_us = pk->rtt_max_us = LG_U32_NONE;
	}
	pk->rtt_last_us = LG_U32_NONE;
	if (l->last_pos >= 0 && l->ring[l->last_pos].rtt_us >= 0)
		pk->rtt_last_us = (uint32_t)l->ring[l->last_pos].rtt_us;
	pk->probe_sent = l->sent;
	pk->probe_recv = l->recv;
	pk->reply_ttl = l->last_ttl;
}

/* ======================================================= send and receive */

static int send_icmp(int rxsock, const struct link *l, const uint8_t *data,
                     size_t len, uint16_t icmp_seq)
{
	uint8_t pkt[8 + LG_MAX_PKT];
	uint16_t cs;
	int s = rxsock, rc, e;

	pkt[0] = ICMP_ECHO_REQ;
	pkt[1] = 0;
	pkt[2] = pkt[3] = 0;
	pkt[4] = (uint8_t)(icmp_ident >> 8);
	pkt[5] = (uint8_t)icmp_ident;
	pkt[6] = (uint8_t)(icmp_seq >> 8);
	pkt[7] = (uint8_t)icmp_seq;
	memcpy(pkt + 8, data, len);
	cs = lg_icmp_csum(pkt, len + 8);
	pkt[2] = (uint8_t)(cs >> 8);
	pkt[3] = (uint8_t)cs;

	if (l->dev) {
		s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (s < 0)
			return -1;
		if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, l->dev,
		               (socklen_t)strlen(l->dev) + 1) != 0) {
			e = errno;
			close(s);
			errno = e;
			return -1;
		}
	}
	rc = (int)sendto(s, pkt, len + 8, 0, (struct sockaddr *)&srv_addr,
	                 sizeof(srv_addr));
	if (l->dev) {
		e = errno;
		close(s);
		errno = e;
	}
	return rc < 0 ? -1 : 0;
}

static void handle_replies(int sock)
{
	uint8_t buf[2048];
	struct lg_hdr h;
	struct lg_packet pk;
	ssize_t n;
	size_t ihl;
	int i, j;

	for (;;) {
		n = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
		if (n < 0)
			return;
		if (n < 20)
			continue;
		ihl = (size_t)(buf[0] & 0x0F) * 4;
		if ((size_t)n < ihl + 8 || buf[ihl] != ICMP_ECHO_REPLY)
			continue;
		if (lg_peek(buf + ihl + 8, (size_t)n - ihl - 8, &h) != 0)
			continue;
		if (h.boot_id != boot_id)
			continue;   /* not our packet (e.g. a regular ping) */
		/* the reply must carry our own, correctly authenticated packet */
		if (lg_decode(buf + ihl + 8, (size_t)n - ihl - 8,
		              have_key ? key : NULL, &pk) != 0) {
			if (verbose)
				syslog(LOG_DEBUG, "reply rejected (bad tag/format)");
			continue;
		}
		if (have_key != !!(pk.h.flags & LG_FLAG_ENCRYPTED))
			continue;

		for (i = 0; i < n_links; i++) {
			struct link *l = &links[i];
			for (j = 0; j < RING; j++) {
				struct slot *s = &l->ring[j];
				if (!s->used || s->pkt_ctr != h.pkt_ctr || s->rtt_us >= 0)
					continue;
				s->rtt_us = (int64_t)((mono_ns() - h.mono_ns) / 1000);
				l->recv++;
				l->fail = 0;
				l->last_ttl = buf[8];   /* TTL from the IP header of the reply */
				if (verbose)
					syslog(LOG_DEBUG, "reply ctr=%u via %s rtt=%.3f ms ttl=%u",
					       h.pkt_ctr, l->dev ? l->dev : "(routing)",
					       s->rtt_us / 1000.0, buf[8]);
			}
		}
	}
}

/* Uplink is healthy: interface present and up, the last send succeeded
 * and replies to the last 2 probes in a row are not missing. */
static int link_healthy(const struct link *l, const struct lg_packet *pk)
{
	if (l->idx != LG_PROBE_NONE) {
		uint8_t st = pk->ifs[l->idx].state;
		if ((st & LG_ST_OPER_MASK) == LG_OPER_NOTPRESENT || !(st & LG_ST_ADMIN_UP))
			return 0;
	}
	return l->fail < 2;
}

static int link_present(const struct link *l, const struct lg_packet *pk)
{
	return l->idx == LG_PROBE_NONE ||
	       (pk->ifs[l->idx].state & LG_ST_OPER_MASK) != LG_OPER_NOTPRESENT;
}

/* Sends one packet over the uplink. Returns 0 if sending succeeded. */
static int send_on_link(int sock, struct link *l, struct lg_packet *pk,
                        uint32_t cycle, int failover)
{
	uint8_t buf[LG_MAX_PKT];
	struct slot *s;
	size_t len;

	/* previous probe got no reply -> one more failure in a row */
	if (l->last_pos >= 0 && l->ring[l->last_pos].rtt_us < 0)
		l->fail++;

	pk->probe_idx = l->idx;
	pk->probe_interval_s = l->interval_s;
	link_fill(l, pk);
	pk->h.pkt_ctr = pkt_ctr++;
	pk->h.mono_ns = mono_ns();
	len = lg_encode(pk, have_key ? key : NULL, buf, sizeof(buf));
	if (!len) {
		syslog(LOG_ERR, "packet encoding error");
		return -1;
	}

	s = &l->ring[l->pos];
	s->used = 1;
	s->pkt_ctr = pk->h.pkt_ctr;
	s->rtt_us = -1;
	l->last_pos = l->pos;
	l->pos = (l->pos + 1) % RING;
	l->sent++;

	if (send_icmp(sock, l, buf, len, (uint16_t)pk->h.pkt_ctr) != 0) {
		l->fail = 2;    /* send error = uplink unhealthy immediately */
		if (verbose)
			syslog(LOG_DEBUG, "send seq=%u via %s failed: %s", cycle,
			       l->dev ? l->dev : "(routing)", strerror(errno));
		return -1;
	}
	if (verbose)
		syslog(LOG_DEBUG, "sent seq=%u ctr=%u via %s%s (%zu B, %s) probes %u/%u",
		       cycle, pk->h.pkt_ctr, l->dev ? l->dev : "(routing)",
		       failover ? " [failover]" : "", len,
		       have_key ? "encrypted" : "PLAINTEXT", pk->probe_recv, pk->probe_sent);
	return 0;
}

static void do_cycle(int sock, uint32_t cycle)
{
	struct lg_packet pk;
	int i, pass, sent_here[LG_MAX_IF + 1], ok = 0;

	if (!srv_ok || cycle % DNS_REFRESH == 0)
		resolve_server();

	memset(&pk, 0, sizeof(pk));
	collect(&pk);       /* always, so that CPU usage covers equal periods */
	if (!srv_ok)
		return;

	snprintf(pk.name, sizeof(pk.name), "%s", my_name);
	pk.h.boot_id = boot_id;
	pk.h.seq = cycle;

	/* 1. uplinks scheduled in this cycle */
	for (i = 0; i < n_links; i++) {
		struct link *l = &links[i];
		sent_here[i] = 0;
		if (cycle % (uint32_t)l->every)
			continue;
		if (!link_present(l, &pk)) {
			if (verbose)
				syslog(LOG_DEBUG, "skipping %s: interface not present", l->dev);
			continue;
		}
		sent_here[i] = 1;
		/* health is checked after sending: it accounts for a missing previous reply */
		if (send_on_link(sock, l, &pk, cycle, 0) == 0 && link_healthy(l, &pk))
			ok = 1;
	}

	/* 2. no scheduled uplink is healthy: fail over to another one,
	 *    healthy ones first, then any other present uplink */
	for (pass = 0; !ok && pass < 2; pass++) {
		for (i = 0; i < n_links && !ok; i++) {
			struct link *l = &links[i];
			if (sent_here[i] || !link_present(l, &pk))
				continue;
			if (pass == 0 && !link_healthy(l, &pk))
				continue;
			sent_here[i] = 1;
			if (send_on_link(sock, l, &pk, cycle, 1) == 0 && link_healthy(l, &pk))
				ok = 1;
		}
	}
}

/* ======================================================= main */

static void print_hex(const uint8_t *b, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		printf("%02x", b[i]);
}

static int cmd_genkey(void)
{
	uint8_t k[LG_KEY_LEN], kid[LG_KEYID_LEN];

	if (random_bytes(k, sizeof(k)) != 0) {
		fprintf(stderr, "cannot read /dev/urandom\n");
		return 1;
	}
	lg_key_id(k, kid);
	printf("key:    ");
	print_hex(k, sizeof(k));
	printf("\nkey_id: ");
	print_hex(kid, sizeof(kid));
	printf("\n\nOn the router, in %s (section '%s'):\n"
	       "\toption key '", DEFAULT_CONFIG, UCI_SECTION);
	print_hex(k, sizeof(k));
	printf("'\nOn the server, in the keys file (/etc/icmp-pulse/keys):\n\t");
	print_hex(k, sizeof(k));
	printf(" router-name\n");
	cp_wipe(k, sizeof(k));
	return 0;
}

static void usage(const char *p, FILE *out)
{
	fprintf(out,
	        "Usage: %s [options]\n"
	        "  -c, --config FILE  configuration file (default %s)\n"
	        "  -f, --stderr       also log to stderr\n"
	        "  -v, --verbose      verbose logging (every packet and reply)\n"
	        "  -t, --check        check the configuration, print key_id and exit\n"
	        "  -g, --genkey       generate a new key and exit\n"
	        "  -V, --version      print version and exit\n"
	        "  -h, --help         print this help and exit\n",
	        p, DEFAULT_CONFIG);
}

int main(int argc, char **argv)
{
	static const struct option lopts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "stderr",  no_argument,       NULL, 'f' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "check",   no_argument,       NULL, 't' },
		{ "genkey",  no_argument,       NULL, 'g' },
		{ "version", no_argument,       NULL, 'V' },
		{ "help",    no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	const char *cfgpath = DEFAULT_CONFIG;
	int opt, logopt = LOG_PID, sock, filt, test_only = 0;
	uint32_t cycle = 0;
	uint64_t next, now, step;
	struct sigaction sa;

	while ((opt = getopt_long(argc, argv, "c:fvtgVh", lopts, NULL)) != -1) {
		switch (opt) {
		case 'c': cfgpath = optarg; break;
		case 'f': logopt |= LOG_PERROR; break;
		case 'v': verbose = 1; break;
		case 't': test_only = 1; logopt |= LOG_PERROR; break;
		case 'g': return cmd_genkey();
		case 'V': printf("icmp-pulse %s\n", ICMP_PULSE_VERSION); return 0;
		case 'h': usage(argv[0], stdout); return 0;
		default: usage(argv[0], stderr); return 2;
		}
	}
	openlog(SYSLOG_IDENT, logopt, LOG_DAEMON);
	if (!verbose)
		setlogmask(LOG_UPTO(LOG_INFO));

	if (load_config(cfgpath) != 0 || setup_name() != 0 || setup_key() != 0)
		return 1;
	setup_links();

	if (test_only) {
		printf("configuration OK: name='%s' server=%s interval=%ds "
		       "interfaces=%d uplinks=%d\n", my_name, cfg.server, cfg.interval,
		       cfg.n_if, n_links);
		if (have_key) {
			printf("encryption: ChaCha20-Poly1305, key_id=");
			print_hex(key_id, LG_KEYID_LEN);
			printf("\n");
		} else {
			printf("encryption: NONE (plaintext packets)\n");
		}
		return 0;
	}

	/* boot_id: 64 random bits; 0xFF..FF is reserved for key_id */
	do {
		if (random_bytes(&boot_id, sizeof(boot_id)) != 0)
			boot_id = mono_ns() ^ ((uint64_t)getpid() << 32) ^ (uint64_t)time(NULL);
	} while (boot_id == UINT64_MAX);
	icmp_ident = (uint16_t)getpid();

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		syslog(LOG_ERR, "socket(SOCK_RAW): %s (root or CAP_NET_RAW required)",
		       strerror(errno));
		return 1;
	}
	filt = ~(1 << ICMP_ECHO_REPLY);
	if (setsockopt(sock, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt)) != 0)
		syslog(LOG_WARNING, "ICMP_FILTER not available: %s", strerror(errno));

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	syslog(LOG_INFO, "icmp-pulse %s started: name='%s' server=%s interval=%ds "
	       "interfaces=%d uplinks=%d encryption=%s", ICMP_PULSE_VERSION, my_name,
	       cfg.server, cfg.interval, cfg.n_if, n_links,
	       have_key ? "ChaCha20-Poly1305" : "NONE");

	step = (uint64_t)cfg.interval * 1000000000ull;
	next = mono_ns();
	while (!stop) {
		struct pollfd pfd = { .fd = sock, .events = POLLIN };
		int timeout;

		now = mono_ns();
		if (now >= next) {
			do_cycle(sock, cycle++);
			next += step;
			if (next <= now)
				next = now + step;
		}
		now = mono_ns();
		timeout = next > now ? (int)((next - now) / 1000000ull) + 1 : 0;
		if (poll(&pfd, 1, timeout) > 0 && (pfd.revents & POLLIN))
			handle_replies(sock);
	}
	syslog(LOG_INFO, "stopped");
	cp_wipe(key, sizeof(key));
	close(sock);
	return 0;
}
