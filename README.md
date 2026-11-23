# icmp-pulse

Lightweight router health monitoring for OpenWrt: sends interface stats, uptime and system data to a server via ICMP heartbeats.

`icmp-pulse` runs on the router and every 10 s sends an ICMP Echo Request carrying diagnostic data to the server.
`icmp-pulse-server` runs on a Linux server, receives the packets, detects outages and reports events.
Data is encrypted with ChaCha20-Poly1305 (RFC 8439) using a built-in implementation, no external libraries.

Wire format: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## What is reported
- **router:** name, uptime, kernel boot identifier, CPU usage (total and softirq), load average, RAM, conntrack table usage;
- **every probed uplink:** RTT (last, min/avg/max over 10 probes), cumulative sent and received probes, reply TTL;
- **every configured interface:** link state, speed, duplex, link change count, default route, rx/tx bytes, packets and errors.

The server additionally sees the public source address and the hop count of every uplink.

## Repository layout
| Path | Contents |
|---|---|
| `common/` | wire format (`proto.c/h`), ChaCha20-Poly1305 (`chachapoly.c/h`), `version.h` |
| `client/` | `icmp-pulse`, the router agent |
| `server/` | `icmp-pulse-server`, the receiver |
| `tests/` | self tests: RFC 8439 vectors, reference frame bytes |
| `files/` | UCI config, procd init script, server keys file, systemd unit |
| `docs/` | protocol description |

## Building
```sh
make            # client and server
make client     # router client only
make server     # server only
make test       # self tests, must end with "RESULT: all tests passed"
```
The Makefile honours `CC`, `CFLAGS`, `LDFLAGS`, `DESTDIR` and `PREFIX` (default `/usr/local`), so the client can be cross-compiled, e.g. `make client CC=mips-openwrt-linux-musl-gcc`.

`make test` checks the encryption against the official RFC 8439 test vectors and compares frame bytes with reference values. Running it on the router (e.g. big-endian MIPS) confirms that the router and the server encode and decode packets identically.

## 1. Router

### Install
```sh
make client test
make install-client PREFIX=/usr   # /usr/sbin/icmp-pulse, /etc/init.d/icmp-pulse,
                                  # /etc/config/icmp-pulse (if not present)
```

### Key
Every router gets its own key:
```sh
icmp-pulse --genkey
```
It prints the key (64 hex characters), its `key_id`, and ready-to-paste lines for the router configuration and the server keys file.

### Configuration `/etc/config/icmp-pulse`
```
config icmp-pulse 'main'
	option server 'monitor.example.com'   # IPv4 address or name
	option interval '10'
	option key '...64 hex characters...'
	# option router_id 'shop-krakow'       # defaults to the hostname, max 16 characters

config interface
	option device 'pppoe-wan'             # PPPoE session: probe, RTT
	option probe '1'

config interface
	option device 'eth1'                  # physical port below PPPoE: link, speed, errors

config interface
	option device 'wwan0'                 # LTE backup
	option probe '1'
	option probe_interval '60'
```
- Interface names are Linux device names: `ls /sys/class/net`.
- `probe '1'`: a separate packet is sent through this uplink, so every uplink, backup included, is tested on its own.
- `probe_interval`: optional, defaults to `interval`; rounded up to a multiple of `interval`. Use it for a less frequent probe on a backup uplink.
- Without any `config interface` section only system data is reported and one packet per cycle follows normal routing (131 B).
- Without `option key` packets are sent unencrypted (testing only).

Check the configuration:
```sh
icmp-pulse --check
```

### Run
```sh
icmp-pulse -f -v                     # test run: every packet and reply on the terminal
/etc/init.d/icmp-pulse enable
/etc/init.d/icmp-pulse start
logread -e icmp-pulse
```
The configuration contains the key, keep it readable by root only (`chmod 600 /etc/config/icmp-pulse`).

### Failover
In every cycle `icmp-pulse` sends probes through the uplinks scheduled for that cycle. If none of them is healthy, the packet is immediately sent through another uplink (healthy ones first) and logged as `[failover]`.
An uplink is unhealthy when its interface is missing or administratively down, sending failed (e.g. `Network unreachable`) or replies to the last 2 probes in a row are missing. The first reply restores it.
As a result the server receives data every `interval` as long as any uplink works.

## 2. Server (Linux)

### Install as an unprivileged service (recommended)
`icmp-pulse-server` only needs one privilege: opening a raw ICMP socket to receive the routers' Echo Requests. On Linux this is the `CAP_NET_RAW` capability, which can be granted without full root. (Unprivileged "ping sockets" do not help here: they only receive replies to their own pings, not incoming requests.)

```sh
make server
sudo make install-server             # /usr/local/sbin/icmp-pulse-server,
                                     # /etc/systemd/system/icmp-pulse-server.service,
                                     # /etc/icmp-pulse/keys (if not present)
sudo useradd -r -s /usr/sbin/nologin -d /nonexistent icmp-pulse
sudo chown -R icmp-pulse:icmp-pulse /etc/icmp-pulse
sudo vi /etc/icmp-pulse/keys         # key and label of every router
sudo systemctl daemon-reload
sudo systemctl enable --now icmp-pulse-server
journalctl -u icmp-pulse-server -f
```
The unit runs as user `icmp-pulse` with `AmbientCapabilities=CAP_NET_RAW` and additional sandboxing (no disk writes, no access to home directories). Options and the time zone (`Environment=TZ=...`) can be changed with `systemctl edit icmp-pulse-server`.

Alternative without systemd: `sudo setcap cap_net_raw+ep /usr/local/sbin/icmp-pulse-server`. Note that the capability is lost whenever the file is overwritten (rebuild, `install`), does not work on `nosuid` mounts, and is granted to anyone who runs the file.

### Options
```
-k, --keys FILE     router keys (default /etc/icmp-pulse/keys)
-P, --allow-plain   also accept plaintext packets when keys are loaded
-q, --quiet         events and alarms only
-v, --verbose       details of rejected packets
-V, --version
```
Without a keys file only plaintext packets are accepted.

Requirements:
- the kernel answers pings: `sysctl net.ipv4.icmp_echo_ignore_all` = 0;
- the firewall (and cloud security group) allows incoming ICMP echo-request;
- log timestamps use the server's local time zone.

### Example output
```
** earth: new router (key earth, key_id 1751753a90fd8e00), uptime 465 s
   earth via pppoe-wan 84.40.153.202 hops 12/12 seq=1 up=86043s rtt 8.6 (8.3/8.6/9.0) ms probes 99/99 cpu 12%/si 3% load 0.42 ram 39% ct 523/16384 | pppoe-wan UNKNOWN *def rx 7.30 tx 0.40 Mb/s | eth1 UP 1000M rx 7.35 tx 0.41 Mb/s
** earth: pppoe-wan PPPoE session re-established, new address 84.40.153.202 -> 84.40.160.17
** earth: uplink pppoe-wan route change to server: 12 -> 15 hops
** earth: active default route via wwan0
** earth: UPLINK pppoe-wan DOWN (3 packets missing, 42 s)
** earth: ROUTER REBOOTED (uptime 42 s)
** earth: WARNING conntrack table 15000/16384 (91%)
** rejected packets (60 s): unknown key 0, bad tag 3, replayed 1, plaintext 0, malformed 0
```
`hops 12/12` = hops to / from the server. `probes 99/99` = received / sent (cumulative). `*def` = active default route. `cpu 12%/si 3%` = CPU usage / of which network processing. `UNKNOWN` on `pppoe-*` is normal: PPP does not report link state; the physical interface below it (e.g. `eth1`) shows the real link.

Full list of events: [docs/PROTOCOL.md](docs/PROTOCOL.md), section 11.

## 3. Scenarios to try on a router
| Action on the router | Event on the server |
|---|---|
| `ifdown wan` | `pppoe-wan UNKNOWN -> ABSENT`, default route via LTE, after ~42 s uplink `pppoe-wan` down; data keeps coming every 10 s via LTE |
| `ifconfig pppoe-wan down` | `pppoe-wan UNKNOWN -> ADMIN_DOWN`, then as above |
| unplug the WAN cable | `eth1 UP -> NO_CARRIER`, then `pppoe-wan UNKNOWN -> ABSENT` |
| `reboot` | ROUTER REBOOTED |
| `/etc/init.d/icmp-pulse restart` | icmp-pulse restarted |
| wrong key on the router | unknown key (in the 60 s summary) |

## Limitations
- IPv4 only.
- Server state (history, replay protection) lives in memory and is lost when the server restarts.
- The server prints to stdout/journal; storage and notifications are future work.
- The hop count assumes an initial TTL of 64/128/255; changes matter more than the absolute value.

## License
GPL-2.0-only, see [LICENSE](LICENSE).
