# icmp-pulse wire protocol (version 0)

> **Development version.** Until protocol version 1 the format may change without backward compatibility; the router and the server must run the same version.

This document describes the frame sent by `icmp-pulse` (router) to `icmp-pulse-server` in ICMP Echo Request packets.

## General rules
- Transport: ICMP Echo Request (type 8). The server kernel answers with an Echo Reply (type 0) carrying the same data; the router measures the RTT from it.
- All multi-byte fields are in network byte order (**big-endian**), regardless of the router CPU.
- The frame is built and parsed field by field (no copying of C structures), so it does not depend on memory alignment or the compiler.
- No floating point: fractional values are sent as integers × 100.
- "No data" = all bits set: `0xFFFF` (2-byte fields), `0xFFFFFFFF` (4-byte fields).
- Authenticated encryption: **ChaCha20-Poly1305 (RFC 8439)**, 32-byte key unique per router.

## Packet layout

```
| IP 20 B | ICMP 8 B | header 36 B                  | payload 79 B + n_if × 72 B | tag 16 B |
  plain     plain      plaintext, authenticated       ENCRYPTED, authenticated     Poly1305
```

Frame size (without IP and ICMP): `36 + 79 + n_if × 72 + 16`.

| Interfaces | Frame | IP packet |
|---|---|---|
| 0 | 131 B | 159 B |
| 1 | 203 B | 231 B |
| 2 | 275 B | 303 B |
| 3 | 347 B | 375 B |
| 12 (max) | 995 B | 1023 B |

In plaintext mode (no key) there is no tag (−16 B).

## 1. IP header (20 B), filled in by the kernel
| Offset | B | Field | Value |
|---|---|---|---|
| 0 | 1 | version, header length | `0x45` |
| 1 | 1 | TOS | 0 |
| 2 | 2 | total length | |
| 4 | 2 | identification | set by the kernel |
| 6 | 2 | flags, fragment offset | usually DF |
| 8 | 1 | TTL | 64 (`/proc/sys/net/ipv4/ip_default_ttl`) |
| 9 | 1 | protocol | 1 (ICMP) |
| 10 | 2 | header checksum | computed by the kernel |
| 12 | 4 | source address | address of the interface the packet left through |
| 16 | 4 | destination address | server |

The server reads the TTL and the source address: hop count `64 − TTL` and uplink address changes.

## 2. ICMP header (8 B), plaintext, not authenticated
| Offset | B | Field | Value |
|---|---|---|---|
| 0 | 1 | type | 8 Echo Request (reply: 0) |
| 1 | 1 | code | 0 |
| 2 | 2 | checksum | over the ICMP header and data |
| 4 | 2 | identifier | lower 16 bits of the `icmp-pulse` PID |
| 6 | 2 | sequence | lower 16 bits of `pkt_ctr` |

NAT may rewrite the identifier and the checksum, so these fields are not authenticated. Replies are matched using the icmp-pulse header, not the ICMP fields.

## 3. icmp-pulse header (36 B), plaintext, authenticated (AAD)
| Offset | B | Field | Description |
|---|---|---|---|
| 0 | 1 | `ver` | format version = 0 (development) |
| 1 | 1 | `flags` | bit0 = payload encrypted with ChaCha20-Poly1305; bits 1–7 reserved (0) |
| 2 | 2 | `len` | length from `ver` to the end of the tag |
| 4 | 8 | `key_id` | router key identifier; 0 in plaintext mode |
| 12 | 8 | `boot_id` | random on every program start; never `0xFF…FF` |
| 20 | 4 | `pkt_ctr` | packet counter since program start, unique for every packet |
| 24 | 4 | `seq` | cycle number; packets sent over different uplinks in the same cycle share `seq` |
| 28 | 8 | `mono_ns` | send time (router CLOCK_MONOTONIC, ns); the router computes the RTT from it |

**`key_id`** = the first 8 bytes of the ChaCha20 keystream for the router key, nonce `FF×12`, counter 0. The server computes `key_id` for every key in its list and selects the key by it. The key cannot be derived from `key_id`. The `FF×12` nonce is never used for data because `boot_id` is never `0xFF…FF`.

**Nonce** (12 B) = `boot_id` (8 B) ‖ `pkt_ctr` (4 B), exactly the header bytes. Within one run the nonce never repeats (`pkt_ctr` increases); across runs it is protected by the random 64-bit `boot_id`.

`seq` vs `pkt_ctr`: `seq` grows once per cycle (time axis, correlating data from different uplinks, gap detection); `pkt_ctr` grows with every packet (nonce, replay protection, reply matching).

## 4. Payload (79 B + n_if × 72 B), encrypted
| Offset | B | Field | Description | Source on the router |
|---|---|---|---|---|
| 0 | 16 | `name` | router name (ASCII, padded with 0x00) | `router_id` or hostname |
| 16 | 1 | `probe_idx` | index of the interface record the packet was sent through; `0xFF` = not bound (normal routing) | configuration |
| 17 | 2 | `probe_interval_s` | how often this uplink sends, in seconds | configuration |
| 19 | 1 | `reply_ttl` | TTL of the last server reply on this uplink; 0 = none | IP header of the Echo Reply |
| 20 | 8 | `uptime_cs` | time since boot, centiseconds | `/proc/uptime` |
| 28 | 4 | `kboot_id` | first 4 bytes of the kernel boot identifier; changes only on router reboot | `/proc/sys/kernel/random/boot_id` |
| 32 | 4 | `rtt_last_us` | RTT of the previous probe on this uplink, µs | Echo Reply |
| 36 | 4 | `rtt_min_us` | minimum over the last 10 probes of the uplink | |
| 40 | 4 | `rtt_avg_us` | average over the last 10 probes | |
| 44 | 4 | `rtt_max_us` | maximum over the last 10 probes | |
| 48 | 4 | `probe_sent` | cumulative: probes sent over this uplink (excluding the current one) | |
| 52 | 4 | `probe_recv` | cumulative: replies received | |
| 56 | 2 | `cpu_busy_x100` | CPU usage since the previous cycle, % × 100 (all cores) | `/proc/stat` |
| 58 | 2 | `cpu_softirq_x100` | part spent in softirq (network traffic processing) | `/proc/stat` |
| 60 | 2 | `load1_x100` | 1-minute load average × 100 | `/proc/loadavg` |
| 62 | 4 | `mem_total_kb` | MemTotal | `/proc/meminfo` |
| 66 | 4 | `mem_avail_kb` | MemAvailable | `/proc/meminfo` |
| 70 | 4 | `ct_count` | conntrack table entries | `/proc/sys/net/netfilter/nf_conntrack_count` |
| 74 | 4 | `ct_max` | conntrack table size | `/proc/sys/net/netfilter/nf_conntrack_max` |
| 78 | 1 | `n_if` | number of interface records (0–12) | configuration |
| 79 | n × 72 | records | in configuration order | |

## 5. Interface record (72 B), encrypted
| Offset | B | Field | Source |
|---|---|---|---|
| 0 | 16 | `name` | configuration (`option device`), max 15 characters |
| 16 | 1 | `state` | `/sys/class/net/<if>/` (bits below) |
| 17 | 1 | `rflags` | `/proc/net/route`, configuration (bits below) |
| 18 | 2 | `speed` | `speed`, Mb/s; `0xFFFF` = unknown |
| 20 | 4 | `carrier_changes` | `carrier_changes`, cumulative |
| 24 | 8 | `rx_bytes` | `/proc/net/dev` |
| 32 | 8 | `rx_packets` | `/proc/net/dev` |
| 40 | 8 | `rx_errs` | `/proc/net/dev` |
| 48 | 8 | `tx_bytes` | `/proc/net/dev` |
| 56 | 8 | `tx_packets` | `/proc/net/dev` |
| 64 | 8 | `tx_errs` | `/proc/net/dev` |

An interface missing from the system: `state = 0x01` (notpresent), counters 0, `speed = 0xFFFF`.

### `state` byte
| Bits | Meaning |
|---|---|
| 0–2 | `operstate`: 0 unknown, 1 notpresent, 2 down, 3 lowerlayerdown, 4 testing, 5 dormant, 6 up |
| 3 | interface administratively up (IFF_UP) |
| 4 | physical link present (carrier) |
| 5 | carrier unknown (read failed) |
| 6–7 | duplex: 0 unknown, 1 half, 2 full |

Example: `0x9E` = up, admin up, carrier, full duplex.

### `rflags` byte
| Bit | Meaning |
|---|---|
| 0 | has the active default route (lowest metric): Internet traffic goes this way |
| 1 | has any default route (e.g. LTE backup) |
| 2 | interface is probed (`probe '1'`) |
| 3–7 | reserved (0) |

## 6. Tag (16 B)
Poly1305 as specified in RFC 8439: AAD = icmp-pulse header (36 B), data = encrypted payload. Changing any byte of the header or payload causes the packet to be rejected. The router also verifies the tag in the Echo Reply, so forged replies cannot fake the RTT.

## 7. What an eavesdropper can see
- **Visible:** IP addresses, `key_id` (constant per router, but without its name), `pkt_ctr`/`seq` counters, `mono_ns` (≈ time since boot), sending rhythm, packet size (reveals the number of interfaces).
- **Hidden:** router name, uptime, latency, interface names and states, traffic counters, CPU, RAM, conntrack.

## 8. Replay protection (server)
- For every router the server keeps the current `boot_id`, the highest `pkt_ctr` and a window of the last 64 numbers; a packet with an already accepted number or one older than the window is rejected.
- Finished `boot_id` values (the last 64) are remembered; packets from them are rejected.
- A new `boot_id` with the same `kboot_id` is accepted only with `mono_ns` greater than the last one seen.
- Limitation: this state is kept in memory; after a server restart the first packet of every router is accepted without history.

## 9. Failover (router)
If no uplink scheduled in a cycle is healthy, the packet is sent over another uplink (`probe_idx` carries the uplink actually used). An uplink is unhealthy if its interface is missing or administratively down, sending failed, or replies to the last 2 probes in a row are missing. As a result the router sends data every `interval` as long as any uplink works, even when the backup uplink has a longer `probe_interval`.

## 10. Server-side calculations
| Quantity | Formula |
|---|---|
| throughput | `Δbytes × 8 / Δt` (Δt from `mono_ns`, once per `seq` cycle) |
| packets/s, average size | `Δpackets / Δt`, `Δbytes / Δpackets` |
| error ratio | `Δerrs / Δpackets` |
| probe loss over any window | `1 − Δprobe_recv / Δprobe_sent` (within one `boot_id`) |
| hops to the server | `64 − TTL` of the packet (128/255 for other systems) |
| hops from the server | `64 − reply_ttl` |
| RAM | `(mem_total − mem_avail) / mem_total` |
| conntrack | `ct_count / ct_max` |

A decreasing interface counter means a reset (no negative difference is computed). On `pppoe-*` it means the session was re-established.

## 11. Events reported by the server
| Event | Condition |
|---|---|
| new router | first packet with a given key (or name in plaintext mode) |
| UPLINK DOWN / UP again | no packets from the uplink for `3 × probe_interval + 12 s` / 2 consecutive packets |
| ROUTER DOWN / BACK | every uplink has timed out, each by its own `3 × probe_interval + 12 s` (with an LTE backup probed every 60 s a fully silent router is reported after ~3 min) / first packet |
| ROUTER REBOOTED | `kboot_id` changed |
| icmp-pulse restarted | `boot_id` changed with the same `kboot_id` |
| uplink address change | different source address of packets from this uplink |
| PPPoE session re-established | `pppoe-*` counters decreased (with or without a new address) |
| route change | different hop count in the same direction in 2 consecutive packets |
| interface state change | e.g. `UP -> NO_CARRIER`, `UP -> ABSENT` |
| FLAPPING | `carrier_changes` increased |
| active default route via X | bit 0 of `rflags` moved to another interface |
| counters reset | counters of a non-PPPoE interface decreased without a router reboot |
| RAM / conntrack usage | ≥ 90% (back < 85%) / ≥ 80% (back < 70%) |
| rejected packets | every 60 s: unknown key, bad tag, replayed, plaintext, malformed |
