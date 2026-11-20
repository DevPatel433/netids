# netids

[![ci](https://github.com/DevPatel433/netids/actions/workflows/ci.yml/badge.svg)](https://github.com/DevPatel433/netids/actions/workflows/ci.yml)

A network intrusion detector for Linux. It watches TCP connection attempts on
a network interface, detects port scans, brute-force attempts, and SYN floods,
and can block offending IPs with nftables. It runs as a hardened systemd
service, emits SIEM-ready JSON alerts, and exposes Prometheus metrics.

## Features

| Area | What it does |
|---|---|
| Detection | Port scans (distinct ports per source), brute force (repeated hits on watched service ports), SYN floods (SYN volume vs. completed-handshake ratio per target) |
| Response | nftables blocklist with per-entry timeouts; blocks persist across restarts; flood alerts are never blocked because their sources are usually spoofed |
| Safety | Dry-run by default; CIDR allowlist that the blocker enforces independently of the detector; no shell is ever invoked; every IP is validated |
| Observability | Text logs, JSON Lines alerts for ELK/Wazuh/Splunk, Prometheus `/metrics` |
| Operations | systemd unit with minimal capabilities and hardening; `netids blocks` and `netids unblock <ip>` |
| Quality | 39 unit tests, CI on Python 3.11 and 3.12, two-VM Vagrant lab for end-to-end testing |

## Architecture

```
                 pure SYN / pure ACK
 NIC ──▶ capture.py ─────────────────▶ detector.py ──alerts──▶ blocker.py ──▶ nftables set
 (scapy)  sniff + BPF                  sliding windows          allowlist      (timed drop)
                                       • port scan                 │
                                       • brute force               ▼
                                       • SYN flood          alerts.py (JSON Lines)
                                                            metrics.py (/metrics)
 main.py: CLI (run | blocks | unblock), config loading, wiring
```

* **capture.py** sniffs with scapy and emits pure SYN events (connection
  attempts) and pure ACK events (handshake completions and data).
* **detector.py** is pure Python with no network dependency. It holds three
  sliding-window detectors, applies per-alert cooldowns, and skips allowlisted
  sources. This is the part the unit tests cover most heavily.
* **blocker.py** manages the nftables table, set, and rules. It reuses an
  existing table on restart, rebuilds a broken one, and refuses to block
  allowlisted addresses.
* **alerts.py** writes one JSON object per alert.
* **metrics.py** serves Prometheus counters from the standard library's HTTP server.
* **main.py** provides the CLI and wires the components together.

## Detection logic

**Port scan.** One source contacts at least `port_scan_unique_ports` distinct
destination ports within `window_seconds` (default 20 in 60 s).

**Brute force.** One source sends at least `brute_force_attempts` SYNs to the
same watched port within the window (default 10 in 60 s, for ports 21, 22,
23, 3306, and 3389).

**SYN flood.** For each destination `IP:port`, the detector counts SYNs and
pure ACKs in the window. It alerts when there are at least `flood_min_syns`
SYNs (default 200) and the ACK-to-SYN ratio is at or below
`flood_max_ack_ratio` (default 0.1). A healthy service completes most of its
handshakes, so its ratio stays high. Spoofed floods don't complete handshakes,
so their ratio drops toward zero. Because flood sources are usually spoofed,
these alerts are logged and counted but never blocked.

Every alert is rate-limited per kind and subject by `alert_cooldown_seconds`.

## Installation

Requires Ubuntu 22.04 or 24.04 with root access.

```bash
git clone https://github.com/DevPatel433/netids && cd netids
sudo ./scripts/install.sh
```

The script installs packages and creates a virtualenv at `/opt/netids/venv`.
It copies the config to `/etc/netids/config.toml`, registers the systemd unit,
and installs a `netids` launcher in `/usr/local/bin`.

Then:

```bash
ip -br addr                              # find your interface, e.g. eth0 or ens33
sudo nano /etc/netids/config.toml        # set [capture] interface, add your admin IP to whitelist
sudo systemctl enable --now netids
sudo journalctl -u netids -f             # watch alerts
```

## Operations

| Task | Command |
|---|---|
| Live logs | `sudo journalctl -u netids -f` |
| Alerts as JSON | `sudo tail -f /var/log/netids/alerts.json` |
| Current blocks | `sudo netids blocks` |
| Unblock an IP | `sudo netids unblock 203.0.113.7` |
| Metrics | `curl -s 127.0.0.1:9109/metrics` |
| Run in the foreground | `sudo netids run` |

Blocks expire automatically after `block_seconds`. They also persist across
service restarts, because the nftables table is reused when it's complete.

## Configuration

All settings are in `config.toml`:

| Section | Key | Meaning |
|---|---|---|
| `capture` | `interface` | Interface to sniff on |
| `detection` | `window_seconds` | Sliding window length |
| `detection` | `port_scan_unique_ports` | Distinct ports in the window that count as a scan |
| `detection` | `brute_force_attempts` | Hits on one watched port in the window that count as brute force |
| `detection` | `watched_ports` | Ports monitored for brute force |
| `detection` | `flood_min_syns`, `flood_max_ack_ratio` | SYN flood thresholds |
| `detection` | `alert_cooldown_seconds` | Minimum gap between repeat alerts for the same subject |
| `detection` | `whitelist` | IPs or CIDR ranges that are never flagged or blocked |
| `response` | `enabled` | `false` logs only (dry run); `true` blocks offenders |
| `response` | `block_seconds` | Block duration |
| `output` | `json_alerts` | JSON Lines alert file (empty string disables) |
| `metrics` | `listen` | Metrics address (empty string disables). Keep it on localhost. |

**Roll out in stages:** start with `enabled = false`, review the alerts for
false positives, tune thresholds, and only then set `enabled = true`.

## Example alert

`/var/log/netids/alerts.json`:

```json
{"action": "blocked", "detail": "20 distinct ports in 60s", "event": "alert", "kind": "port_scan", "sensor": "sensor", "src": "192.168.56.20", "timestamp": "2026-11-19T10:42:07.318204+00:00"}
```

Ship this file to a SIEM with Filebeat, Wazuh, or Splunk's universal
forwarder. Each line is a complete JSON object, so no custom parser is needed.

## Metrics

Prometheus scrapes `http://127.0.0.1:9109/metrics`:

```
netids_syn_packets_total 4182
netids_ack_packets_total 9051
netids_alerts_total{kind="brute_force"} 1
netids_alerts_total{kind="port_scan"} 3
netids_alerts_total{kind="syn_flood"} 0
netids_blocks_total 3
```

The endpoint binds to localhost by default. If you change it, put it behind
your firewall or a reverse proxy.

## Testing

Unit tests need neither root nor network access:

```bash
python3 -m unittest discover -s tests -t . -v
```

The 39 tests cover:

* **Detection:** port-scan thresholds, slow scans outside the window, watched-port brute force, unwatched ports ignored, SYN flood detected with spoofed sources, healthy busy services not flagged, flood volume floor, cooldown and re-alerting, idle-state pruning, config validation
* **Allowlist:** single IPs, IPv4 and IPv6 CIDR ranges, invalid entries rejected at startup
* **Blocker:** dry run makes no changes; setup creates a fresh table, reuses a complete one, and rebuilds a partial one; timeouts are set correctly; duplicate blocks are handled; allowlisted addresses are refused; invalid IPs never reach `nft`; unblock and list work
* **Outputs:** JSON alert records, Prometheus rendering, and a live HTTP request to `/metrics` plus a 404 for other paths

CI runs the same suite on every push.

### End-to-end lab

The Vagrant lab gives you a sensor VM and an attacker VM on a private network:

```bash
cd lab && vagrant up
vagrant ssh attacker -c "sudo /vagrant/scripts/simulate_attack.sh 192.168.56.10"
vagrant ssh sensor -c "sudo netids blocks; tail -n 5 /var/log/netids/alerts.json"
```

To demonstrate blocking, set `enabled = true` in the sensor's config and
restart the service. Then verify that the attacker's SSH and ping to the
sensor fail. Run `sudo netids unblock 192.168.56.20` on the sensor to restore access.

## Design decisions

* **Detection is separated from I/O.** The detector never touches the network,
  so its logic can be tested exhaustively and quickly.
* **The blocker enforces the allowlist itself**, not just the detector. A bug
  in detection can't lock out an admin.
* **Flood alerts are never blocked**, because blocking a spoofed source would
  hit an innocent host.
* **Commands use argument lists, not shell strings,** and IPs are validated
  before reaching `nft`, which closes off command injection.
* **Systemd grants only `CAP_NET_RAW` and `CAP_NET_ADMIN`,** plus filesystem
  and syscall hardening, instead of running with full root privileges.
* **The metrics server uses the standard library,** so there are no extra
  runtime dependencies beyond scapy.

## Limitations

* **Detection is based on TCP SYN and ACK packets only.** A slow scanner that
  stays under the thresholds, or an attacker who uses only allowed ports, can
  evade these rules. A production deployment would use Suricata or Zeek.
* **IPv4-only blocking.** Detection sees IPv4 TCP traffic only, since the
  capture filter and the nftables set are both IPv4.
* **Flood detection is a heuristic.** Data-carrying ACKs count toward the
  ratio, so it only catches floods that produce very few completed
  connections.
* **Performance is designed for lab and small-network scale.** Per-packet
  work is pure Python, which is not suitable for high-speed links.
* **In-memory state.** Detection windows reset on restart. Blocks persist,
  because they live in the kernel.

## Roadmap

* IPv6 blocking with a second nftables set
* Scale-out with a ring buffer or an eBPF/XDP fast path
* Grafana dashboard definitions for the metrics
* Wazuh decoder and rule files for the JSON alert format
