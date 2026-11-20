# Changelog

## 0.2.0
- **SYN flood detection** using the ACK-completion ratio per destination port, not just raw packet counts.
- **CIDR allowlists** (IPv4 and IPv6), validated at startup. The blocker refuses to block allowlisted addresses even if the detector were wrong.
- **Persistent blocks**: the nftables table is reused across restarts, so active blocks survive a service restart.
- **Block management CLI**: `netids blocks` and `netids unblock <ip>`.
- **JSON Lines alerts** for SIEM ingestion (ELK, Wazuh, Splunk).
- **Prometheus metrics** at `/metrics` (packet counters, alerts by kind, blocks).
- **CI** running the unit tests on Python 3.11 and 3.12.
- **Vagrant lab** with a sensor and an attacker VM.
- Fixed: a missing `nft` binary now produces a clear error, not a traceback.

## 0.1.0
- Port scan and brute-force detection over a sliding window.
- nftables blocking with timed sets.
- systemd service with minimal capabilities and hardening.
