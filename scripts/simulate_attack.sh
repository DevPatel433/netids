#!/usr/bin/env bash
# Generates traffic that netids should detect. Run it from a SEPARATE machine
# (a second VM on the same network). Only use it against hosts you own.
#
#   sudo ./scripts/simulate_attack.sh <netids-host-ip>
set -euo pipefail

TARGET="${1:?usage: sudo $0 <netids-host-ip>}"

if ! command -v nmap >/dev/null; then
    echo "nmap not found; install it with: sudo apt-get install -y nmap" >&2
    exit 1
fi

echo "[*] Phase 1: SYN port scan of ports 1-1000 on $TARGET"
nmap -sS -p 1-1000 -T4 "$TARGET" || true

echo "[*] Phase 2: 15 rapid connection attempts to SSH (port 22)"
for _ in $(seq 1 15); do
    timeout 1 bash -c "exec 3<>/dev/tcp/$TARGET/22" 2>/dev/null || true
done

echo "[*] Done. Check alerts with: sudo journalctl -u netids -n 50"
