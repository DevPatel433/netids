#!/usr/bin/env bash
# Installs netids on an Ubuntu host. Run from the project root as root:
#   sudo ./scripts/install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo $0" >&2
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR=/opt/netids
CONFIG_DIR=/etc/netids
LOG_DIR=/var/log/netids

echo "[1/6] Installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nftables

echo "[2/6] Copying code to $INSTALL_DIR"
install -d "$INSTALL_DIR"
cp -r "$PROJECT_DIR/netids" "$PROJECT_DIR/requirements.txt" "$PROJECT_DIR/README.md" "$INSTALL_DIR/"

echo "[3/6] Creating virtualenv and installing Python dependencies"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

echo "[4/6] Installing config and log directory"
install -d "$CONFIG_DIR" "$LOG_DIR"
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    install -m 644 "$PROJECT_DIR/config.toml" "$CONFIG_DIR/config.toml"
    echo "      Created $CONFIG_DIR/config.toml (existing configs are left untouched)"
fi

echo "[5/6] Registering systemd service and CLI launcher"
install -m 644 "$PROJECT_DIR/systemd/netids.service" /etc/systemd/system/netids.service
systemctl daemon-reload
cat > /usr/local/bin/netids << 'LAUNCHER'
#!/usr/bin/env bash
exec /opt/netids/venv/bin/python -m netids -c /etc/netids/config.toml "$@"
LAUNCHER
chmod 755 /usr/local/bin/netids

echo "[6/6] Done"
cat << EOF

Next steps:
  1. Set the capture interface:   sudo nano $CONFIG_DIR/config.toml   (see: ip -br addr)
  2. Start in dry-run mode:       sudo systemctl enable --now netids
  3. Watch alerts:                sudo journalctl -u netids -f
  4. Check the metrics:           curl -s 127.0.0.1:9109/metrics
  5. Enable blocking when ready:  set enabled = true under [response], then
                                  sudo systemctl restart netids
  6. Manage blocks:               sudo netids blocks
                                  sudo netids unblock <ip>
EOF
