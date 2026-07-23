#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

INSTALL_DIR=/opt/ibn-monitor
CONFIG_DIR=/etc/ibn-monitor
LOG_DIR=/var/log/ibn-monitor
LIB_DIR=/var/lib/ibn-monitor
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

id -u ibn-monitor >/dev/null 2>&1 || useradd --system --no-create-home \
  --shell /usr/sbin/nologin ibn-monitor

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$LIB_DIR"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install "$ROOT"

install -m 0640 "$ROOT/config/policy.v2.example.json" "$CONFIG_DIR/policy.v2.json"
install -m 0644 "$ROOT/deploy/systemd/ibn-monitor.service" /etc/systemd/system/
install -m 0644 "$ROOT/deploy/systemd/ibn-monitor-nftables.service" /etc/systemd/system/
install -m 0644 "$ROOT/deploy/systemd/ibn-monitor-nftables.path" /etc/systemd/system/
install -m 0755 "$ROOT/scripts/apply-nftables.sh" /usr/local/sbin/ibn-apply-nftables
install -m 0644 "$ROOT/deploy/logrotate/ibn-monitor" /etc/logrotate.d/ibn-monitor

chown -R ibn-monitor:ibn-monitor "$LOG_DIR" "$LIB_DIR"
chown root:ibn-monitor "$CONFIG_DIR/policy.v2.json"
chmod 640 "$CONFIG_DIR/policy.v2.json"

# Allow CAP_NET_RAW without full root: file capabilities on the venv python.
setcap cap_net_raw+ep "$INSTALL_DIR/.venv/bin/python3" || \
  echo "warning: setcap failed; ensure AmbientCapabilities work for ibn-monitor" >&2

systemctl daemon-reload
systemctl enable --now ibn-monitor
systemctl status ibn-monitor --no-pager

echo
echo "Sensor is detection-only. To apply nftables from the same policy:"
echo "  sudo /usr/local/sbin/ibn-apply-nftables $CONFIG_DIR/policy.v2.json"
