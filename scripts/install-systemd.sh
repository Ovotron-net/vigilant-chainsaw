#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this script as root." >&2
  exit 1
fi

INSTALL_DIR=/opt/ibn-monitor
CONFIG_DIR=/etc/ibn-monitor
LOG_DIR=/var/log/ibn-monitor

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install "$(cd "$(dirname "$0")/.." && pwd)"
install -m 0640 "$(dirname "$0")/../config/policy.json" "$CONFIG_DIR/policy.json"
install -m 0644 "$(dirname "$0")/../deploy/systemd/ibn-monitor.service" /etc/systemd/system/
install -m 0644 "$(dirname "$0")/../deploy/logrotate/ibn-monitor" /etc/logrotate.d/ibn-monitor

systemctl daemon-reload
systemctl enable --now ibn-monitor
systemctl status ibn-monitor --no-pager
