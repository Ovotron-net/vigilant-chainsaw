#!/usr/bin/env bash
# Privileged apply workflow for ibn-monitor nftables artifacts.
# Sensor process never runs this; operators / automation do.
set -euo pipefail

CONFIG=${1:-/etc/ibn-monitor/policy.v2.json}
BACKUP_DIR=${IBN_NFT_BACKUP_DIR:-/var/lib/ibn-monitor/nft-backups}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"

CANDIDATE=$(mktemp)
BACKUP="$BACKUP_DIR/ibn_monitor.$STAMP.nft"
trap 'rm -f "$CANDIDATE"' EXIT

echo "==> Rendering candidate from $CONFIG"
ibn-monitor render-nftables --config "$CONFIG" --output "$CANDIDATE"

echo "==> Backing up current inet ibn_monitor table (if present) to $BACKUP"
if sudo nft list table inet ibn_monitor >/dev/null 2>&1; then
  {
    echo "#!/usr/sbin/nft -f"
    echo "flush table inet ibn_monitor"
    sudo nft list table inet ibn_monitor
  } >"$BACKUP"
else
  cat >"$BACKUP" <<'EOF'
#!/usr/sbin/nft -f
# previous state: table absent
delete table inet ibn_monitor
EOF
fi

echo "==> Checking candidate ruleset"
sudo nft --check --file "$CANDIDATE"

echo "==> Applying candidate atomically"
sudo nft --file "$CANDIDATE"

echo "==> Verifying installed table"
sudo nft list table inet ibn_monitor >/dev/null

# Confirm policy revision comment made it into the live listing when v2.
if grep -q 'policy_revision=' "$CANDIDATE"; then
  REV=$(grep -m1 'policy_revision=' "$CANDIDATE" | sed 's/.*policy_revision=//')
  if ! sudo nft list table inet ibn_monitor | grep -q .; then
    echo "Verification failed: table empty after apply" >&2
    echo "==> Rolling back from $BACKUP"
    sudo nft --file "$BACKUP" || true
    exit 1
  fi
  echo "Applied policy_revision=$REV (see comments in $CANDIDATE)"
fi

echo "OK: inet ibn_monitor updated. Backup: $BACKUP"
sudo nft list table inet ibn_monitor
