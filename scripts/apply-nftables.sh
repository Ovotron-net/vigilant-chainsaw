#!/usr/bin/env bash
set -euo pipefail

CONFIG=${1:-/etc/ibn-monitor/policy.json}
OUTPUT=$(mktemp)
trap 'rm -f "$OUTPUT"' EXIT

ibn-monitor render-nftables --config "$CONFIG" --output "$OUTPUT"
echo "Validating generated ruleset..."
sudo nft --check --file "$OUTPUT"
echo "Applying generated ruleset..."
sudo nft --file "$OUTPUT"
sudo nft list table inet ibn_monitor
