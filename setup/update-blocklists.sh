#!/bin/bash

# Cybwatch Blocklist Updater
# Downloads threat intel blocklists from free sources

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BLOCKLIST_DIR="$SCRIPT_DIR/../data/blocklists"

mkdir -p "$BLOCKLIST_DIR"

echo "================================"
echo "  Cybwatch Blocklist Updater"
echo "================================"
echo ""
echo "Downloading to: $BLOCKLIST_DIR"
echo ""

# Spamhaus DROP (Don't Route Or Peer)
# Hijacked IP ranges used for spam/malware
echo "[1/3] Downloading Spamhaus DROP..."
curl -s "https://www.spamhaus.org/drop/drop.txt" -o "$BLOCKLIST_DIR/spamhaus-drop.txt"
echo "      Done: $(grep -v '^;' "$BLOCKLIST_DIR/spamhaus-drop.txt" | grep -c '/' || echo 0) networks"

# Spamhaus EDROP (Extended DROP)
echo "[2/3] Downloading Spamhaus EDROP..."
curl -s "https://www.spamhaus.org/drop/edrop.txt" -o "$BLOCKLIST_DIR/spamhaus-edrop.txt"
echo "      Done: $(grep -v '^;' "$BLOCKLIST_DIR/spamhaus-edrop.txt" | grep -c '/' || echo 0) networks"

# Emerging Threats - Compromised IPs
echo "[3/3] Downloading Emerging Threats..."
curl -s "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" -o "$BLOCKLIST_DIR/emerging-threats.txt"
echo "      Done: $(grep -v '^#' "$BLOCKLIST_DIR/emerging-threats.txt" | grep -c '\.' || echo 0) IPs"

echo ""
echo "================================"
echo "  Update Complete!"
echo "================================"
echo ""
echo "Files saved to: $BLOCKLIST_DIR"
ls -la "$BLOCKLIST_DIR"
echo ""
echo "Run this weekly to keep blocklists fresh:"
echo "  ./setup/update-blocklists.sh"
echo ""
