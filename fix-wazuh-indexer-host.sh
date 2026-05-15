#!/bin/bash
# fix-wazuh-indexer-host.sh
# Fixes the wazuh-manager indexer connector host from 0.0.0.0 to 127.0.0.1
# so that wazuh-states-* indices (vulnerabilities, inventory) are created.
#
# Root cause: <indexer><host>https://0.0.0.0:9200</host> is a bind address,
# not a valid connection target. wazuh-states-* indices never get created.
# Fix: change to https://127.0.0.1:9200 and restart the manager.

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
BACKUP="${OSSEC_CONF}.bak.$(date +%Y%m%d-%H%M%S)"

echo "[1/5] Verifying ossec.conf is readable..."
if ! test -f "$OSSEC_CONF"; then
    echo "ERROR: $OSSEC_CONF not found" >&2
    exit 1
fi

echo "[2/5] Checking current indexer host..."
CURRENT=$(grep -o 'https://[^<]*:9200' "$OSSEC_CONF" | head -1 || true)
if [ -z "$CURRENT" ]; then
    echo "ERROR: Could not find indexer host in $OSSEC_CONF" >&2
    exit 1
fi
echo "  Current: $CURRENT"

if [ "$CURRENT" = "https://127.0.0.1:9200" ]; then
    echo "  Already set to 127.0.0.1 — nothing to do."
    exit 0
fi

if [ "$CURRENT" != "https://0.0.0.0:9200" ]; then
    echo "  WARNING: Unexpected host '$CURRENT' — expected https://0.0.0.0:9200"
    echo "  Proceeding anyway (will replace with https://127.0.0.1:9200)"
fi

echo "[3/5] Backing up config to $BACKUP..."
cp "$OSSEC_CONF" "$BACKUP"
echo "  Backup written."

echo "[4/5] Applying fix..."
sed -i 's|https://0\.0\.0\.0:9200|https://127.0.0.1:9200|g' "$OSSEC_CONF"

# Verify the change took effect
NEW=$(grep -o 'https://[^<]*:9200' "$OSSEC_CONF" | head -1 || true)
if [ "$NEW" != "https://127.0.0.1:9200" ]; then
    echo "ERROR: Fix did not apply — got '$NEW'. Restoring backup." >&2
    cp "$BACKUP" "$OSSEC_CONF"
    exit 1
fi
echo "  Updated to: $NEW"

echo "[5/5] Restarting wazuh-manager..."
systemctl restart wazuh-manager
sleep 5

STATUS=$(systemctl is-active wazuh-manager)
if [ "$STATUS" = "active" ]; then
    echo "  wazuh-manager is active."
else
    echo "ERROR: wazuh-manager status is '$STATUS' after restart." >&2
    echo "  Check: journalctl -u wazuh-manager -n 50" >&2
    exit 1
fi

echo ""
echo "Done. Next steps:"
echo "  - Wait ~1h for syscollector to push inventory (wazuh-states-inventory-* will appear)"
echo "  - Wait ~1h for vulnerability-detection to run (wazuh-states-vulnerabilities-* will appear)"
echo "  - Verify with:"
echo "    curl -sk -H 'Authorization: Basic <b64>' https://127.0.0.1:9200/wazuh-states-vulnerabilities-*/_count -d '{\"query\":{\"match_all\":{}}}'"
