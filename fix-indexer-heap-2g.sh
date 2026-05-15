#!/bin/bash
# fix-indexer-heap-2g.sh
# Bump wazuh-indexer heap from 1g to 2g.
#
# Problem: circuit_breaking_exception when wazuh-states-* indices start ingesting
# inventory data from all agents simultaneously. Real heap usage hit 976MB / 972MB limit.
# Server has 7.8GB RAM, 2.3GB available — 2g heap is safe.
#
# Previous: fix-indexer-heap-1g.sh (bumped 512m -> 1g, April 2026)

set -euo pipefail

JVM_OPTS="/etc/wazuh-indexer/jvm.options"

echo "[1/4] Current heap settings:"
grep -E "^-Xm[sx]" "$JVM_OPTS" || echo "  (none found)"

echo "[2/4] Updating to -Xms2g -Xmx2g..."
sed -i '/^-Xms/d' "$JVM_OPTS"
sed -i '/^-Xmx/d' "$JVM_OPTS"
echo "-Xms2g" >> "$JVM_OPTS"
echo "-Xmx2g" >> "$JVM_OPTS"

echo "  Verified:"
grep -E "^-Xm[sx]" "$JVM_OPTS"

echo "[3/4] Restarting wazuh-indexer..."
systemctl restart wazuh-indexer
sleep 15

STATUS=$(systemctl is-active wazuh-indexer)
if [ "$STATUS" != "active" ]; then
    echo "ERROR: wazuh-indexer is '$STATUS' after restart" >&2
    exit 1
fi
echo "  wazuh-indexer is active."

echo "[4/4] Verifying heap from process..."
sleep 5
NEW_HEAP=$(cat /proc/$(pgrep -f "org.opensearch.bootstrap.OpenSearch" | head -1)/cmdline 2>/dev/null | tr '\0' '\n' | grep -E "Xms|Xmx" | tr '\n' ' ')
echo "  Heap: $NEW_HEAP"

echo ""
echo "Done. Cluster health:"
curl -sk -u admin:NewStrongP4ss* "https://192.168.10.20:9200/_cluster/health?pretty" 2>/dev/null | grep -E "status|shards|nodes"
echo ""
echo "Wazuh-manager will resume indexing automatically — no restart needed."
