#!/bin/bash
# Bump wazuh-indexer heap to 1GB (512m caused circuit breaker trip with 275 shards)
set -e

JVM_OPTS="/etc/wazuh-indexer/jvm.options"

echo "=== Updating wazuh-indexer heap to 1GB ==="

echo "[1] Current settings:"
grep -E "^-Xm[sx]" "$JVM_OPTS" || echo "  (none)"

echo "[2] Removing old Xms/Xmx..."
sed -i '/^-Xms/d' "$JVM_OPTS"
sed -i '/^-Xmx/d' "$JVM_OPTS"

echo "[3] Setting -Xms1g -Xmx1g..."
echo "-Xms1g" >> "$JVM_OPTS"
echo "-Xmx1g" >> "$JVM_OPTS"

echo "    Verified:"
grep -E "^-Xm[sx]" "$JVM_OPTS"

echo "[4] Restarting wazuh-indexer..."
systemctl restart wazuh-indexer

echo "[5] Waiting 45s for indexer to recover shards..."
sleep 45

systemctl is-active wazuh-indexer && echo "    Service: RUNNING" || { echo "    Service: FAILED"; journalctl -u wazuh-indexer -n 10 --no-pager; exit 1; }

echo "[6] Cluster health:"
curl -sk -u admin:'NewStrongP4ss*' "https://localhost:9200/_cluster/health?pretty" | grep -E '"status"|"unassigned_shards"|"active_primary_shards"'

echo ""
echo "If status is yellow or green, the dashboard should recover within 1-2 minutes."
echo "If status still red, run: sudo bash /opt/monitoring/fix-indexer-unassigned.sh"
