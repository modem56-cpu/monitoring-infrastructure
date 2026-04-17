#!/bin/bash
# Fix wazuh-indexer OOM: lower JVM heap and clean up heap dump
set -e

JVM_OPTS="/etc/wazuh-indexer/jvm.options"
HEAP_DUMP_GLOB="/var/lib/wazuh-indexer/java_pid*.hprof"

echo "=== Wazuh Indexer OOM Fix ==="

# 1. Remove heap dump(s) to free memory/disk
echo "[1] Cleaning up heap dumps..."
for f in $HEAP_DUMP_GLOB; do
    if [ -f "$f" ]; then
        SIZE=$(du -h "$f" | cut -f1)
        rm -f "$f"
        echo "    Removed $f ($SIZE)"
    fi
done

# 2. Show current heap settings
echo "[2] Current JVM heap settings:"
grep -E "^-Xm[sx]" "$JVM_OPTS" 2>/dev/null || echo "    (no explicit -Xms/-Xmx found, using defaults)"

# 3. Set heap to 512m (safe for this server's RAM pressure)
# OpenSearch needs -Xms == -Xmx to avoid heap resizing
echo "[3] Setting heap to 512m..."

# Remove existing Xms/Xmx lines
sed -i '/^-Xms/d' "$JVM_OPTS"
sed -i '/^-Xmx/d' "$JVM_OPTS"

# Add at top of file (after any comment lines)
# Insert after last comment block
echo "-Xms512m" >> "$JVM_OPTS"
echo "-Xmx512m" >> "$JVM_OPTS"

echo "    Done. New settings:"
grep -E "^-Xm[sx]" "$JVM_OPTS"

# 4. Also disable heap dump on OOM to prevent filling disk next time
echo "[4] Disabling heap dump on OOM..."
sed -i '/^-XX:+HeapDumpOnOutOfMemoryError/d' "$JVM_OPTS"
sed -i '/-XX:HeapDumpPath/d' "$JVM_OPTS"
echo "-XX:-HeapDumpOnOutOfMemoryError" >> "$JVM_OPTS"

# 5. Restart the indexer
echo "[5] Starting wazuh-indexer..."
systemctl start wazuh-indexer

# 6. Wait and check
echo "[6] Waiting 30s for indexer to come up..."
sleep 30
systemctl is-active wazuh-indexer && echo "    wazuh-indexer: RUNNING" || echo "    wazuh-indexer: FAILED"

# 7. Quick health check
echo "[7] Cluster health:"
curl -sk -u admin:'NewStrongP4ss*' "https://localhost:9200/_cluster/health?pretty" 2>/dev/null | grep -E '"status"|"cluster_name"' || echo "    (indexer not yet ready)"

echo ""
echo "Done. If cluster status is 'green' or 'yellow', restart the dashboard:"
echo "  sudo systemctl restart wazuh-dashboard"
