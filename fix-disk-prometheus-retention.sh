#!/usr/bin/env bash
# Reduce Prometheus retention from 90d to 30d and reclaim disk space
set -euo pipefail

echo "=== Prometheus Retention Fix ==="
echo ""
echo "Before:"
df -h / | tail -1
echo "Prometheus data volume: $(docker exec prometheus du -sh /prometheus/ 2>/dev/null | cut -f1)"

echo ""
echo "=== Step 1: Restart Prometheus with 30-day retention ==="
cd /opt/monitoring
docker compose up -d prometheus
echo "  Prometheus restarted"

echo ""
echo "=== Step 2: Wait for Prometheus to come up ==="
for i in $(seq 1 15); do
  if curl -sf http://127.0.0.1:9090/-/healthy >/dev/null 2>&1; then
    echo "  Prometheus healthy after ${i}s"
    break
  fi
  sleep 1
done

echo ""
echo "=== Step 3: Trigger TSDB clean tombstones ==="
curl -s -X POST http://127.0.0.1:9090/api/v1/admin/tsdb/clean_tombstones && echo "  Clean tombstones triggered"

echo ""
echo "Note: Old data beyond 30d will be purged during the next compaction cycle."
echo "      Significant space recovery may take 1-2 hours as blocks expire."
echo ""
echo "After (current):"
df -h / | tail -1
echo "Prometheus data volume: $(docker exec prometheus du -sh /prometheus/ 2>/dev/null | cut -f1)"
