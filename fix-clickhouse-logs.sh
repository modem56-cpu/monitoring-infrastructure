#!/usr/bin/env bash
# Truncate bloated ClickHouse system log tables and disable trace/processor logging
set -euo pipefail

echo "=== ClickHouse System Log Cleanup ==="
echo ""
echo "Before:"
df -h / | tail -1

echo ""
echo "=== Step 1: Truncate bloated system log tables ==="
cd /opt/akvorado/docker

TABLES=(
  trace_log
  text_log
  part_log
  processors_profile_log
  metric_log
  query_views_log
  asynchronous_metric_log
  query_log
  query_thread_log
  query_metric_log
)

for table in "${TABLES[@]}"; do
  size=$(docker compose exec -T clickhouse clickhouse-client \
    --query "SELECT formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE active AND table='${table}'" 2>/dev/null || echo "N/A")
  docker compose exec -T clickhouse clickhouse-client \
    --query "TRUNCATE TABLE IF EXISTS system.${table}" 2>/dev/null && echo "  Truncated system.${table} (was ${size})" \
    || echo "  Skipped system.${table} (not found)"
done

echo ""
echo "=== Step 2: Free space from deleted parts ==="
docker compose exec -T clickhouse clickhouse-client \
  --query "SYSTEM DROP MARK CACHE" 2>/dev/null && echo "  Mark cache dropped"

echo ""
echo "After truncation:"
df -h / | tail -1

echo ""
echo "=== Step 3: Restart ClickHouse to apply new config ==="
docker compose restart clickhouse
sleep 5
echo "  ClickHouse restarted"

echo ""
echo "=== Final disk status ==="
df -h / | tail -1
echo ""
echo "ClickHouse volume:"
docker compose exec -T clickhouse clickhouse-client \
  --query "SELECT table, formatReadableSize(sum(bytes_on_disk)) as size FROM system.parts WHERE active GROUP BY table ORDER BY sum(bytes_on_disk) DESC" 2>/dev/null
