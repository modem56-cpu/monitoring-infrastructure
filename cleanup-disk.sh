#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  Disk Cleanup"
echo "============================================"
echo ""
echo "Before:"
df -h / | tail -1

echo ""
echo "=== Step 1: Remove old .bak files in reports (>7 days) ==="
count=$(find /opt/monitoring/reports -name "*.bak*" -mtime +7 2>/dev/null | wc -l)
find /opt/monitoring/reports -name "*.bak*" -mtime +7 -delete 2>/dev/null
echo "  Deleted $count .bak files"

echo ""
echo "=== Step 2: Remove .bak files in bin ==="
count=$(find /opt/monitoring/bin -name "*.bak*" 2>/dev/null | wc -l)
find /opt/monitoring/bin -name "*.bak*" -delete 2>/dev/null
echo "  Deleted $count .bak files"

echo ""
echo "=== Step 3: Remove old .bak files in /opt/monitoring root ==="
count=$(find /opt/monitoring -maxdepth 1 -name "*.bak*" 2>/dev/null | wc -l)
find /opt/monitoring -maxdepth 1 -name "*.bak*" -delete 2>/dev/null
echo "  Deleted $count .bak files"

echo ""
echo "=== Step 4: Remove .bad files ==="
count=$(find /opt/monitoring -name "*.bad.*" 2>/dev/null | wc -l)
find /opt/monitoring -name "*.bad.*" -delete 2>/dev/null
echo "  Deleted $count .bad files"

echo ""
echo "=== Step 5: Rotate syslogs ==="
if [ -f /var/log/syslog.1 ]; then
  truncate -s 0 /var/log/syslog.1
  echo "  Truncated syslog.1"
fi
# Remove old compressed logs
find /var/log -name "syslog.*.gz" -mtime +7 -delete 2>/dev/null
find /var/log -name "*.log.*.gz" -mtime +30 -delete 2>/dev/null
echo "  Cleaned old compressed logs"

echo ""
echo "=== Step 6: Clean journal ==="
journalctl --vacuum-size=200M 2>/dev/null
echo "  Journal vacuumed to 200M"

echo ""
echo "=== Step 7: Docker cleanup ==="
docker image prune -f 2>/dev/null | tail -1
echo "  Pruned unused images"

echo ""
echo "=== Step 8: Clean old monitoring report JSONs ==="
count=$(find /opt/monitoring/reports -name "monitoring_report_*.json" -mtime +1 2>/dev/null | wc -l)
find /opt/monitoring/reports -name "monitoring_report_*.json" -mtime +1 -delete 2>/dev/null
echo "  Deleted $count old report JSONs"

echo ""
echo "=== Step 9: Remove screenshots ==="
count=$(find /opt/monitoring -maxdepth 1 -name "*.png" 2>/dev/null | wc -l)
find /opt/monitoring -maxdepth 1 -name "*.png" -delete 2>/dev/null
echo "  Deleted $count screenshots"

echo ""
echo "After:"
df -h / | tail -1

echo ""
echo "=== Remaining .bak files ==="
find /opt/monitoring -name "*.bak*" 2>/dev/null | wc -l
