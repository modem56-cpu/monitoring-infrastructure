#!/usr/bin/env bash
# Deploy gworkspace-collector v3 (metric name fixes + freshness metrics)
# Must run as root (bin/ is root-owned)
set -euo pipefail

echo "=== Deploying gworkspace-collector v3 ==="
cp /opt/monitoring/gworkspace-collector-v3.py /opt/monitoring/bin/gworkspace-collector.py
chmod 755 /opt/monitoring/bin/gworkspace-collector.py
echo "  Collector deployed to bin/"

echo ""
echo "=== Running collector now ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Verifying new metrics ==="
grep -E "report_date_unixtime|report_lag_days|last_success_unixtime" \
    /opt/monitoring/textfile_collector/gworkspace.prom && echo "  Freshness metrics present" \
    || echo "  WARNING: freshness metrics not found in output"

echo ""
echo "=== Done ==="
