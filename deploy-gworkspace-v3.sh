#!/usr/bin/env bash
set -euo pipefail

echo "=== Deploying gworkspace-collector-v2 ==="
cp /opt/monitoring/gworkspace-collector-v2.py /opt/monitoring/bin/gworkspace-collector.py
chmod +x /opt/monitoring/bin/gworkspace-collector.py
echo "  Collector deployed"

echo ""
echo "=== Running collector now ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Done ==="
