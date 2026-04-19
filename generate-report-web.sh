#!/usr/bin/env bash
set -euo pipefail
python3 /opt/monitoring/generate-report.py /opt/monitoring/reports/monitoring_report.json
python3 /opt/monitoring/generate-network-inventory.py
# Also create a timestamped copy
cp /opt/monitoring/reports/monitoring_report.json "/opt/monitoring/reports/monitoring_report_$(date +%Y%m%d_%H%M%S).json"
