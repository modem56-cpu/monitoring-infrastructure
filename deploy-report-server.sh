#!/usr/bin/env bash
set -euo pipefail
# deploy-report-server.sh
# Replaces python3 -m http.server with report-server.py (supports ?download=1)
# Run as root: sudo bash /opt/monitoring/deploy-report-server.sh

SERVICE=/etc/systemd/system/monitoring-reports-web.service

# Update service ExecStart
sed -i 's|ExecStart=.*http.server.*|ExecStart=/usr/bin/python3 /opt/monitoring/report-server.py|' "$SERVICE"

systemctl daemon-reload
systemctl restart monitoring-reports-web.service
systemctl is-active monitoring-reports-web.service

echo "Done. Testing headers..."
sleep 1
curl -sI http://127.0.0.1:8088/monitoring_report.json | grep -E "HTTP|Content-Type|Content-Disposition"
echo "---"
curl -sI 'http://127.0.0.1:8088/monitoring_report.json?download=1' | grep -E "HTTP|Content-Type|Content-Disposition"
