#!/usr/bin/env bash
set -euo pipefail
# deploy-report-server.sh
# Updates topproc-html.service (the active port-8088 server) to use
# report-server.py instead of python3 -m http.server.
# Disables the duplicate monitoring-reports-web.service.
# Run as root: sudo bash /opt/monitoring/deploy-report-server.sh

# 1. Update topproc-html.service
sed -i \
  's|ExecStart=.*http.server.*|ExecStart=/usr/bin/python3 /opt/monitoring/report-server.py|' \
  /etc/systemd/system/topproc-html.service

# 2. Disable/stop the duplicate service that also targets port 8088
systemctl disable --now monitoring-reports-web.service 2>/dev/null || true

# 3. Reload and restart
systemctl daemon-reload
systemctl restart topproc-html.service
systemctl is-active topproc-html.service

echo "Done. Validating headers..."
sleep 1
echo "--- inline view ---"
curl -sI http://127.0.0.1:8088/monitoring_report.json | grep -E "^HTTP|Content-Type|Content-Disposition|Cache-Control"
echo "--- download ---"
curl -sI 'http://127.0.0.1:8088/monitoring_report.json?download=1' | grep -E "^HTTP|Content-Type|Content-Disposition|Cache-Control"
