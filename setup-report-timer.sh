#!/usr/bin/env bash
set -euo pipefail

cat > /etc/systemd/system/monitoring-report.service << 'SVC'
[Unit]
Description=Generate monitoring JSON report
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/monitoring/generate-report.py /opt/monitoring/reports/monitoring_report.json
SVC

cat > /etc/systemd/system/monitoring-report.timer << 'TMR'
[Unit]
Description=Generate monitoring report every 5 minutes

[Timer]
OnBootSec=60s
OnUnitActiveSec=5min
AccuracySec=10s

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now monitoring-report.timer
echo "Timer enabled — report regenerates every 5 minutes"
