#!/usr/bin/env bash
set -euo pipefail

# Create sys-sample-prom systemd service and timer
# Run as: sudo bash /opt/monitoring/setup-sys-sample-timer.sh

echo "Creating sys-sample-prom.service ..."
cat > /etc/systemd/system/sys-sample-prom.service <<'EOF'
[Unit]
Description=Generate sys_sample.prom for node_exporter textfile collector
After=network.target

[Service]
Type=oneshot
Environment=TEXTDIR=/opt/monitoring/textfile_collector
ExecStart=/opt/monitoring/bin/sys-sample-prom.sh
EOF

echo "Creating sys-sample-prom.timer ..."
cat > /etc/systemd/system/sys-sample-prom.timer <<'EOF'
[Unit]
Description=Run sys-sample-prom every 15 seconds

[Timer]
OnBootSec=10s
OnUnitActiveSec=15s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

echo "Reloading systemd ..."
systemctl daemon-reload

echo "Enabling and starting timer ..."
systemctl enable --now sys-sample-prom.timer

echo "Verifying ..."
systemctl status sys-sample-prom.timer --no-pager
echo ""
echo "Done. Timer is active."
