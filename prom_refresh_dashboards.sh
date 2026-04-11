#!/usr/bin/env bash
set -euo pipefail
export APPORT_DISABLE=1

TOPN="${TOPN:-100}"
REPORT_DIR="/opt/monitoring/reports"

# Default instances (override by exporting these vars if needed)
WAZUH_INST="${WAZUH_INST:-192.168.10.20:9100}"
DEVOPS_INST="${DEVOPS_INST:-192.168.5.131:9100}"
TOWER_INST="${TOWER_INST:-192.168.10.10:9100}"

san() { echo "$1" | tr '.:' '_' ; }

mkdir -p "$REPORT_DIR"

# VM dashboards
sudo /opt/monitoring/prom_vm_dashboard_html.sh "$WAZUH_INST"  "$TOPN"
sudo /opt/monitoring/prom_vm_dashboard_html.sh "$DEVOPS_INST" "$TOPN"

# Tower dashboard (try dedicated script; if it fails, fallback to VM-style dashboard)
if sudo /opt/monitoring/prom_tower_dashboard_html.sh "$TOWER_INST" "$TOPN"; then
  :
else
  echo "WARN: prom_tower_dashboard_html.sh failed; generating generic dashboard for tower." >&2
  sudo /opt/monitoring/prom_vm_dashboard_html.sh "$TOWER_INST" "$TOPN"
  # Copy/rename so your existing tower URL keeps working
  sudo cp -f \
    "$REPORT_DIR/vm_dashboard_$(san "$TOWER_INST").html" \
    "$REPORT_DIR/tower_$(san "$TOWER_INST").html"
fi

# Keep dot-filename URLs working (symlinks)
sudo ln -sf "$REPORT_DIR/vm_dashboard_$(san "$WAZUH_INST").html"  "$REPORT_DIR/vm_dashboard_192.168.10.20_9100.html"
sudo ln -sf "$REPORT_DIR/vm_dashboard_$(san "$DEVOPS_INST").html" "$REPORT_DIR/vm_dashboard_192.168.5.131_9100.html"
sudo ln -sf "$REPORT_DIR/tower_$(san "$TOWER_INST").html"         "$REPORT_DIR/tower_192.168.10.10_9100.html"

echo "OK: dashboards refreshed in $REPORT_DIR"
