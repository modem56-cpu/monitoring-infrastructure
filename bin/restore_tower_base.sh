#!/usr/bin/env bash
set -euo pipefail
TS="$(date +%F_%H%M%S)"

SRC="/root/backup_dash_extras_2026-02-14_191835/opt_monitoring_bin/prom_tower_dashboard_html.sh"
DST_BASE="/opt/monitoring/bin/prom_tower_dashboard_html.base.sh"

if [[ ! -f "$SRC" ]]; then
  echo "ERROR: Missing backup source: $SRC"
  exit 1
fi

if [[ -f /opt/monitoring/bin/prom_tower_dashboard_html.sh ]]; then
  sudo cp -av /opt/monitoring/bin/prom_tower_dashboard_html.sh "/opt/monitoring/bin/prom_tower_dashboard_html.sh.before_wrapper.${TS}"
fi

sudo cp -av "$SRC" "$DST_BASE"
sudo chmod +x "$DST_BASE"

echo "OK: restored base generator to $DST_BASE"
