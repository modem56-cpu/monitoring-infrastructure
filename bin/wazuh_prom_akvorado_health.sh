#!/usr/bin/env bash
set -u

check_url() {
  local name="$1"
  local url="$2"
  if curl -fsS --max-time 8 "$url" >/dev/null; then
    echo "$name status=ok url=$url"
  else
    echo "$name status=fail url=$url"
  fi
}

check_unit() {
  local unit="$1"
  local state
  state="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
  echo "unit=$unit state=$state"
}

check_proc() {
  local name="$1"
  local pattern="$2"
  if pgrep -fa "$pattern" >/dev/null; then
    echo "$name proc=up"
  else
    echo "$name proc=down"
  fi
}

echo "component=prom_akvorado_health ts=$(date -Is)"

check_proc prometheus '/bin/prometheus --config.file='
check_proc akvorado_orchestrator '/usr/local/bin/akvorado orchestrator'
check_proc reports_web 'python3 -m http.server 8088'

check_unit monitoring-reports-web.service
check_unit prom-html-dashboards.timer
check_unit vm-dashboard-refresh.timer
check_unit tower-10-24-dashboard.timer

check_url prometheus_url 'http://127.0.0.1:9090/-/healthy'
check_url reports_url 'http://127.0.0.1:8088/'
check_url akvorado_url 'http://127.0.0.1:8082/'

if ss -lun | grep -qE '[:.]4739[[:space:]]'; then
  echo 'ipfix_4739 state=listening'
else
  echo 'ipfix_4739 state=not_listening'
fi
