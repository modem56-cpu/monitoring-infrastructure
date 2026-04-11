#!/usr/bin/env bash
set -euo pipefail

PROM="${PROM:-http://127.0.0.1:9090}"
HTML_BASE="${HTML_BASE:-http://127.0.0.1:8088}"
REPORT_DIR="${REPORT_DIR:-/opt/monitoring/reports}"

nodes=(
  "192.168.10.20:9100|wazuh-server|vm_dashboard_192_168_10_20_9100.html|http://127.0.0.1:9100/metrics"
  "192.168.5.131:9100|vm-devops|vm_dashboard_192_168_5_131_9100.html|http://192.168.5.131:9100/metrics"
  "192.168.10.10:9100|unraid-tower|tower_192_168_10_10_9100.html|http://192.168.10.10:9100/metrics"
)

q_json () {
  local query="$1"
  curl -sS -m 8 "$PROM/api/v1/query" --data-urlencode "query=$query"
}

pick_val () {
  python3 - <<'PY'
import sys, json
j=json.load(sys.stdin)
res=j.get("data",{}).get("result",[])
if not res:
    print("N/A"); sys.exit(0)
v=res[0].get("value",[None,"N/A"])[1]
print(v)
PY
}

echo "== Prometheus ready =="
curl -fsS -m 3 "$PROM/-/ready" >/dev/null && echo "PROM=OK" || echo "PROM=NOT READY"
echo

for row in "${nodes[@]}"; do
  IFS='|' read -r inst name html metrics_url <<<"$row"
  host="${inst%:*}"

  echo "=============================="
  echo "Node: $name ($inst)"

  # Prometheus up?
  up="$(q_json "up{instance=\"$inst\"}" | pick_val)"
  echo "Prometheus up{instance=\"$inst\"} = $up"

  # sys_topproc count
  cnt="$(q_json "count(sys_topproc_rss_kb{instance=\"$inst\"})" | pick_val)"
  echo "sys_topproc_rss_kb count = $cnt"

  # direct scrape (best-effort)
  tmp="/tmp/metrics_${host//./_}.txt"
  if curl -sS -m 3 -o "$tmp" "$metrics_url" ; then
    echo "Exporter scrape OK: $metrics_url"
    echo -n "sys_topproc lines (sample): "
    grep -E '^sys_topproc_' "$tmp" | head -n 1 >/dev/null && echo "YES" || echo "NO"
  else
    echo "Exporter scrape FAILED: $metrics_url"
  fi

  # html file + served?
  if [[ -f "$REPORT_DIR/$html" ]]; then
    echo "HTML file exists: $REPORT_DIR/$html"
    stat -c "mtime=%y size=%s" "$REPORT_DIR/$html" 2>/dev/null || true
  else
    echo "HTML file MISSING: $REPORT_DIR/$html"
  fi

  code="$(curl -sS -I -o /dev/null -m 3 -w "%{http_code}" "$HTML_BASE/$html" || true)"
  echo "HTML served: $HTML_BASE/$html -> http=$code"
done

echo "=============================="
echo "Local services (quick view):"
sudo systemctl is-active topproc-html.service 2>/dev/null && echo "topproc-html.service=active" || echo "topproc-html.service=NOT active"
sudo systemctl is-active sys-topproc.timer    2>/dev/null && echo "sys-topproc.timer=active"    || echo "sys-topproc.timer=NOT active"
sudo systemctl is-active sys-sample.timer     2>/dev/null && echo "sys-sample.timer=active"     || echo "sys-sample.timer=NOT active"
