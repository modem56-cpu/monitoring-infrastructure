#!/usr/bin/env bash
set -euo pipefail

PROM="${PROM:-http://127.0.0.1:9090}"
HTML="${HTML:-http://127.0.0.1:8088}"
JOB_FILTER="${JOB_FILTER:-}"   # optional: set to avoid duplicates, e.g. JOB_FILTER=node_wazuh_server

inst="${1:?usage: $0 <ip:port> [html_file]}"
html_file="${2:-}"
ip="${inst%%:*}"

sel="instance=\"$inst\""
if [[ -n "$JOB_FILTER" ]]; then
  sel="$sel,job=\"$JOB_FILTER\""
fi

q() { curl -sS -m 5 "$PROM/api/v1/query" --data-urlencode "query=$1"; }

echo "== NODE: $inst =="
echo -n "up:                " ; q "up{$sel}" ; echo
echo -n "sys_sample series:  " ; q "count({$sel,__name__=~\"sys_sample_.*\"})" ; echo
echo -n "sys_topproc series: " ; q "count(sys_topproc_rss_kb{$sel})" ; echo
echo -n "top rss (1):        " ; q "topk(1,sys_topproc_rss_kb{$sel})" ; echo

echo "-- direct exporter: http://$ip:9100/metrics (first 5 lines) --"
curl -sS -m 3 "http://$ip:9100/metrics" | sed -n '1,5p'

echo "-- sys_topproc sample (first 5 series) --"
curl -sS -m 3 "http://$ip:9100/metrics" | grep -E '^sys_topproc_' | head -n 5 || true

if [[ -n "$html_file" ]]; then
  echo -n "-- html served: $HTML/$html_file  => "
  curl -sS -I -o /dev/null -w "http=%{http_code}\n" "$HTML/$html_file?ts=$(date +%s)" || true
fi
