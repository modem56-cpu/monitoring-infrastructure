#!/usr/bin/env bash
set -euo pipefail

PROM="http://127.0.0.1:9090"

NODE="192.168.5.131:9100"
ICMP="192.168.5.131"

q() {
  local query="$1"
  curl -fsS "$PROM/api/v1/query" --data-urlencode "query=$query"
}

first_value() {
  # Reads JSON from stdin, prints first result value or N/A (never throws)
  python3 - <<'PY'
import sys, json
s=sys.stdin.read().strip()
if not s:
    print("N/A"); raise SystemExit(0)
try:
    d=json.loads(s)
    r=d.get("data",{}).get("result",[])
    print(r[0]["value"][1] if r else "N/A")
except Exception:
    print("N/A")
PY
}

echo "=== Prometheus readiness ($PROM) ==="
curl -fsS "$PROM/-/ready" && echo

echo "=== up (node-exporter) ==="
q "up{instance=\"$NODE\"}" | first_value | awk '{print "up =", $0}'

echo "=== probe_success (icmp) ==="
q "probe_success{job=\"bb_icmp\",instance=\"$ICMP\"}" | first_value | awk '{print "probe_success =", $0}'

echo "=== node_* metric count (0 means exporter data not present) ==="
q "count({__name__=~\"node_.+\",instance=\"$NODE\"}) or vector(0)" | first_value | awk '{print "node_metrics_count =", $0}'

echo "=== jobs/instances matching 192.168.5.131 ==="
q "count by (job,instance) ({instance=~\"192\\\\.168\\\\.5\\\\.131(:9100)?\"})" | python3 - <<'PY'
import sys, json
s=sys.stdin.read().strip()
d=json.loads(s) if s else {}
r=d.get("data",{}).get("result",[])
for item in r:
    m=item.get("metric",{})
    v=item.get("value",[None,"?"])[1]
    print(f'{m.get("job","?")}  {m.get("instance","?")}  count={v}')
PY
