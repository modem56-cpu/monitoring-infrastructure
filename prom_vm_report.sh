#!/usr/bin/env bash
set -euo pipefail

PROM="${PROM:-http://127.0.0.1:9090}"
IP="${1:?Usage: prom_vm_report.sh <ip> [port]}"
PORT="${2:-9100}"
NODE="${IP}:${PORT}"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Query helper (never hard-fail the whole script)
q() {
  local query="$1"
  curl -fsS "$PROM/api/v1/query" --data-urlencode "query=$query" 2>/dev/null || true
}

# Print first scalar value from Prometheus instant query JSON
first_value() {
  python3 -c "import sys,json
raw=sys.stdin.read().strip()
if not raw:
    print('N/A'); raise SystemExit(0)
try:
    d=json.loads(raw)
except Exception:
    print('N/A'); raise SystemExit(0)
r=d.get('data',{}).get('result',[])
print(r[0]['value'][1] if r else 'N/A')
"
}

echo "Prometheus: $PROM"
echo "Target IP: $IP"
echo "Timestamp: $(ts)"
echo

echo "=== Prometheus readiness ==="
if curl -fsS "$PROM/-/ready" >/dev/null 2>&1; then
  echo "Prometheus Server is Ready."
else
  echo "Prometheus NOT ready or not reachable at $PROM"
fi
echo

echo "=== Objects found for this IP (jobs/instances) ==="
q "count by (job, instance) ({instance=\"$IP\"} or {instance=\"$NODE\"})" \
| python3 -c "import sys,json
raw=sys.stdin.read().strip()
if not raw:
    print('(none)'); raise SystemExit(0)
d=json.loads(raw)
r=d.get('data',{}).get('result',[])
if not r:
    print('(none)')
else:
    for item in r:
        m=item.get('metric',{})
        v=item.get('value',['',''])[1]
        print('{}  {}  count={}'.format(m.get('job','?'), m.get('instance','?'), v))
"
echo

echo "=== up (node-exporter scrape) ==="
UP="$(q "up{instance=\"$NODE\"}" | first_value)"
echo "up = $UP"
echo

echo "=== probe_success (icmp via blackbox) ==="
PROBE="$(q "probe_success{job=\"bb_icmp\",instance=\"$IP\"}" | first_value)"
echo "probe_success = $PROBE"
echo

echo "=== node_* metric count (0 means exporter data not present) ==="
NODECNT="$(q "count({__name__=~\"node_.+\",instance=\"$NODE\"})" | first_value)"
echo "node_metrics_count = $NODECNT"
echo

echo "=== Target details (from /api/v1/targets) ==="
curl -fsS "$PROM/api/v1/targets" 2>/dev/null \
| NODE="$NODE" ICMP="$IP" python3 -c "import os,sys,json
NODE=os.environ.get('NODE','')
ICMP=os.environ.get('ICMP','')
raw=sys.stdin.read().strip()
if not raw:
    print('targets: (no data)'); raise SystemExit(0)
d=json.loads(raw)
targets=d.get('data',{}).get('activeTargets',[])

def pick(pred):
    for t in targets:
        try:
            if pred(t): return t
        except Exception:
            pass
    return None

node = pick(lambda t: t.get('labels',{}).get('instance','')==NODE)
icmp = pick(lambda t: t.get('labels',{}).get('job','')=='bb_icmp' and t.get('labels',{}).get('instance','')==ICMP)

def show(name,t):
    if not t:
        print(name + ': (not found)')
        return
    print(name + ':')
    print('  health: ' + str(t.get('health')))
    print('  lastScrape: ' + str(t.get('lastScrape')))
    print('  scrapeUrl: ' + str(t.get('scrapeUrl')))
    le=t.get('lastError','') or '(none)'
    print('  lastError: ' + le)

show('node-exporter', node)
show('bb_icmp', icmp)
"
