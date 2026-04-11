#!/usr/bin/env bash
set -euo pipefail

IP="${1:?usage: prom_topproc_report.sh <ip> [port]}"
PORT="${2:-9100}"
PROM="${PROM:-http://127.0.0.1:9090}"
INSTANCE="${IP}:${PORT}"

echo "Prometheus: $PROM"
echo "Target: $INSTANCE"
echo "Timestamp: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

CODE="$(curl -sSg -o "$TMP" -w '%{http_code}' \
  --data-urlencode "query={__name__=~\"sys_topproc_(pcpu_percent|pmem_percent|vsz_kb|rss_kb)\",instance=\"$INSTANCE\"}" \
  "$PROM/api/v1/query" || true)"

if [[ "$CODE" != "200" ]]; then
  echo "ERROR: Prometheus API returned HTTP $CODE"
  sed -n '1,120p' "$TMP" || true
  exit 1
fi

python3 -c '
import json, sys

d = json.load(open(sys.argv[1], "r", encoding="utf-8"))
res = d.get("data", {}).get("result", [])

rows = {}  # key=(rank,pid,user,comm,exe) -> dict(metric->value)
for item in res:
    m = item.get("metric", {})
    name = m.get("__name__", "")
    rank = int(m.get("rank", "9999"))
    pid  = m.get("pid", "?")
    user = m.get("user", "?")
    comm = m.get("comm", "?")
    exe  = m.get("exe", "")
    val  = float(item.get("value", [0, "0"])[1])
    key = (rank, pid, user, comm, exe)
    rows.setdefault(key, {})
    rows[key][name] = val

print("USER                 PID   %CPU   %MEM        VSZ(KB)     RSS(KB)  EXE_PATH")
printed = False
for (rank, pid, user, comm, exe) in sorted(rows.keys(), key=lambda k: k[0]):
    r = rows[(rank, pid, user, comm, exe)]
    pcpu = r.get("sys_topproc_pcpu_percent", 0.0)
    pmem = r.get("sys_topproc_pmem_percent", 0.0)
    vsz  = r.get("sys_topproc_vsz_kb", 0.0)
    rss  = r.get("sys_topproc_rss_kb", 0.0)

    exe_show = exe if exe else "(unknown)"
    if len(exe_show) > 90:
        exe_show = "…" + exe_show[-89:]

    print(f"{user:<20} {pid:>6}  {pcpu:>5.2f}  {pmem:>5.2f}  {vsz:>11.0f}  {rss:>11.0f}  {exe_show}")
    printed = True

if not printed:
    print("(no sys_topproc_* metrics found yet)")
' "$TMP"
