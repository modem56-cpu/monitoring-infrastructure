#!/usr/bin/env bash
set -euo pipefail

TEXTDIR="${TEXTDIR:-/opt/monitoring/textfile_collector}"
TOPN="${1:-100}"

[[ "$TOPN" =~ ^[0-9]+$ ]] || { echo "ERROR: topN must be integer"; exit 2; }
sudo install -d -m 0755 "$TEXTDIR"

TMP="$(mktemp)"
OUT="$TEXTDIR/sys_topproc.prom"
trap 'rm -f "$TMP"' EXIT

# Header
{
  echo "# HELP sys_topproc_rss_kb Resident set size (KB) of top processes"
  echo "# TYPE sys_topproc_rss_kb gauge"
  echo "# HELP sys_topproc_vsz_kb Virtual memory size (KB) of top processes"
  echo "# TYPE sys_topproc_vsz_kb gauge"
  echo "# HELP sys_topproc_pcpu_percent CPU percent of top processes"
  echo "# TYPE sys_topproc_pcpu_percent gauge"
  echo "# HELP sys_topproc_pmem_percent MEM percent of top processes"
  echo "# TYPE sys_topproc_pmem_percent gauge"
} > "$TMP"

# Get TOPN by RSS from ps
# fields: pid user pcpu pmem rss vsz comm
mapfile -t LINES < <(ps -eo pid=,user=,pcpu=,pmem=,rss=,vsz=,comm= --sort=-rss | head -n "$TOPN")

rank=0
for line in "${LINES[@]}"; do
  # shellcheck disable=SC2086
  set -- $line
  pid="$1"; user="$2"; pcpu="$3"; pmem="$4"; rss="$5"; vsz="$6"; comm="$7"
  [[ -n "$pid" ]] || continue
  ((rank++)) || true

  exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  # escape label values safely using python
  esc() { python3 - <<PY "$1"
import sys
s=sys.argv[1]
s=s.replace("\\\\","\\\\\\\\").replace('"','\\\\\"').replace("\n"," ").replace("\r"," ")
print(s)
PY
  }

  u="$(esc "$user")"
  c="$(esc "$comm")"
  e="$(esc "$exe")"

  echo "sys_topproc_rss_kb{rank=\"$rank\",user=\"$u\",pid=\"$pid\",comm=\"$c\",exe=\"$e\"} $rss" >> "$TMP"
  echo "sys_topproc_vsz_kb{rank=\"$rank\",user=\"$u\",pid=\"$pid\",comm=\"$c\",exe=\"$e\"} $vsz" >> "$TMP"
  echo "sys_topproc_pcpu_percent{rank=\"$rank\",user=\"$u\",pid=\"$pid\",comm=\"$c\",exe=\"$e\"} $pcpu" >> "$TMP"
  echo "sys_topproc_pmem_percent{rank=\"$rank\",user=\"$u\",pid=\"$pid\",comm=\"$c\",exe=\"$e\"} $pmem" >> "$TMP"
done

sudo install -m 0644 "$TMP" "$OUT"
echo "Wrote: $OUT"
