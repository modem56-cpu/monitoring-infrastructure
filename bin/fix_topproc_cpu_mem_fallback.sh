#!/usr/bin/env bash
set -euo pipefail

ts="$(date +%F_%H%M%S)"
files=(
  /opt/monitoring/bin/prom_tower_dashboard_html.base.sh
  /opt/monitoring/bin/prom_tower_dashboard_html.sh
  /opt/monitoring/bin/prom_tower_dashboard_html_ubuntu.sh
  /opt/monitoring/prom_tower_dashboard_html.sh
)

cpu_line='top_cpu = q_vec(f'\''topk(15, (sys_topproc_pcpu_percent{instance="{instance}"} or sys_topproc_cpu_percent{instance="{instance}"}))'\'')'
mem_line='top_mem = q_vec(f'\''topk(15, (sys_topproc_pmem_percent{instance="{instance}"} or sys_topproc_mem_percent{instance="{instance}"}))'\'')'

patched_any=0

for f in "${files[@]}"; do
  [[ -f "$f" ]] || continue

  sudo cp -a "$f" "$f.bak.${ts}"

  # Replace any existing top_cpu/top_mem q_vec line (keep indentation)
  sudo python3 - <<PY
import re
p="${f}"
s=open(p,"r",encoding="utf-8",errors="ignore").read()
orig=s

def repl_line(pattern, newline):
    def _r(m):
        return m.group(1) + newline
    return re.sub(pattern, _r, s, flags=re.M)

# patch top_cpu / top_mem regardless of previous contents
s2=re.sub(r'^(\s*)top_cpu\s*=\s*q_vec\(.*\)\s*$',
          r'\1${cpu_line}', s, flags=re.M)
s3=re.sub(r'^(\s*)top_mem\s*=\s*q_vec\(.*\)\s*$',
          r'\1${mem_line}', s2, flags=re.M)

open(p,"w",encoding="utf-8").write(s3)
print("patched" if s3!=orig else "nochange")
PY

  if grep -q "patched" <(sudo python3 -c 'print("patched")' 2>/dev/null); then :; fi

  # Detect whether file actually changed from backup
  if ! diff -q "$f" "$f.bak.${ts}" >/dev/null 2>&1; then
    echo "OK patched: $f (backup: $f.bak.${ts})"
    patched_any=1
  else
    echo "NO CHANGE: $f"
  fi
done

if [[ "$patched_any" -eq 0 ]]; then
  echo "ERROR: No files changed. Run: sudo grep -R \"top_cpu = q_vec\" -n /opt/monitoring | head"
  exit 2
fi

echo "OK: patch complete."
