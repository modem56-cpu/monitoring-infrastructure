#!/usr/bin/env bash
set -euo pipefail

ts="$(date +%F_%H%M%S)"

mapfile -t files < <(
  sudo grep -RIl --exclude='*.bak*' --exclude='*.bak.*' --exclude-dir='.git' \
    -E '^\s*top_(cpu|mem)\s*=\s*q_vec\(' /opt/monitoring 2>/dev/null || true
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "ERROR: No files found containing top_cpu/top_mem q_vec lines under /opt/monitoring"
  exit 2
fi

echo "Found ${#files[@]} file(s) to patch:"
printf ' - %s\n' "${files[@]}"

for f in "${files[@]}"; do
  sudo cp -a "$f" "$f.bak.${ts}"

  sudo python3 - "$f" <<'PY'
import re, sys, pathlib

p = pathlib.Path(sys.argv[1])
txt = p.read_text(encoding="utf-8", errors="ignore").splitlines(True)

cpu_line = "top_cpu = q_vec(f'topk(15, (sys_topproc_pcpu_percent{{instance=\"{instance}\"}} or sys_topproc_cpu_percent{{instance=\"{instance}\"}}))')\n"
mem_line = "top_mem = q_vec(f'topk(15, (sys_topproc_pmem_percent{{instance=\"{instance}\"}} or sys_topproc_mem_percent{{instance=\"{instance}\"}}))')\n"

out = []
changed = False

for line in txt:
    m = re.match(r'^(\s*)top_cpu\s*=\s*q_vec\(.*\)\s*$', line)
    if m:
        out.append(m.group(1) + cpu_line)
        changed = True
        continue

    m = re.match(r'^(\s*)top_mem\s*=\s*q_vec\(.*\)\s*$', line)
    if m:
        out.append(m.group(1) + mem_line)
        changed = True
        continue

    out.append(line)

if changed:
    p.write_text("".join(out), encoding="utf-8")
    print(f"OK patched: {p}")
else:
    print(f"NO CHANGE: {p}")
PY
done

echo "OK: patch complete."
