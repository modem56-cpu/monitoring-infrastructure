#!/usr/bin/env bash
set -euo pipefail

FILES=(
  /opt/monitoring/bin/update_all_dashboards.sh
  /opt/monitoring/bin/prom_tower_dashboard_html.base.sh
  /opt/monitoring/bin/prom_tower_dashboard_html.sh
  /opt/monitoring/bin/prom_tower_dashboard_html_ubuntu.sh
  /opt/monitoring/prom_tower_dashboard_html.sh
)

python3 - <<'PY'
from pathlib import Path
import time

files = [
  "/opt/monitoring/bin/update_all_dashboards.sh",
  "/opt/monitoring/bin/prom_tower_dashboard_html.base.sh",
  "/opt/monitoring/bin/prom_tower_dashboard_html.sh",
  "/opt/monitoring/bin/prom_tower_dashboard_html_ubuntu.sh",
  "/opt/monitoring/prom_tower_dashboard_html.sh",
]

ts = time.strftime("%Y-%m-%d_%H%M%S")

def patch_text(s: str):
    changed = 0

    # A) Fix the Python f-string SyntaxError caused by raw {__name__=~"..."} inside f-strings.
    # Replace the invalid selector block with a valid OR fallback that does not use __name__ regex.
    bad_cpu = '(sys_topproc_pcpu_percent{{instance="{instance}"}} or sys_topproc_cpu_percent{{instance="{instance}"}})'
    good_cpu = '(sys_topproc_pcpu_percent{{instance="{instance}"}} or sys_topproc_cpu_percent{{instance="{instance}"}})'
    if bad_cpu in s:
        s = s.replace(bad_cpu, good_cpu)
        changed += 1

    bad_mem = '(sys_topproc_pmem_percent{{instance="{instance}"}} or sys_topproc_mem_percent{{instance="{instance}"}})'
    good_mem = '(sys_topproc_pmem_percent{{instance="{instance}"}} or sys_topproc_mem_percent{{instance="{instance}"}})'
    if bad_mem in s:
        s = s.replace(bad_mem, good_mem)
        changed += 1

    # B) Fix Unraid metrics label mismatch:
    # The Unraid metrics are exposed with label target="192.168.10.10" (NO PORT).
    # If script uses target="{instance.split(':')[0]}" it becomes target="192.168.10.10:9100" and returns empty.
    if 'target="{instance.split(':')[0]}"' in s:
        s = s.replace('target="{instance.split(':')[0]}"', 'target="{instance.split(\':\')[0]}"')
        changed += 1

    # Also handle single-quoted variant if present
    if "target='{instance.split(':')[0]}'" in s:
        s = s.replace("target='{instance.split(':')[0]}'", "target='{instance.split(':')[0]}'")
        changed += 1

    return s, changed

total_files_changed = 0
for f in files:
    p = Path(f)
    if not p.exists():
        continue
    original = p.read_text()
    patched, changes = patch_text(original)
    if changes == 0:
        print(f"NO CHANGE: {f}")
        continue

    bak = Path(f"{f}.bak.{ts}")
    bak.write_text(original)
    p.write_text(patched)
    print(f"OK PATCHED: {f} (changes={changes})")
    print(f"  Backup: {bak}")
    total_files_changed += 1

if total_files_changed == 0:
    print("ERROR: No files matched patch patterns.")
    print("NEXT STEP: Show us what the scripts currently contain around the failing lines.")
PY
