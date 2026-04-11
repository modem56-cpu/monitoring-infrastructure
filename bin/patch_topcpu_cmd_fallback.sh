#!/usr/bin/env bash
set -euo pipefail

TS="$(date +%F_%H%M%S)"
FILES=(
  /opt/monitoring/bin/prom_tower_dashboard_html.base.sh
  /opt/monitoring/bin/prom_tower_dashboard_html.sh
)

python3 - <<'PY'
from pathlib import Path
import re, time, sys

files = [
  "/opt/monitoring/bin/prom_tower_dashboard_html.base.sh",
  "/opt/monitoring/bin/prom_tower_dashboard_html.sh",
]

ts = time.strftime("%Y-%m-%d_%H%M%S")

# Replace ONLY the CPU-table "comm = m.get(...)" line.
pat = re.compile(r'^(?P<i>\s*)comm\s*=\s*m\.get\("comm",\s*""\s*\)\s*$', re.M)
rep = r'\g<i>comm = (m.get("cmd") or m.get("comm") or m.get("command") or m.get("name") or "")'

changed_any = False

for f in files:
    p = Path(f)
    if not p.exists():
        continue
    s = p.read_text(encoding="utf-8", errors="ignore")
    s2, n = pat.subn(rep, s)
    bak = Path(str(p) + f".bak.{ts}")
    bak.write_text(s, encoding="utf-8")
    p.write_text(s2, encoding="utf-8")
    print(f"OK patched: {p}  replaced={n}  backup={bak}")
    if n > 0:
        changed_any = True

if not changed_any:
    print("ERROR: Did not find the expected line: comm = m.get(\"comm\",\"\")")
    sys.exit(2)
PY
