#!/usr/bin/env bash
set -euo pipefail

TS="$(date +%F_%H%M%S)"

targets=(
  /opt/monitoring/bin/prom_tower_dashboard_html.base.sh
  /opt/monitoring/bin/prom_tower_dashboard_html.sh
)

python3 - <<'PY'
from pathlib import Path
import re, time

ts = time.strftime("%Y-%m-%d_%H%M%S")
files = [
  "/opt/monitoring/bin/prom_tower_dashboard_html.base.sh",
  "/opt/monitoring/bin/prom_tower_dashboard_html.sh",
]

fallback_line = r'cmd = (m.get("cmd") or m.get("command") or m.get("comm") or m.get("name") or "")'

patched_any = False

for f in files:
    p = Path(f)
    if not p.exists():
        continue

    s = p.read_text(encoding="utf-8", errors="ignore")

    # Backup
    bak = p.with_name(p.name + f".bak.{ts}")
    bak.write_text(s, encoding="utf-8")

    # Replace any "cmd = m.get(...)" style lines with the fallback line (keep indentation)
    s2, n = re.subn(
        r'^(?P<i>\s*)cmd\s*=\s*m\.get\([^\n]*\)\s*$',
        lambda m: m.group("i") + fallback_line,
        s,
        flags=re.M
    )

    # Also cover cases like: cmd=m.get(...)
    s2, n2 = re.subn(
        r'^(?P<i>\s*)cmd\s*=\s*\(?m\.get\([^\n]*\)\)?\s*$',
        lambda m: m.group("i") + fallback_line,
        s2,
        flags=re.M
    )

    # If the file had no cmd= lines, keep as-is (backup still created)
    p.write_text(s2, encoding="utf-8")
    print(f"OK patched: {p} (replaced cmd lines: {n+n2})  backup: {bak}")
    patched_any = patched_any or (n+n2) > 0

if not patched_any:
    print("NOTE: No cmd=m.get(...) lines matched; generator may use a different variable name.")
PY
