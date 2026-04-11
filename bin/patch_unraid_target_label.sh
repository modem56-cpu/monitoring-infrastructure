#!/usr/bin/env bash
set -euo pipefail

FILE="/opt/monitoring/bin/prom_tower_dashboard_html.base.sh"

python3 - <<'PY'
from pathlib import Path
import re, time, sys

p = Path("/opt/monitoring/bin/prom_tower_dashboard_html.base.sh")
s = p.read_text()

bak = Path(str(p) + f".bak.{time.strftime('%Y-%m-%d_%H%M%S')}")
bak.write_text(s)

# Only touch Unraid metric selectors.
# Convert: tower_unraid_*{{instance="{instance}"}}  -> tower_unraid_*{{target="{instance.split(':')[0]}"}}.
pat = r'(tower_unraid_[A-Za-z0-9_]+)\{\{instance="\{instance\}"\}\}'
rep = r'\1{{target="{instance.split(\':\')[0]}"}}'
s2, n = re.subn(pat, rep, s)

# Some scripts may use single braces (rare) - handle as well.
pat2 = r'(tower_unraid_[A-Za-z0-9_]+)\{instance="\{instance\}"\}'
rep2 = r'\1{target="{instance.split(\':\')[0]}"}'
s2, n2 = re.subn(pat2, rep2, s2)

total = n + n2
if total == 0:
    print("ERROR: No tower_unraid instance selectors found to replace.")
    print("Tip: run: sudo grep -nE 'tower_unraid_.*instance=\"\\{instance\\}\"' -n", p)
    sys.exit(2)

p.write_text(s2)
print(f"OK: updated {total} Unraid selectors to use target=…")
print(f"Backup: {bak}")
PY
