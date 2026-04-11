#!/usr/bin/env bash
set -euo pipefail

TS="$(date +%F_%H%M%S)"
ROOTS=(/opt/monitoring/bin /opt/monitoring)

python3 - <<'PY'
from pathlib import Path
import re, time

roots = [Path("/opt/monitoring/bin"), Path("/opt/monitoring")]
ts = time.strftime("%Y-%m-%d_%H%M%S")

# --- Patterns that are breaking your generator (f-string + raw {__name__=~...} selector) ---
# We patch ANY string chunk inside scripts that looks like:
#   {__name__=~"sys_topproc_.*cpu.*",{instance="{instance}"}}
# or minor variations in spacing/braces.
cpu_bad = re.compile(
    r"""\{\s*__name__\s*=\s*~\s*"sys_topproc_.*?cpu.*?"\s*,\s*\{?\s*instance\s*=\s*"\{instance\}"\s*\}?\s*\}""",
    re.IGNORECASE
)
mem_bad = re.compile(
    r"""\{\s*__name__\s*=\s*~\s*"sys_topproc_.*?mem.*?"\s*,\s*\{?\s*instance\s*=\s*"\{instance\}"\s*\}?\s*\}""",
    re.IGNORECASE
)

cpu_good = r'(sys_topproc_pcpu_percent{{instance="{instance}"}} or sys_topproc_cpu_percent{{instance="{instance}"}})'
mem_good = r'(sys_topproc_pmem_percent{{instance="{instance}"}} or sys_topproc_mem_percent{{instance="{instance}"}})'

# --- Unraid label mismatch fix ---
# Unraid metrics are labeled target="192.168.10.10" (NO PORT), but dashboards often pass instance="IP:9100".
# Convert any target="{instance}" or target="{{instance}}" to target="{instance.split(':')[0]}".
target_bad_1 = re.compile(r'target\s*=\s*"\{instance\}"')
target_bad_2 = re.compile(r"target\s*=\s*'\{instance\}'")

patched = []
scanned = 0

def patch_text(s: str):
    changed = 0

    # Fix the SyntaxError-causing selector chunk
    s2, n = cpu_bad.subn(cpu_good, s)
    if n: changed += n
    s = s2

    s2, n = mem_bad.subn(mem_good, s)
    if n: changed += n
    s = s2

    # Fix Unraid selector to strip port for target label
    s2, n = target_bad_1.subn('target="{instance.split(\':\')[0]}"', s)
    if n: changed += n
    s = s2

    s2, n = target_bad_2.subn("target='{instance.split(':')[0]}'", s)
    if n: changed += n
    s = s2

    return s, changed

def is_text_file(p: Path) -> bool:
    if not p.is_file():
        return False
    if p.suffix not in (".sh", ".py", ".tmpl", ".txt", ""):
        return False
    # avoid huge binaries
    try:
        data = p.read_bytes()
    except Exception:
        return False
    if b"\x00" in data[:2000]:
        return False
    return True

for root in roots:
    if not root.exists():
        continue
    for p in root.rglob("*"):
        if not is_text_file(p):
            continue
        scanned += 1
        try:
            s = p.read_text()
        except Exception:
            continue

        # Only touch files that have signs of these metrics (avoid random edits)
        if ("sys_topproc_" not in s) and ("tower_unraid_" not in s) and ("__name__=~" not in s):
            continue

        new_s, changes = patch_text(s)
        if changes == 0:
            continue

        bak = p.with_name(p.name + f".bak.{ts}")
        bak.write_text(s)
        p.write_text(new_s)
        patched.append((str(p), str(bak), changes))

print(f"SCANNED: {scanned} files")
if not patched:
    print("ERROR: No files matched patch patterns.")
    print("NEXT STEP: show the exact failing Python snippet from update_all_dashboards.sh via:")
    print("  sudo sed -n '130,190p' /opt/monitoring/bin/update_all_dashboards.sh")
else:
    print("PATCHED FILES:")
    for f,b,c in patched:
        print(f"  OK: {f} (changes={c})")
        print(f"      Backup: {b}")
PY
