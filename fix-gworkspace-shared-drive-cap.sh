#!/usr/bin/env bash
# fix-gworkspace-shared-drive-cap.sh
# Removes the 50-page (50k file) cap on shared drive enumeration.
# Yokly USA and Agapay were being truncated, causing ~540 GB undercount vs Google Admin Console.
set -euo pipefail

TARGET="/opt/monitoring/bin/gworkspace-collector.py"

python3 - "$TARGET" << 'PY'
import sys, re

path = sys.argv[1]
with open(path) as f:
    content = f.read()

old = '''        size_bytes = 0
        file_count = 0
        pt2 = None
        pages = 0
        while pages < 50:  # cap at ~50k files per drive'''

new = '''        size_bytes = 0
        file_count = 0
        pt2 = None
        while True:  # no file count cap — large drives (e.g. Yokly USA >50k files) were being truncated'''

if old not in content:
    print("ERROR: pattern not found — already patched or file changed", file=sys.stderr)
    sys.exit(1)

# Also remove the now-unused `pages += 1` line
content = content.replace(old, new)
content = content.replace("            pages += 1\n", "")

with open(path, 'w') as f:
    f.write(content)

print(f"Patched {path}")
PY

echo "Restarting gworkspace-collector to pick up the fix..."
systemctl restart gworkspace-collector.service || true
echo "Done. Next 5-minute run will enumerate all files in Yokly USA and Agapay."
echo "Expected: shared drives total ~1.50 TB (was 0.96 TB due to truncation)."
