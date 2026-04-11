#!/usr/bin/env bash
set -euo pipefail

CONF="/opt/monitoring/prometheus.yml"
JOB="windows_192_168_1_253"
TGT="192.168.1.253:9182"
ts="$(date +%F_%H%M%S)"

sudo cp -a "$CONF" "${CONF}.bak.${ts}"

python3 - <<PY
import re
from pathlib import Path

conf = Path("$CONF")
job  = "$JOB"
tgt  = "$TGT"

lines = conf.read_text(encoding="utf-8", errors="ignore").splitlines(True)

job_re = re.compile(r'^\s*-\s*job_name:\s*["\']?%s["\']?\s*$' % re.escape(job))
next_job_re = re.compile(r'^\s*-\s*job_name:\s*')

out = []
i = 0
removed = 0

while i < len(lines):
    if job_re.match(lines[i]):
        removed += 1
        i += 1
        # skip until next "- job_name:" at same indentation level (or EOF)
        while i < len(lines) and not next_job_re.match(lines[i]):
            i += 1
        continue
    out.append(lines[i])
    i += 1

text = "".join(out).rstrip() + "\n"

block = f"""
  - job_name: {job}
    static_configs:
      - targets: ['{tgt}']
        labels: {{ alias: 'win11-vm' }}
"""

# Ensure scrape_configs exists
if "scrape_configs:" not in text:
    raise SystemExit("ERROR: scrape_configs: not found in prometheus.yml")

# Append block once
text = text + "\n" + block.lstrip("\n")
conf.write_text(text, encoding="utf-8")

print(f"OK: removed {removed} old block(s), wrote 1 clean block.")
PY

# Validate inside container
docker exec prometheus sh -lc 'promtool check config /etc/prometheus/prometheus.yml'

# Reload
curl -sS -X POST http://127.0.0.1:9090/-/reload -o /dev/null -w 'Reload HTTP %{http_code}\n'

# Verify up
curl -sG 'http://127.0.0.1:9090/api/v1/query' \
  --data-urlencode 'query=up{instance="192.168.1.253:9182"}' ; echo
