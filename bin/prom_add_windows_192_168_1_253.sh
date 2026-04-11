#!/usr/bin/env bash
set -euo pipefail

CONF="/opt/monitoring/prometheus.yml"
TGT="192.168.1.253:9182"
JOB="windows_192_168_1_253"
ts="$(date +%F_%H%M%S)"

sudo cp -a "$CONF" "${CONF}.bak.${ts}"

python3 - <<PY
from pathlib import Path
import re

conf = Path("$CONF")
tgt  = "$TGT"
job  = "$JOB"

s = conf.read_text(encoding="utf-8", errors="ignore")

if tgt in s:
    print("OK: target already present, no change.")
    raise SystemExit(0)

# Append a new scrape job at the end (safe; does not touch existing jobs)
block = f"""
  - job_name: "{job}"
    static_configs:
      - targets: ["{tgt}"]
        labels: {{ alias: "win11-vm" }}
"""
conf.write_text(s.rstrip() + "\\n" + block.lstrip("\\n"), encoding="utf-8")
print("OK: appended Windows job.")
PY

# Validate config inside container
docker exec prometheus sh -lc 'promtool check config /etc/prometheus/prometheus.yml'

# Reload Prometheus
curl -sS -X POST http://127.0.0.1:9090/-/reload -o /dev/null -w 'Reload HTTP %{http_code}\n'

# Quick check
curl -sG 'http://127.0.0.1:9090/api/v1/query' \
  --data-urlencode "query=up{instance=\"$TGT\"}" ; echo
