#!/usr/bin/env bash
set -euo pipefail
export APPORT_DISABLE=1

PROM="${PROM:-http://127.0.0.1:9090}"
HTML_DIR="${HTML_DIR:-/opt/monitoring/reports}"
HTML_BASEURL="${HTML_BASEURL:-http://127.0.0.1:8088}"

# Format: "instance|job_filter|html_file"
# job_filter can be blank
NODES=(
  "192.168.10.20:9100|node_wazuh_server|vm_dashboard_192_168_10_20_9100.html"
  "192.168.5.131:9100||vm_dashboard_192_168_5_131_9100.html"
  "192.168.10.10:9100|node_unraid_192_168_10_10|tower_192_168_10_10_9100.html"
)

python3 - <<'PY'
import os, re, sys, json, math
from urllib.parse import urlencode
from urllib.request import urlopen, Request

PROM=os.environ.get("PROM","http://127.0.0.1:9090").rstrip("/")
HTML_DIR=os.environ.get("HTML_DIR","/opt/monitoring/reports")
HTML_BASEURL=os.environ.get("HTML_BASEURL","http://127.0.0.1:8088").rstrip("/")

nodes=[]
for line in os.environ.get("NODES_RAW","").splitlines():
    if line.strip():
        nodes.append(line.strip())

# If env didn't pass nodes, parse from embedded bash NODES block by reading argv? Not possible here.
# So we read from a file the bash wrote into the script environment via sys.stdin? We'll just hardcode by parsing the script itself.
# Instead, bash will pass nodes through an env var below.
PY

export NODES_RAW="192.168.10.20:9100|node_wazuh_server|vm_dashboard_192_168_10_20_9100.html\n192.168.5.131:9100||vm_dashboard_192_168_5_131_9100.html\n192.168.10.10:9100|node_unraid_192_168_10_10|tower_192_168_10_10_9100.html"
