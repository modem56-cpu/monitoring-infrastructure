#!/usr/bin/env bash
# fix-container-down-alert.sh
# Fixes false-positive ContainerDown alerts caused by stale container_last_seen
# series from previous restartcount label values. When a container restarts,
# cAdvisor creates a new series (new restartcount label) while the old series
# lingers >120s, triggering the alert even though the container is healthy.
#
# Fix: aggregate by (name, instance, job, alias) using max() so the alert
# evaluates the freshest timestamp across all label-set variants per container.
#
# Run as root.
set -euo pipefail

RULES_FILE="/opt/monitoring/rules/containers.rules.yml"

python3 - << 'PY'
import sys

path = "/opt/monitoring/rules/containers.rules.yml"
with open(path) as f:
    content = f.read()

old = 'expr: absent(container_last_seen{name!=""}) or (time() - container_last_seen{name!=""}) > 120'
new = 'expr: absent(container_last_seen{name!=""}) or (time() - max by (name, instance, job, alias) (container_last_seen{name!=""})) > 120'

if old not in content:
    print("Already patched or pattern not found — skipping.")
    sys.exit(0)

content = content.replace(old, new)
with open(path, "w") as f:
    f.write(content)
print(f"Patched {path}")
PY

echo ""
echo "Reloading Prometheus..."
curl -s -X POST http://localhost:9090/-/reload 2>/dev/null \
  && echo "  Prometheus reloaded." \
  || echo "  Note: reload Prometheus manually if needed."

echo ""
echo "ContainerDown alert will now use max() over all restartcount variants."
echo "A restarting container will only fire if ALL series for that name are stale."
