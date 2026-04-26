#!/usr/bin/env bash
# Fix EmployeeGWCountMismatch annotation — cannot reference metric names as template functions
set -euo pipefail

RULES=/opt/monitoring/rules/gworkspace.rules.yml

python3 << 'PYEOF'
import re

path = "/opt/monitoring/rules/gworkspace.rules.yml"
with open(path) as f:
    content = f.read()

old = 'summary: "Employee count ({{ employee_reconcile_active_employees }}) vs GW active users ({{ employee_reconcile_gw_active_total }}) differ by more than 5"'
new = 'summary: "Employee roster vs GW active users differ by {{ $value | humanize }} — check for orphaned or unprovisioned accounts"'

if old in content:
    content = content.replace(old, new)
    with open(path, "w") as f:
        f.write(content)
    print("Fixed annotation")
else:
    print("Pattern not found — already fixed or changed")
PYEOF

echo ""
echo "Validating..."
docker exec prometheus promtool check rules /etc/prometheus/rules/gworkspace.rules.yml 2>&1

echo ""
echo "Reloading Prometheus..."
curl -sf -X POST http://127.0.0.1:9090/-/reload && echo "Prometheus reloaded OK"

echo ""
echo "Restarting Wazuh..."
systemctl restart wazuh-manager
sleep 3
systemctl is-active wazuh-manager && echo "Wazuh manager: active"

echo ""
echo "First reconciliation run..."
SA_KEY=/keys/gam-project-gf5mq-97886701cbdd.json \
ADMIN_EMAIL=brian.monte@yokly.gives \
  /opt/monitoring/bin/employee-gworkspace-reconcile.py
