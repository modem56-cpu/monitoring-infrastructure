#!/usr/bin/env bash
# Sync active employees from Google Sheet and run reconciliation
set -euo pipefail

echo "Step 1: Pull active employees from Google Sheet..."
rm -f /tmp/employees_new.json
OUT_FILE=/opt/monitoring/data/employees.json \
SA_KEY=/opt/monitoring/gam-project-gf5mq-97886701cbdd.json \
ADMIN_EMAIL=brian.monte@yokly.gives \
  python3 /opt/monitoring/sync-employees-from-sheet.py

echo ""
echo "Step 3: Run reconciliation with full roster..."
SA_KEY=/opt/monitoring/gam-project-gf5mq-97886701cbdd.json \
ADMIN_EMAIL=brian.monte@yokly.gives \
  /opt/monitoring/bin/employee-gworkspace-reconcile.py

echo ""
echo "Done."
