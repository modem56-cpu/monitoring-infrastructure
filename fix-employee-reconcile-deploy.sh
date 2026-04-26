#!/usr/bin/env bash
# Fix issues from initial deploy-employee-reconcile.sh run:
#   1. Correct Wazuh decoder XML (remove <decoder_list> wrapper)
#   2. Create /keys/ directory and symlink the SA key
#   3. Restart Wazuh manager
#   4. Reload Prometheus
set -euo pipefail

echo "=== Fix: Employee Reconcile Deploy Issues ==="
echo ""

# ── Fix 1: Wazuh decoder XML format ────────────────────────────────────
echo "Fix 1: Wazuh decoder — remove <decoder_list> wrapper"
cat > /var/ossec/etc/decoders/employee_reconcile_decoder.xml << 'DECODER'
<decoder name="employee_reconcile">
  <prematch>{"source":"employee_reconcile"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
DECODER
chown wazuh:wazuh /var/ossec/etc/decoders/employee_reconcile_decoder.xml
echo "  Decoder fixed"

# ── Fix 2: Create /keys/ and symlink SA key ─────────────────────────────
echo ""
echo "Fix 2: /keys/ directory + SA key symlink"
mkdir -p /keys
chmod 750 /keys

KEY_SRC="/opt/monitoring/gam-project-gf5mq-97886701cbdd.json"
KEY_DST="/keys/gam-project-gf5mq-97886701cbdd.json"

if [ -f "$KEY_DST" ]; then
  echo "  $KEY_DST already exists"
elif [ -L "$KEY_DST" ]; then
  echo "  Symlink already exists"
elif [ -f "$KEY_SRC" ]; then
  ln -s "$KEY_SRC" "$KEY_DST"
  echo "  Symlinked $KEY_SRC → $KEY_DST"
else
  echo "  WARN: Source key not found at $KEY_SRC — place key manually"
fi

ls -la /keys/

# ── Fix 3: Validate Prometheus rules before reload ──────────────────────
echo ""
echo "Fix 3: Validate Prometheus rules"
docker exec prometheus promtool check rules \
  /etc/prometheus/rules/gworkspace.rules.yml 2>&1 && \
  echo "  Rules OK" || { echo "  ERROR in rules — check gworkspace.rules.yml"; exit 1; }

# ── Fix 4: Restart Wazuh manager ───────────────────────────────────────
echo ""
echo "Fix 4: Restart Wazuh manager"
systemctl restart wazuh-manager
sleep 3
systemctl is-active wazuh-manager && echo "  Wazuh manager: active" || echo "  ERROR: Wazuh manager not running"

# ── Fix 5: Reload Prometheus ────────────────────────────────────────────
echo ""
echo "Fix 5: Reload Prometheus"
curl -sf -X POST http://127.0.0.1:9090/-/reload && echo "  Prometheus reloaded" || echo "  ERROR: Prometheus reload failed"

# ── Fix 6: Run reconciliation now ──────────────────────────────────────
echo ""
echo "Fix 6: First reconciliation run"
SA_KEY="$KEY_DST" \
ADMIN_EMAIL=brian.monte@yokly.gives \
  /opt/monitoring/bin/employee-gworkspace-reconcile.py && echo "  Run OK" || echo "  WARN: Run failed (check key/credentials)"

echo ""
echo "=== Done ==="
echo ""
echo "Next: add all 99 staff to /opt/monitoring/data/employees.json"
echo "      then: systemctl start employee-reconcile.service"
