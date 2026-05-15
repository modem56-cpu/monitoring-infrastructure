#!/usr/bin/env bash
set -euo pipefail
#
# deploy-fathom-monitoring.sh
#
# Deploys the Fathom health exporter, inventory exporter, and systemd timers
# to fathom-server (192.168.10.24).
# Run from the monitoring server as wazuh-admin.
#
# Prerequisites — SSH key setup (first time only):
#
#   Step A: Generate key on monitoring server (if not already done):
#     ssh-keygen -t ed25519 -f ~/.ssh/id_fathom -C "monitoring@wazuh-server" -N ""
#
#   Step B: Copy public key to fathom-server:
#     ssh-copy-id -i ~/.ssh/id_fathom.pub fathom-admin@192.168.10.24
#     (or paste ~/.ssh/id_fathom.pub into fathom-server's ~/.ssh/authorized_keys)
#
#   Step C: Test:
#     ssh -i ~/.ssh/id_fathom fathom-admin@192.168.10.24 hostname
#
# Usage after SSH key setup:
#   SSH_KEY=~/.ssh/id_fathom bash /opt/monitoring/fathom/deploy-fathom-monitoring.sh
#
# SAFETY: This script is READ-ONLY on the fathom DB.
# Timers are NOT enabled automatically — confirm unit files first.
# -----------------------------------------------------------------------

FATHOM_HOST="192.168.10.24"
FATHOM_USER="fathom-admin"
SSH_KEY="${SSH_KEY:-}"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
[[ -n "$SSH_KEY" ]] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_SCRIPTS_DIR="/opt/fathom-vault-sync/meeting_transcript_repository-master/scripts/monitoring"
REMOTE_SYSTEMD_DIR="/etc/systemd/system"

ssh_run() { ssh $SSH_OPTS "${FATHOM_USER}@${FATHOM_HOST}" "$@"; }

# Pre-flight: verify SSH connectivity
echo "=== Pre-flight: SSH connectivity check ==="
if ! ssh $SSH_OPTS -o BatchMode=yes "${FATHOM_USER}@${FATHOM_HOST}" "hostname" 2>/dev/null; then
    echo ""
    echo "ERROR: Cannot SSH to ${FATHOM_USER}@${FATHOM_HOST}"
    echo ""
    echo "  SSH key setup required. Run these steps on the monitoring server:"
    echo "    1. ssh-keygen -t ed25519 -f ~/.ssh/id_fathom -C 'monitoring@wazuh-server' -N ''"
    echo "    2. cat ~/.ssh/id_fathom.pub"
    echo "       (then add the public key to fathom-server's /home/fathom-admin/.ssh/authorized_keys)"
    echo "    3. export SSH_KEY=~/.ssh/id_fathom"
    echo "    4. Re-run this script"
    exit 1
fi
echo "  SSH OK — connected to ${FATHOM_HOST} as ${FATHOM_USER}"

echo "=== Step 1: Verifying environment on fathom-server ==="
ssh_run "
  echo '--- node_exporter ---'
  find /usr/local/bin /usr/bin -name node_exporter 2>/dev/null || echo NOT FOUND
  echo '--- textfile dir ---'
  ls -la /var/lib/node_exporter/textfile_collector/ 2>/dev/null || echo NOT FOUND
  echo '--- venv ---'
  ls /opt/fathom-vault-sync/meeting_transcript_repository-master/.venv/bin/python3 2>/dev/null || echo NOT FOUND
  echo '--- node_exporter flags ---'
  systemctl cat node_exporter 2>/dev/null | grep textfile || echo 'no textfile flag found'
  echo '--- scripts dir ---'
  ls /opt/fathom-vault-sync/meeting_transcript_repository-master/scripts/ 2>/dev/null
"

echo ""
echo "=== Step 2: Creating scripts/monitoring directory ==="
ssh_run "mkdir -p ${REMOTE_SCRIPTS_DIR}"

echo ""
echo "=== Step 3: Copying exporter script ==="
scp $SSH_OPTS \
  "${SRC_DIR}/fathom_health_exporter.py" \
  "${FATHOM_USER}@${FATHOM_HOST}:${REMOTE_SCRIPTS_DIR}/fathom_health_exporter.py"
ssh_run "chmod 755 ${REMOTE_SCRIPTS_DIR}/fathom_health_exporter.py"

echo ""
echo "=== Step 4: Ensuring textfile_collector dir is writable ==="
ssh_run "
  TDIR=/var/lib/node_exporter/textfile_collector
  if [ ! -d \"\$TDIR\" ]; then
    sudo mkdir -p \"\$TDIR\"
    sudo chown fathom-admin:\$(id -gn fathom-admin) \"\$TDIR\"
    echo 'Created textfile_collector directory'
  else
    # Check write access
    if touch \"\$TDIR/.write_test\" 2>/dev/null; then
      rm \"\$TDIR/.write_test\"
      echo 'Write access OK'
    else
      echo 'Need sudo to fix permissions...'
      sudo chown fathom-admin:\$(id -gn fathom-admin) \"\$TDIR\" || \
        sudo chmod g+w \"\$TDIR\"
      echo 'Permissions fixed'
    fi
  fi
"

echo ""
echo "=== Step 5: Test-running the exporter (DRY RUN) ==="
ssh_run "
  /opt/fathom-vault-sync/meeting_transcript_repository-master/.venv/bin/python3 \
    ${REMOTE_SCRIPTS_DIR}/fathom_health_exporter.py && \
  echo 'Exporter ran OK' && \
  echo '--- .prom output (first 40 lines) ---' && \
  head -40 /var/lib/node_exporter/textfile_collector/fathom_health.prom
"

echo ""
echo "=== Step 6: Verify Prometheus is picking up metrics ==="
ssh_run "curl -s http://localhost:9100/metrics | grep '^fathom_' | head -20"

echo ""
echo "=== Step 7: Copying systemd units (NOT enabling yet) ==="
scp $SSH_OPTS \
  "${SRC_DIR}/fathom-health-exporter.service" \
  "${FATHOM_USER}@${FATHOM_HOST}:/tmp/fathom-health-exporter.service"
scp $SSH_OPTS \
  "${SRC_DIR}/fathom-health-exporter.timer" \
  "${FATHOM_USER}@${FATHOM_HOST}:/tmp/fathom-health-exporter.timer"

ssh_run "
  sudo cp /tmp/fathom-health-exporter.service ${REMOTE_SYSTEMD_DIR}/
  sudo cp /tmp/fathom-health-exporter.timer   ${REMOTE_SYSTEMD_DIR}/
  sudo systemctl daemon-reload
  echo 'Units installed. NOT enabled yet.'
  echo ''
  echo '--- fathom-health-exporter.service ---'
  systemctl cat fathom-health-exporter.service
  echo ''
  echo '--- fathom-health-exporter.timer ---'
  systemctl cat fathom-health-exporter.timer
"

echo ""
echo "=== Step 8: Deploy inventory exporter ==="
scp $SSH_OPTS \
  "${SRC_DIR}/fathom-inventory-exporter.py" \
  "${FATHOM_USER}@${FATHOM_HOST}:${REMOTE_SCRIPTS_DIR}/fathom-inventory-exporter.py"
ssh_run "chmod 755 ${REMOTE_SCRIPTS_DIR}/fathom-inventory-exporter.py"

echo ""
echo "=== Step 8a: Test-run inventory exporter ==="
ssh_run "
  mkdir -p /var/lib/fathom-monitoring/inventory
  /opt/fathom-vault-sync/meeting_transcript_repository-master/.venv/bin/python3 \
    ${REMOTE_SCRIPTS_DIR}/fathom-inventory-exporter.py && \
  echo '--- Inventory state ---' && \
  cat /var/lib/fathom-monitoring/fathom_inventory_state.json && \
  echo '--- Inventory directory ---' && \
  ls -lh /var/lib/fathom-monitoring/inventory/ 2>/dev/null || echo 'No inventory files yet'
"

echo ""
echo "=== Step 9: Deploy inventory exporter systemd units ==="
scp $SSH_OPTS \
  "${SRC_DIR}/fathom-inventory-exporter.service" \
  "${FATHOM_USER}@${FATHOM_HOST}:/tmp/fathom-inventory-exporter.service"
scp $SSH_OPTS \
  "${SRC_DIR}/fathom-inventory-exporter.timer" \
  "${FATHOM_USER}@${FATHOM_HOST}:/tmp/fathom-inventory-exporter.timer"

ssh_run "
  sudo cp /tmp/fathom-inventory-exporter.service ${REMOTE_SYSTEMD_DIR}/
  sudo cp /tmp/fathom-inventory-exporter.timer   ${REMOTE_SYSTEMD_DIR}/
  sudo systemctl daemon-reload
  echo 'Inventory exporter units installed. NOT enabled yet.'
"

echo ""
echo "=== Step 10: Sync inventory files to monitoring server report directory ==="
REPORTS_DIR="/opt/monitoring/reports"
mkdir -p "$REPORTS_DIR"

echo "Syncing inventory files from fathom-server to ${REPORTS_DIR}/"
for FILE in fathom_recording_inventory.json fathom_recording_inventory.csv \
            fathom_recording_issues.json fathom_recording_issues.csv; do
  scp $SSH_OPTS \
    "${FATHOM_USER}@${FATHOM_HOST}:/var/lib/fathom-monitoring/inventory/${FILE}" \
    "${REPORTS_DIR}/${FILE}" 2>/dev/null \
    && chmod 644 "${REPORTS_DIR}/${FILE}" && echo "  OK: ${FILE}" \
    || echo "  MISSING: ${FILE} — run inventory exporter first"
done

echo ""
echo "=== Step 11: Set up periodic sync cron on monitoring server ==="
SYNC_SCRIPT="${SRC_DIR}/sync-inventory-from-fathom.sh"
CRON_LINE="*/15 * * * * SSH_KEY=${SSH_KEY:-~/.ssh/id_fathom} bash ${SYNC_SCRIPT} >> /var/log/fathom-inventory-sync.log 2>&1"
if ! crontab -l 2>/dev/null | grep -qF "sync-inventory-from-fathom"; then
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  echo "  Cron installed: sync every 15 minutes"
else
  echo "  Cron already present — skipping"
fi

echo ""
echo "======================================================="
echo " DEPLOYMENT COMPLETE — TIMERS NOT YET ENABLED"
echo "======================================================="
echo ""
echo "Enable timers on fathom-server:"
echo "  ssh ${FATHOM_USER}@${FATHOM_HOST} 'sudo systemctl enable --now fathom-health-exporter.timer fathom-inventory-exporter.timer'"
echo ""
echo "Verify timers:"
echo "  ssh ${FATHOM_USER}@${FATHOM_HOST} 'systemctl list-timers fathom-*'"
echo ""
echo "Verify Prometheus picks up recording metrics:"
echo "  curl -s http://192.168.10.24:9100/metrics | grep '^fathom_recording_'"
echo ""
echo "Verify inventory files are served (after first timer run):"
echo "  curl -s http://192.168.10.20:8088/fathom_recording_issues.json | python3 -m json.tool | head -30"
echo ""
echo "Manual run of inventory exporter (if you don't want to wait for the timer):"
echo "  ssh ${FATHOM_USER}@${FATHOM_HOST} 'sudo systemctl start fathom-inventory-exporter.service'"
echo "  SSH_KEY=${SSH_KEY:-~/.ssh/id_fathom} bash ${SRC_DIR}/sync-inventory-from-fathom.sh"
