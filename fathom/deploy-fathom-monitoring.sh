#!/usr/bin/env bash
set -euo pipefail
#
# deploy-fathom-monitoring.sh
#
# Deploys the Fathom health exporter and systemd timer to fathom-server.
# Run from the monitoring server as wazuh-admin (or any user with SSH access
# to fathom-server as fathom-admin).
#
# Usage:
#   SSH_KEY=~/.ssh/id_fathom bash /opt/monitoring/fathom/deploy-fathom-monitoring.sh
#
# Or interactively:
#   bash /opt/monitoring/fathom/deploy-fathom-monitoring.sh
#
# SAFETY: This script is READ-ONLY on the fathom DB.
# It does not enable the timer automatically — confirm unit files first.
# -----------------------------------------------------------------------

FATHOM_HOST="192.168.10.24"
FATHOM_USER="fathom-admin"
SSH_KEY="${SSH_KEY:-}"
SSH_OPTS="-o StrictHostKeyChecking=accept-new"
[[ -n "$SSH_KEY" ]] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_SCRIPTS_DIR="/opt/fathom-vault-sync/meeting_transcript_repository-master/scripts/monitoring"
REMOTE_SYSTEMD_DIR="/etc/systemd/system"

ssh_run() { ssh $SSH_OPTS "${FATHOM_USER}@${FATHOM_HOST}" "$@"; }

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
echo "======================================================="
echo " DEPLOYMENT COMPLETE — TIMER NOT YET ENABLED"
echo "======================================================="
echo ""
echo "Review the unit files above, then enable with:"
echo "  ssh ${FATHOM_USER}@${FATHOM_HOST} 'sudo systemctl enable --now fathom-health-exporter.timer'"
echo ""
echo "Verify timer is running:"
echo "  ssh ${FATHOM_USER}@${FATHOM_HOST} 'systemctl status fathom-health-exporter.timer'"
echo ""
echo "Verify Prometheus pickup (from monitoring server):"
echo "  curl -s http://192.168.10.24:9100/metrics | grep '^fathom_'"
