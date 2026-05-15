#!/usr/bin/env bash
set -euo pipefail
#
# sync-inventory-from-fathom.sh
#
# Pulls fathom recording inventory export files from fathom-server
# (192.168.10.24) to /opt/monitoring/reports/ on the monitoring server.
#
# Prerequisites:
#   - SSH key for fathom-admin@192.168.10.24 must be available.
#     Run the setup section of deploy-fathom-monitoring.sh first if not done.
#   - fathom-inventory-exporter.py must be deployed and have run at least once.
#
# Typical use:
#   Cron on monitoring server (run as wazuh-admin or root):
#     */15 * * * * SSH_KEY=/home/wazuh-admin/.ssh/id_fathom bash /opt/monitoring/fathom/sync-inventory-from-fathom.sh >> /var/log/fathom-inventory-sync.log 2>&1
#
# Manual run:
#   SSH_KEY=~/.ssh/id_fathom bash /opt/monitoring/fathom/sync-inventory-from-fathom.sh

FATHOM_HOST="192.168.10.24"
FATHOM_USER="fathom-admin"
REMOTE_DIR="/var/lib/fathom-monitoring/inventory"
LOCAL_DIR="/opt/monitoring/reports"
SSH_KEY="${SSH_KEY:-}"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
[[ -n "$SSH_KEY" ]] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[$NOW] Starting inventory sync from ${FATHOM_USER}@${FATHOM_HOST}:${REMOTE_DIR}/"

FILES=(
    "fathom_recording_inventory.json"
    "fathom_recording_inventory.csv"
    "fathom_recording_issues.json"
    "fathom_recording_issues.csv"
)

mkdir -p "$LOCAL_DIR"
SYNCED=0
MISSING=0

for FILE in "${FILES[@]}"; do
    if scp $SSH_OPTS \
        "${FATHOM_USER}@${FATHOM_HOST}:${REMOTE_DIR}/${FILE}" \
        "${LOCAL_DIR}/${FILE}" 2>/dev/null; then
        chmod 644 "${LOCAL_DIR}/${FILE}"
        SIZE=$(stat -c%s "${LOCAL_DIR}/${FILE}" 2>/dev/null || echo 0)
        echo "  OK: ${FILE} (${SIZE} bytes)"
        SYNCED=$((SYNCED + 1))
    else
        echo "  MISSING: ${FILE} — not yet generated on fathom-server"
        MISSING=$((MISSING + 1))
    fi
done

if [[ $MISSING -gt 0 ]]; then
    echo "[$NOW] Sync partial: ${SYNCED} files synced, ${MISSING} not yet available."
    echo "  To generate: ssh ${FATHOM_USER}@${FATHOM_HOST} 'python3 /opt/fathom-vault-sync/meeting_transcript_repository-master/scripts/monitoring/fathom-inventory-exporter.py'"
    exit 0
fi

echo "[$NOW] Sync complete: ${SYNCED} files synced to ${LOCAL_DIR}/"
