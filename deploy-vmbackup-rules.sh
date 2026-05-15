#!/usr/bin/env bash
# deploy-vmbackup-rules.sh
# Appends VM backup Prometheus alert rules to infrastructure.rules.yml
# and fixes the malformed Wazuh vmbackup rule 100600 description.
#
# Run as root or with sudo:
#   sudo bash /opt/monitoring/deploy-vmbackup-rules.sh
set -euo pipefail

RULES_FILE="/opt/monitoring/rules/infrastructure.rules.yml"
WAZUH_RULES="/var/ossec/etc/rules/vmbackup.xml"

# ─── Part 1: Prometheus alert rules ───────────────────────────────────────────
echo "=== Adding vmbackup Prometheus alert rules to infrastructure.rules.yml ==="

if grep -q "VMBackupStale" "$RULES_FILE"; then
    echo "  vmbackup rules already present — skipping."
else
    cat >> "$RULES_FILE" << 'YAMLEOF'

  # --- VM Backups (Unraid textfile collector via vmbackup-prom.sh) ---

  - alert: VMBackupStale
    expr: vmbackup_latest_age_seconds > 691200
    for: 30m
    labels:
      severity: warning
      category: vm_backup
    annotations:
      summary: "VM backup stale — {{ $labels.vm }} backed up {{ $value | humanizeDuration }} ago (threshold: 8 days)"

  - alert: VMBackupMissing
    expr: vmbackup_has_backup == 0
    for: 30m
    labels:
      severity: critical
      category: vm_backup
    annotations:
      summary: "VM {{ $labels.vm }} has no backup directory — not being backed up"

  - alert: VMBackupUnhealthy
    expr: vmbackup_backup_healthy == 0 and vmbackup_has_backup == 1
    for: 30m
    labels:
      severity: warning
      category: vm_backup
    annotations:
      summary: "VM backup unhealthy for {{ $labels.vm }} — age or disk image size below threshold"

  - alert: VMBackupAgeUnknown
    expr: vmbackup_latest_age_seconds == -1 and vmbackup_has_backup == 1
    for: 30m
    labels:
      severity: warning
      category: vm_backup
    annotations:
      summary: "VM backup age unknown for {{ $labels.vm }} — backup dir exists but no disk image found"

  - alert: VMBackupCollectorDown
    expr: vmbackup_collector_up == 0 or absent(vmbackup_collector_up)
    for: 15m
    labels:
      severity: critical
      category: vm_backup
    annotations:
      summary: "VM backup collector (vmbackup-prom.sh) not running on Unraid — backup status unknown"
YAMLEOF
    echo "  Rules appended."
fi

# Reload Prometheus to pick up the new rules
echo ""
echo "=== Reloading Prometheus ==="
if curl -sf -X POST http://127.0.0.1:9090/-/reload; then
    echo "  Prometheus reloaded."
else
    echo "  Reload failed — check Prometheus logs. Rules will load on next restart."
fi

# ─── Part 2: Fix malformed Wazuh vmbackup rule 100600 ─────────────────────────
echo ""
echo "=== Fixing Wazuh vmbackup rule 100600 (malformed 'age= days') ==="

if [ -f "$WAZUH_RULES" ]; then
    # Rule 100600 description currently: VM Backup status: $(extra_data) age=$(data) days
    # $(data) field maps to age_days value from decoder but renders blank when command
    # output doesn't match or Wazuh internal field conflicts with 'data' field name.
    # Fix: remove the unreliable $(data) interpolation from the base rule; child
    # rule 100601 already fires specifically when age_days is stale (regex match on raw log).
    if grep -q 'age=\$(data) days' "$WAZUH_RULES"; then
        sed -i 's|VM Backup status: \$(extra_data) age=\$(data) days|VM Backup status check: $(extra_data)|g' "$WAZUH_RULES"
        echo "  Fixed rule 100600 description — removed blank $(data) age interpolation."
    else
        echo "  Rule 100600 description already fixed or not found."
    fi

    # Reload Wazuh rules
    if command -v systemctl &>/dev/null; then
        systemctl reload wazuh-manager 2>/dev/null && echo "  Wazuh manager reloaded." || true
    fi
    /var/ossec/bin/wazuh-control reload 2>/dev/null && echo "  Wazuh rules reloaded." || true
else
    echo "  $WAZUH_RULES not found — Wazuh rules may not be deployed yet."
fi

echo ""
echo "=== Done ==="
echo "Verify Prometheus rules loaded:"
echo "  curl -s http://127.0.0.1:9090/api/v1/rules | python3 -c \"import json,sys; [print(r['name']) for g in json.load(sys.stdin)['data']['groups'] for r in g['rules'] if 'VMBackup' in r.get('name','')]\""
echo ""
echo "Verify live vmbackup metrics:"
echo "  curl -s 'http://127.0.0.1:9090/api/v1/query?query=vmbackup_backup_healthy' | python3 -m json.tool"
