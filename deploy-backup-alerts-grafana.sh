#!/usr/bin/env bash
set -euo pipefail

echo "=== Step 1: Create Prometheus alert rules for VM backups ==="

cat > /opt/monitoring/rules/vmbackup.rules.yml << 'RULES'
groups:
- name: vmbackup
  rules:

  - alert: VMBackupUnhealthy
    expr: vmbackup_backup_healthy == 0 and vmbackup_vm_defined == 1
    for: 1h
    labels:
      severity: critical
    annotations:
      summary: "VM {{ $labels.vm }} backup is unhealthy (stale >8d or size <50MB)"

  - alert: VMBackupMissing
    expr: vmbackup_vm_defined == 1 and vmbackup_has_backup == 0
    for: 1h
    labels:
      severity: critical
    annotations:
      summary: "VM {{ $labels.vm }} is defined but has NO backup — not being backed up"

  - alert: VMBackupStale
    expr: vmbackup_latest_age_seconds > 691200 and vmbackup_vm_defined == 1
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "VM {{ $labels.vm }} backup is {{ $value | humanizeDuration }} old"

  - alert: VMBackupSuspiciouslySmall
    expr: vmbackup_latest_disk_size_bytes > 0 and vmbackup_latest_disk_size_bytes < 52428800 and vmbackup_vm_defined == 1
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "VM {{ $labels.vm }} backup is only {{ $value | humanize1024 }}B — suspiciously small"

  - alert: VMBackupCollectorDown
    expr: vmbackup_collector_up == 0 or absent(vmbackup_collector_up)
    for: 2h
    labels:
      severity: warning
    annotations:
      summary: "VM backup monitor script is not running on Unraid"

  - alert: VMNotDefined
    expr: vmbackup_has_backup == 1 and vmbackup_vm_defined == 0
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "VM {{ $labels.vm }} has backups but is not defined in libvirt — may have been removed"
RULES

echo "  Created vmbackup.rules.yml (6 alert rules)"

echo ""
echo "=== Step 2: Restart Prometheus ==="
docker restart prometheus 2>&1

echo ""
echo "=== Step 3: Add backup to Wazuh bridge ==="
if grep -q "vmbackup" /usr/local/bin/prom-to-wazuh.sh 2>/dev/null; then
  echo "  Already in bridge"
else
  cat >> /usr/local/bin/prom-to-wazuh.sh << 'BRIDGE'

# ============================================================
# 10. VM Backup Health
# ============================================================
query 'vmbackup_backup_healthy == 0 and vmbackup_vm_defined == 1' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    vm = r['metric'].get('vm','')
    print(f'{vm}')
" 2>/dev/null | while read -r vm; do
  emit "VMBackupUnhealthy" "192.168.10.10" "$vm" "critical" "0" "VM $vm backup is unhealthy on Unraid"
done

query 'vmbackup_vm_defined == 1 and vmbackup_has_backup == 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    vm = r['metric'].get('vm','')
    print(f'{vm}')
" 2>/dev/null | while read -r vm; do
  emit "VMBackupMissing" "192.168.10.10" "$vm" "critical" "0" "VM $vm has NO backup on Unraid"
done
BRIDGE
  echo "  Added backup checks to Wazuh bridge"
fi

echo ""
echo "=== Done ==="
echo "  Alert rules: vmbackup.rules.yml"
echo "  Wazuh bridge: VMBackupUnhealthy + VMBackupMissing events"
echo ""
echo "  Next: Deploy setup-unraid-backup-monitor.sh on Unraid"
echo "  Then create Grafana dashboard after metrics flow"
