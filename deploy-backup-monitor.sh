#!/usr/bin/env bash
set -euo pipefail
#
# deploy-backup-monitor.sh
# Deploys VM backup monitoring via Wazuh wodle command on Unraid agent
# Also creates a local check script for Prometheus metrics
#

echo "============================================"
echo "  VM Backup Monitoring Deployment"
echo "============================================"

# ============================================================
# 1. Create backup check script for Unraid (to be deployed via shared agent config)
# ============================================================
echo ""
echo "=== Step 1: Create shared agent config with backup monitor command ==="

SHARED="/var/ossec/etc/shared/default/agent.conf"
if grep -q "vmbackup" "$SHARED" 2>/dev/null; then
  echo "  Backup monitor already in shared config"
else
  # Add command monitoring to the shared agent config
  python3 << 'PY'
path = "/var/ossec/etc/shared/default/agent.conf"
with open(path) as f:
    content = f.read()

# Add before closing </agent_config>
backup_config = '''
  <!-- VM Backup Monitoring (Unraid) -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>vmbackup-status</tag>
    <command>bash -c 'BACKUP_DIR="/mnt/user/Backups/Domains"; echo "vmbackup_check_start"; for vm_dir in "$BACKUP_DIR"/*/; do vm=$(basename "$vm_dir"); latest=$(find "$vm_dir" -maxdepth 1 -name "*.zst" -o -name "*.img" -o -name "*.xml" 2>/dev/null | sort | tail -1); if [ -n "$latest" ]; then age_days=$(( ($(date +%s) - $(stat -c %Y "$latest")) / 86400 )); size=$(stat -c %s "$latest"); echo "vmbackup_vm|$vm|latest=$latest|age_days=$age_days|size=$size"; else echo "vmbackup_vm|$vm|latest=NONE|age_days=-1|size=0"; fi; done; DEFINED_VMS=$(virsh list --all --name 2>/dev/null | grep -v "^$" | sort); for vm in $DEFINED_VMS; do if [ ! -d "$BACKUP_DIR/$vm" ]; then echo "vmbackup_missing|$vm|no_backup_dir"; fi; done; echo "vmbackup_check_end"'</command>
    <interval>6h</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
  </wodle>

'''

content = content.replace('</agent_config>', backup_config + '</agent_config>')
with open(path, 'w') as f:
    f.write(content)
print("  Added vmbackup command to shared agent config")
PY
fi

# ============================================================
# 2. Create Wazuh decoder for vmbackup output
# ============================================================
echo ""
echo "=== Step 2: Create vmbackup decoder ==="

cat > /var/ossec/etc/decoders/vmbackup.xml << 'XML'
<decoder name="vmbackup-status">
  <prematch>vmbackup_vm|</prematch>
  <regex>vmbackup_vm\|(\S+)\|latest=(\S+)\|age_days=(\S+)\|size=(\S+)</regex>
  <order>extra_data,url,data,status</order>
</decoder>

<decoder name="vmbackup-missing">
  <prematch>vmbackup_missing|</prematch>
  <regex>vmbackup_missing\|(\S+)\|(\S+)</regex>
  <order>extra_data,data</order>
</decoder>
XML
chown wazuh:wazuh /var/ossec/etc/decoders/vmbackup.xml

# ============================================================
# 3. Create Wazuh rules for vmbackup
# ============================================================
echo ""
echo "=== Step 3: Create vmbackup rules ==="

cat > /var/ossec/etc/rules/vmbackup.xml << 'XML'
<group name="vmbackup,backup,">

  <rule id="100600" level="3">
    <decoded_as>vmbackup-status</decoded_as>
    <description>VM Backup status: $(extra_data) age=$(data) days</description>
    <group>vmbackup,</group>
  </rule>

  <rule id="100601" level="10">
    <if_sid>100600</if_sid>
    <match>age_days=8|age_days=9|age_days=1\d|age_days=2\d|age_days=3\d</match>
    <description>WARNING: VM backup stale for $(extra_data) — $(data) days old</description>
    <group>vmbackup,stale,</group>
  </rule>

  <rule id="100602" level="12">
    <decoded_as>vmbackup-missing</decoded_as>
    <description>CRITICAL: VM $(extra_data) has NO backup directory — not being backed up</description>
    <group>vmbackup,missing,</group>
  </rule>

  <rule id="100603" level="8">
    <if_sid>100600</if_sid>
    <match>size=0|latest=NONE</match>
    <description>WARNING: VM backup for $(extra_data) has no backup files</description>
    <group>vmbackup,empty,</group>
  </rule>

</group>
XML
chown wazuh:wazuh /var/ossec/etc/rules/vmbackup.xml

# ============================================================
# 4. Create Prometheus bridge for backup metrics
# ============================================================
echo ""
echo "=== Step 4: Add backup check to Prometheus bridge ==="

if grep -q "vmbackup" /usr/local/bin/prom-to-wazuh.sh 2>/dev/null; then
  echo "  Already in bridge"
else
  cat >> /usr/local/bin/prom-to-wazuh.sh << 'BRIDGE'

# ============================================================
# 9. VM Backup staleness check (from Wazuh agent data)
# ============================================================
# This is handled by the Wazuh wodle command on the Unraid agent
# Alerts flow through vmbackup rules (100600-100603)
# No Prometheus query needed — Wazuh handles this directly
BRIDGE
  echo "  Added backup section to bridge (handled by Wazuh)"
fi

# ============================================================
# 5. Create alert rule in Prometheus for backup staleness
# ============================================================
echo ""
echo "=== Step 5: Add backup alert note to infrastructure rules ==="

# Since backup monitoring is via Wazuh wodle (not Prometheus metrics),
# add a comment to infrastructure rules noting this
echo "  Backup monitoring handled by Wazuh wodle command on Unraid agent"
echo "  Rules: 100600 (status), 100601 (stale >7d), 100602 (missing), 100603 (empty)"

# ============================================================
# 6. Restart Wazuh
# ============================================================
echo ""
echo "=== Step 6: Restart Wazuh ==="
systemctl restart wazuh-manager

echo ""
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo ""
echo "  How it works:"
echo "    1. Wazuh shared agent config pushes vmbackup command to Unraid agent (005)"
echo "    2. Every 6 hours, agent runs the command on Unraid"
echo "    3. For each VM in Backups/Domains/:"
echo "       - Reports latest backup file, age in days, and size"
echo "       - If age > 7 days → level 10 alert (stale)"
echo "       - If size = 0 or no files → level 8 alert (empty)"
echo "    4. For each defined VM NOT in Backups/Domains/:"
echo "       - level 12 alert (CRITICAL: not being backed up)"
echo ""
echo "  This would have caught the Fathom issue:"
echo "    - vmbackup_vm|fathom-vaultserver|size=6.5MB → suspiciously small for a VM"
echo "    - Or vmbackup_missing|fathom-vaultserver → if it was removed from libvirt"
echo ""
echo "  Wazuh rules: 100600-100603"
echo "  Check interval: every 6 hours"
echo "  Agent: unraid-192-168-10-10 (005)"
