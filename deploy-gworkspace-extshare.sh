#!/usr/bin/env bash
# deploy-gworkspace-extshare.sh
# Deploys GWorkspace shared drive external member audit changes:
#   1. Installs updated gworkspace-collector.py (adds section 3d)
#   2. Installs approved_external_shared_drives.json to /opt/monitoring/data/
#   3. Installs updated gworkspace.rules.yml (fixes broken exception metrics,
#      adds GWorkspace_UnapprovedSharedDriveExternalAccess alert)
#   4. Deploys updated prom-to-wazuh.sh (section 17 for unapproved drives)
#   5. Updates Wazuh rules (adds rule 100117)
#   6. Reloads Prometheus config
#   7. Restarts wazuh-manager
# Run as root
set -euo pipefail

REPO="/opt/monitoring"
OSSEC="/var/ossec"

echo "=== Step 1: Install updated gworkspace-collector.py ==="
cp "$REPO/gworkspace-collector.py" /opt/monitoring/bin/gworkspace-collector.py
chmod 755 /opt/monitoring/bin/gworkspace-collector.py
echo "  Installed /opt/monitoring/bin/gworkspace-collector.py"

echo ""
echo "=== Step 2: Install approved_external_shared_drives.json ==="
cp "$REPO/approved_external_shared_drives.json" /opt/monitoring/data/approved_external_shared_drives.json
chmod 644 /opt/monitoring/data/approved_external_shared_drives.json
echo "  Installed /opt/monitoring/data/approved_external_shared_drives.json"
echo "  Current approved drives:"
python3 -c "
import json
with open('/opt/monitoring/data/approved_external_shared_drives.json') as f:
    for d in json.load(f):
        print(f'    {d[\"drive_id\"]}  {d[\"drive_name\"]} ({d[\"client\"]})')
"

echo ""
echo "=== Step 3: Install updated gworkspace.rules.yml ==="
cp "$REPO/gworkspace.rules.yml" /opt/monitoring/rules/gworkspace.rules.yml
chmod 644 /opt/monitoring/rules/gworkspace.rules.yml
echo "  Installed /opt/monitoring/rules/gworkspace.rules.yml"
echo "  Reloading Prometheus config..."
curl -sf -X POST http://127.0.0.1:9090/-/reload && echo "  Prometheus reloaded OK" || echo "  WARNING: Prometheus reload failed (check manually)"

echo ""
echo "=== Step 4: Deploy updated prom-to-wazuh.sh ==="
cp "$REPO/prom-to-wazuh.sh" /usr/local/bin/prom-to-wazuh.sh
chmod 755 /usr/local/bin/prom-to-wazuh.sh
echo "  Installed /usr/local/bin/prom-to-wazuh.sh (section 17 added)"

echo ""
echo "=== Step 5: Update Wazuh rules (add rule 100117) ==="
cat > "$OSSEC/etc/rules/prometheus_monitoring.xml" << 'XML'
<!--
  Prometheus monitoring rules (100100-100117)
  Bridge: /usr/local/bin/prom-to-wazuh.sh -> /var/log/prometheus-wazuh.log
  Localfile log_format:json -> fields available as data.*
-->
<group name="prometheus,monitoring,">

  <!-- Base: any JSON event with source=prometheus -->
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^prometheus$</field>
    <description>Prometheus bridge: $(data.alertname) [$(data.severity)] on $(data.instance)</description>
    <group>prometheus,monitoring,</group>
  </rule>

  <!-- NodeDown -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="alertname">^NodeDown$</field>
    <description>CRITICAL: Node $(data.instance) ($(data.alias)) is DOWN</description>
    <group>prometheus,availability,</group>
  </rule>

  <!-- HighCPU -->
  <rule id="100102" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^HighCPU$</field>
    <description>High CPU on $(data.alias) — $(data.summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- HighCPUProcess -->
  <rule id="100103" level="6">
    <if_sid>100100</if_sid>
    <field name="alertname">^HighCPUProcess$</field>
    <description>High CPU process on $(data.alias): $(data.summary)</description>
    <group>prometheus,performance,process,</group>
  </rule>

  <!-- MemoryPressure -->
  <rule id="100104" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^MemoryPressure$</field>
    <description>Memory pressure on $(data.alias) — $(data.summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- DiskAlmostFull -->
  <rule id="100105" level="10">
    <if_sid>100100</if_sid>
    <field name="alertname">^DiskAlmostFull$</field>
    <description>Disk almost full on $(data.alias) — $(data.summary)</description>
    <group>prometheus,storage,</group>
  </rule>

  <!-- SwapPressure -->
  <rule id="100106" level="5">
    <if_sid>100100</if_sid>
    <field name="alertname">^SwapPressure$</field>
    <description>Swap pressure on $(data.alias) — $(data.summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- SSHSession (info) -->
  <rule id="100107" level="3">
    <if_sid>100100</if_sid>
    <field name="alertname">^SSHSession$</field>
    <description>SSH session detected: $(data.summary)</description>
    <group>prometheus,ssh,audit,</group>
  </rule>

  <!-- AkvoradoDown -->
  <rule id="100108" level="12">
    <if_sid>100100</if_sid>
    <field name="alertname">^AkvoradoDown$</field>
    <description>CRITICAL: Akvorado component down — $(data.summary)</description>
    <group>prometheus,akvorado,availability,</group>
  </rule>

  <!-- AkvoradoNoFlows / AkvoradoKafkaLag -->
  <rule id="100109" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^AkvoradoNoFlows$|^AkvoradoKafkaLag$</field>
    <description>Akvorado flow pipeline issue — $(data.summary)</description>
    <group>prometheus,akvorado,performance,</group>
  </rule>

  <!-- GWorkspaceExternalShare (info — known baseline) -->
  <rule id="100110" level="3">
    <if_sid>100100</if_sid>
    <field name="alertname">^GWorkspaceExternalShare$</field>
    <description>GWorkspace external sharing baseline: $(data.summary)</description>
    <group>prometheus,google_workspace,</group>
  </rule>

  <!-- GWorkspace drive growth / over quota -->
  <rule id="100111" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^GWorkspaceDriveGrowth$|^GWorkspaceOverQuota$</field>
    <description>GWorkspace storage alert — $(data.summary)</description>
    <group>prometheus,google_workspace,storage,</group>
  </rule>

  <!-- Employee orphaned accounts -->
  <rule id="100112" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^EmployeeOrphanedAccounts$</field>
    <description>Employee reconcile: $(data.summary)</description>
    <group>prometheus,employee_reconcile,</group>
  </rule>

  <!-- Employee unauthorized admin -->
  <rule id="100113" level="12">
    <if_sid>100100</if_sid>
    <field name="alertname">^EmployeeUnauthorizedAdmin$</field>
    <description>CRITICAL: Unauthorized GW admin — $(data.summary)</description>
    <group>prometheus,employee_reconcile,unauthorized_admin,</group>
  </rule>

  <!-- Network new device -->
  <rule id="100114" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^NetworkNewDevice$</field>
    <description>Network: new unknown device detected — $(data.summary)</description>
    <group>prometheus,network_inventory,</group>
  </rule>

  <!-- Network ARP conflict -->
  <rule id="100115" level="10">
    <if_sid>100100</if_sid>
    <field name="alertname">^NetworkARPConflict$</field>
    <description>Network ARP conflict detected — $(data.summary)</description>
    <group>prometheus,network_inventory,arp,</group>
  </rule>

  <!-- Unraid array full -->
  <rule id="100116" level="10">
    <if_sid>100100</if_sid>
    <field name="alertname">^UnraidArrayFull$</field>
    <description>Unraid array capacity critical — $(data.summary)</description>
    <group>prometheus,storage,unraid,</group>
  </rule>

  <!-- GWorkspace unapproved shared drive with external members -->
  <rule id="100117" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^GWorkspaceUnapprovedSharedDriveAccess$</field>
    <description>GWorkspace: unapproved shared drive(s) have external members — $(data.summary)</description>
    <group>prometheus,google_workspace,shared_drive,</group>
  </rule>

</group>
XML
chown wazuh:wazuh "$OSSEC/etc/rules/prometheus_monitoring.xml"
echo "  Wrote rules 100100-100117"

echo ""
echo "=== Step 6: Restart wazuh-manager ==="
systemctl restart wazuh-manager
sleep 3
systemctl is-active --quiet wazuh-manager && echo "  wazuh-manager OK" || { echo "  ERROR: wazuh-manager failed"; exit 1; }

echo ""
echo "=== Done ==="
echo ""
echo "Next steps:"
echo "  1. Run collector manually to verify section 3d fires:"
echo "     sudo -u root /opt/monitoring/bin/gworkspace-collector.py"
echo "  2. Check new metrics exist:"
echo "     curl -s 'http://127.0.0.1:9090/api/v1/query?query=gworkspace_unapproved_external_shared_drives_total'"
echo "     curl -s 'http://127.0.0.1:9090/api/v1/query?query=gworkspace_shared_drive_external_members'"
echo "  3. Add additional approved client drives to:"
echo "     /opt/monitoring/data/approved_external_shared_drives.json"
echo "     (use drive_id from Drive API, not drive name)"
echo "  4. Grafana dashboard already updated — check Google Workspace > Shared Drive External Access Audit"
