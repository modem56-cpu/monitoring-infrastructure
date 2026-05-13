#!/usr/bin/env bash
# deploy-prom-wazuh-final.sh
# 1. Deploys updated prom-to-wazuh.sh (severity fix + new checks)
# 2. Replaces decoder with log_format:json-compatible approach (decoded_as:json)
# 3. Restarts wazuh-manager
# 4. Runs logtest to verify decoder fires on a sample bridge event
# Run as root
set -euo pipefail

OSSEC="/var/ossec"

echo "=== Step 1: Deploy updated prom-to-wazuh.sh ==="
cp /opt/monitoring/prom-to-wazuh.sh /usr/local/bin/prom-to-wazuh.sh
chmod 755 /usr/local/bin/prom-to-wazuh.sh
echo "  Deployed /usr/local/bin/prom-to-wazuh.sh"

echo ""
echo "=== Step 2: Replace prometheus decoder (use decoded_as:json approach) ==="
# The log_format:json localfile setting makes Wazuh parse JSON automatically.
# When log_format:json is active, the internal JSON decoder runs first and
# sets decoded_as=json with all fields as data.*
# Rules must therefore use <decoded_as>json</decoded_as>, not the custom decoder name.
cat > "$OSSEC/etc/decoders/prometheus_monitoring.xml" << 'XML'
<!--
  prometheus_monitoring decoder
  NOTE: /var/log/prometheus-wazuh.log is configured with log_format:json
  in ossec.conf localfile. Wazuh's built-in JSON decoder handles all field
  extraction automatically (fields become data.source, data.alertname, etc.).
  This file exists for documentation only — the rules use <decoded_as>json</decoded_as>.
-->
<decoder name="prometheus_monitoring_passthrough">
  <prematch>{"timestamp":</prematch>
</decoder>
XML
chown wazuh:wazuh "$OSSEC/etc/decoders/prometheus_monitoring.xml"
echo "  Wrote decoder (passthrough — JSON handled by log_format:json)"

echo ""
echo "=== Step 3: Update rules to use decoded_as:json ==="
cat > "$OSSEC/etc/rules/prometheus_monitoring.xml" << 'XML'
<!--
  Prometheus monitoring rules (100100-100116)
  Bridge: /usr/local/bin/prom-to-wazuh.sh → /var/log/prometheus-wazuh.log
  Localfile log_format:json → fields available as data.*
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

  <!-- SSHSession (info — expected activity) -->
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

</group>
XML
chown wazuh:wazuh "$OSSEC/etc/rules/prometheus_monitoring.xml"
echo "  Wrote rules 100100-100116 (using decoded_as:json)"

echo ""
echo "=== Step 4: Restart Wazuh manager ==="
systemctl restart wazuh-manager
sleep 3
systemctl is-active --quiet wazuh-manager && echo "  wazuh-manager OK" || { echo "  ERROR: wazuh-manager failed"; exit 1; }

echo ""
echo "=== Step 5: Decoder test via wazuh-logtest ==="
TEST_LINE='{"timestamp":"2026-05-13T03:00:00Z","source":"prometheus","alertname":"NetworkARPConflict","instance":"192.168.10.20:9100","alias":"wazuh-server","severity":"critical","value":"4","summary":"Network inventory: 4 ARP conflicts in last 24h"}'
echo "Input: $TEST_LINE"
echo ""
echo "$TEST_LINE" | /var/ossec/bin/wazuh-logtest -U 2>&1 | grep -E "decoder|rule\.id|rule\.level|rule\.description|group|Phase" || \
echo "$TEST_LINE" | timeout 5 /var/ossec/bin/ossec-logtest 2>&1 | head -30 || \
echo "  (wazuh-logtest not available interactively — check alerts.json after next timer run)"

echo ""
echo "=== Done ==="
echo ""
echo "Verify in ~60s (after next timer run):"
echo "  sudo grep -c '\"source\":\"prometheus\"' /var/ossec/logs/alerts/alerts.json"
echo "  sudo grep '\"source\":\"prometheus\"' /var/ossec/logs/alerts/alerts.json | tail -3 | python3 -m json.tool | grep -E 'alertname|rule|level'"
