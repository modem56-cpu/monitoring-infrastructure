#!/usr/bin/env bash
# restore-wazuh-prometheus-ingestion.sh
# Restores Prometheus→Wazuh bridge decoder, rules, and logcollector.
# Run as root when:
#   - /var/ossec/etc/decoders/prometheus_monitoring.xml is missing
#   - /var/ossec/etc/rules/prometheus_monitoring.xml is missing
#   - prometheus-wazuh.log is not in ossec.conf logcollector
#
# Idempotent — safe to re-run.
set -euo pipefail

OSSEC="/var/ossec"

echo "=== Restoring Prometheus→Wazuh ingestion ==="
echo ""

# 1. Decoder
echo "--- Step 1: Prometheus decoder ---"
cat > "$OSSEC/etc/decoders/prometheus_monitoring.xml" << 'XML'
<!--
  Prometheus monitoring decoder
  Parses JSON log lines written by prom-to-wazuh.sh
  Format: {"timestamp":"...","source":"prometheus","alertname":"...","instance":"...","alias":"...","severity":"...","value":"...","summary":"..."}
-->
<decoder name="prometheus_monitoring">
  <prematch>{"timestamp":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
XML
chown wazuh:wazuh "$OSSEC/etc/decoders/prometheus_monitoring.xml"
echo "  Wrote $OSSEC/etc/decoders/prometheus_monitoring.xml"

# 2. Rules
echo ""
echo "--- Step 2: Prometheus rules (100100-100113) ---"
cat > "$OSSEC/etc/rules/prometheus_monitoring.xml" << 'XML'
<!--
  Prometheus monitoring rules (100100-100113)
  Triggered by events from prom-to-wazuh.sh bridge script.
  Decoder: prometheus_monitoring (JSON_Decoder)
  All rules key on data.source == "prometheus" via the base rule.
-->
<group name="prometheus,monitoring,">

  <!-- Base rule: any Prometheus bridge event -->
  <rule id="100100" level="3">
    <decoded_as>prometheus_monitoring</decoded_as>
    <field name="source">^prometheus$</field>
    <description>Prometheus bridge: $(alertname) on $(instance) [$(severity)]</description>
    <group>prometheus,monitoring,</group>
  </rule>

  <!-- NodeDown — critical -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="alertname">^NodeDown$</field>
    <description>CRITICAL: Node $(instance) is DOWN</description>
    <group>prometheus,availability,</group>
  </rule>

  <!-- HighCPU — system-wide CPU > 90% -->
  <rule id="100102" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^HighCPU$</field>
    <description>High CPU on $(alias) ($(instance)) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- HighCPUProcess — single process > 90% CPU -->
  <rule id="100103" level="6">
    <if_sid>100100</if_sid>
    <field name="alertname">^HighCPUProcess$</field>
    <description>High CPU process on $(alias): $(summary)</description>
    <group>prometheus,performance,process,</group>
  </rule>

  <!-- MemoryPressure — memory > 90% -->
  <rule id="100104" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^MemoryPressure$</field>
    <description>Memory pressure on $(alias) ($(instance)) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- DiskAlmostFull — rootfs > 90% -->
  <rule id="100105" level="10">
    <if_sid>100100</if_sid>
    <field name="alertname">^DiskAlmostFull$</field>
    <description>Disk almost full on $(alias) ($(instance)) — $(summary)</description>
    <group>prometheus,storage,</group>
  </rule>

  <!-- SwapPressure — swap > 80% -->
  <rule id="100106" level="5">
    <if_sid>100100</if_sid>
    <field name="alertname">^SwapPressure$</field>
    <description>Swap pressure on $(alias) ($(instance)) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- SSHSession — info level (expected activity) -->
  <rule id="100107" level="3">
    <if_sid>100100</if_sid>
    <field name="alertname">^SSHSession$</field>
    <description>SSH session: $(summary)</description>
    <group>prometheus,ssh,audit,</group>
  </rule>

  <!-- AkvoradoDown — critical -->
  <rule id="100108" level="12">
    <if_sid>100100</if_sid>
    <field name="alertname">^AkvoradoDown$</field>
    <description>CRITICAL: Akvorado component down — $(summary)</description>
    <group>prometheus,akvorado,availability,</group>
  </rule>

  <!-- AkvoradoNoFlows / AkvoradoKafkaLag — warning -->
  <rule id="100109" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^AkvoradoNoFlows$|^AkvoradoKafkaLag$</field>
    <description>Akvorado flow pipeline issue — $(summary)</description>
    <group>prometheus,akvorado,performance,</group>
  </rule>

  <!-- GWorkspace external sharing (info — known baseline) -->
  <rule id="100110" level="3">
    <if_sid>100100</if_sid>
    <field name="alertname">^GWorkspaceExternalShare$</field>
    <description>GWorkspace: $(summary)</description>
    <group>prometheus,google_workspace,</group>
  </rule>

  <!-- GWorkspace over quota / drive growth — warning -->
  <rule id="100111" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^GWorkspaceDriveGrowth$|^GWorkspaceOverQuota$</field>
    <description>GWorkspace storage alert — $(summary)</description>
    <group>prometheus,google_workspace,storage,</group>
  </rule>

  <!-- Employee reconcile — orphaned accounts (warning) -->
  <rule id="100112" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^EmployeeOrphanedAccounts$</field>
    <description>Employee reconcile: $(summary)</description>
    <group>prometheus,employee_reconcile,</group>
  </rule>

  <!-- Employee reconcile — unauthorized admin (critical) -->
  <rule id="100113" level="12">
    <if_sid>100100</if_sid>
    <field name="alertname">^EmployeeUnauthorizedAdmin$</field>
    <description>CRITICAL: Unauthorized GW admin — $(summary)</description>
    <group>prometheus,employee_reconcile,unauthorized_admin,</group>
  </rule>

  <!-- Network new device — warning -->
  <rule id="100114" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^NetworkNewDevice$</field>
    <description>Network: new unknown device detected — $(summary)</description>
    <group>prometheus,network_inventory,</group>
  </rule>

  <!-- Network ARP conflict — critical -->
  <rule id="100115" level="10">
    <if_sid>100100</if_sid>
    <field name="alertname">^NetworkARPConflict$</field>
    <description>Network ARP conflict detected — $(summary)</description>
    <group>prometheus,network_inventory,arp,</group>
  </rule>

  <!-- Unraid array full — critical -->
  <rule id="100116" level="10">
    <if_sid>100100</if_sid>
    <field name="alertname">^UnraidArrayFull$</field>
    <description>Unraid array capacity critical — $(summary)</description>
    <group>prometheus,storage,unraid,</group>
  </rule>

  <!-- GWorkspace unapproved shared drive with external members — warning -->
  <rule id="100117" level="7">
    <if_sid>100100</if_sid>
    <field name="alertname">^GWorkspaceUnapprovedSharedDriveAccess$</field>
    <description>GWorkspace: unapproved shared drive(s) have external members — $(data.summary)</description>
    <group>prometheus,google_workspace,shared_drive,</group>
  </rule>

</group>
XML
chown wazuh:wazuh "$OSSEC/etc/rules/prometheus_monitoring.xml"
echo "  Wrote $OSSEC/etc/rules/prometheus_monitoring.xml (rules 100100-100117)"

# 3. Logcollector entry in ossec.conf
echo ""
echo "--- Step 3: Logcollector entry ---"
CONF="$OSSEC/etc/ossec.conf"
if grep -q "prometheus-wazuh.log" "$CONF" 2>/dev/null; then
    echo "  Already present — skipping"
else
    sed -i '/<\/ossec_config>/i \
  <!-- Prometheus monitoring bridge -->\
  <localfile>\
    <log_format>json</log_format>\
    <location>\/var\/log\/prometheus-wazuh.log<\/location>\
  <\/localfile>' "$CONF"
    echo "  Added logcollector entry for /var/log/prometheus-wazuh.log"
fi

# 4. Log file permissions
echo ""
echo "--- Step 4: Log file permissions ---"
LOG="/var/log/prometheus-wazuh.log"
if [ ! -f "$LOG" ]; then
    touch "$LOG"
    echo "  Created $LOG"
fi
chown wazuh-admin:wazuh "$LOG"
chmod 664 "$LOG"
echo "  Permissions set: wazuh-admin:wazuh 664"

# 5. Restart Wazuh manager
echo ""
echo "--- Step 5: Restart Wazuh manager ---"
systemctl restart wazuh-manager
sleep 3
if systemctl is-active --quiet wazuh-manager; then
    echo "  wazuh-manager restarted OK"
else
    echo "  ERROR: wazuh-manager failed to start — check: journalctl -u wazuh-manager -n 30"
    exit 1
fi

echo ""
echo "=== Done ==="
echo ""
echo "Verify ingestion (wait ~2 minutes for first events):"
echo "  tail -f /var/ossec/logs/alerts/alerts.json | grep -m 5 prometheus"
echo "  grep prometheus-wazuh.log /var/ossec/etc/ossec.conf"
