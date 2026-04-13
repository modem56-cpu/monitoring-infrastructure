#!/usr/bin/env bash
set -euo pipefail
#
# deploy-wazuh-prometheus.sh — Deploy Prometheus→Wazuh integration
# Run as: sudo bash /opt/monitoring/deploy-wazuh-prometheus.sh
#

OSSEC="/var/ossec"

echo "=== Step 1: Create log file ==="
touch /var/log/prometheus-wazuh.log
chown wazuh-admin:wazuh /var/log/prometheus-wazuh.log
chmod 664 /var/log/prometheus-wazuh.log

echo "=== Step 2: Install bridge script ==="
cp /opt/monitoring/prom-to-wazuh.sh /usr/local/bin/prom-to-wazuh.sh
chmod 755 /usr/local/bin/prom-to-wazuh.sh

echo "=== Step 3: Create Wazuh decoder ==="
cat > "$OSSEC/etc/decoders/prometheus_monitoring.xml" << 'XML'
<!--
  Prometheus monitoring decoder
  Parses JSON log lines from prom-to-wazuh.sh
-->
<decoder name="prometheus_monitoring">
  <prematch>{"timestamp":\S+,"source":"prometheus"</prematch>
  <regex>"alertname":"(\S+)","instance":"(\S+)","alias":"(\S+)","severity":"(\S+)","value":"(\S+)","summary":"(\.+)"</regex>
  <order>alert_name,srcip,dstuser,status,data,extra_data</order>
</decoder>
XML
chown wazuh:wazuh "$OSSEC/etc/decoders/prometheus_monitoring.xml"

echo "=== Step 4: Create Wazuh rules ==="
cat > "$OSSEC/etc/rules/prometheus_monitoring.xml" << 'XML'
<!--
  Prometheus monitoring rules (100100-100110)
  Triggered by events from prom-to-wazuh.sh bridge script
-->
<group name="prometheus,">

  <!-- Base rule: any Prometheus monitoring event -->
  <rule id="100100" level="3">
    <decoded_as>prometheus_monitoring</decoded_as>
    <description>Prometheus: $(alert_name) on $(srcip)</description>
    <group>prometheus,monitoring,</group>
  </rule>

  <!-- NodeDown — critical -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="alert_name">^NodeDown$</field>
    <description>CRITICAL: Node $(srcip) is DOWN</description>
    <group>prometheus,availability,</group>
  </rule>

  <!-- HighCPU — system-wide CPU > 90% -->
  <rule id="100102" level="8">
    <if_sid>100100</if_sid>
    <field name="alert_name">^HighCPU$</field>
    <description>WARNING: High CPU on $(srcip) — $(extra_data)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- HighCPUProcess — single process > 90% CPU -->
  <rule id="100103" level="7">
    <if_sid>100100</if_sid>
    <field name="alert_name">^HighCPUProcess$</field>
    <description>WARNING: High CPU process on $(srcip) — $(extra_data)</description>
    <group>prometheus,performance,process,</group>
  </rule>

  <!-- MemoryPressure — memory > 90% -->
  <rule id="100104" level="8">
    <if_sid>100100</if_sid>
    <field name="alert_name">^MemoryPressure$</field>
    <description>WARNING: Memory pressure on $(srcip) — $(extra_data)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- DiskAlmostFull — rootfs > 90% -->
  <rule id="100105" level="10">
    <if_sid>100100</if_sid>
    <field name="alert_name">^DiskAlmostFull$</field>
    <description>CRITICAL: Disk almost full on $(srcip) — $(extra_data)</description>
    <group>prometheus,storage,</group>
  </rule>

  <!-- SwapPressure — swap > 80% -->
  <rule id="100106" level="6">
    <if_sid>100100</if_sid>
    <field name="alert_name">^SwapPressure$</field>
    <description>WARNING: Swap pressure on $(srcip) — $(extra_data)</description>
    <group>prometheus,performance,</group>
  </rule>

  <!-- SSHSession — audit (info level) -->
  <rule id="100107" level="3">
    <if_sid>100100</if_sid>
    <field name="alert_name">^SSHSession$</field>
    <description>INFO: SSH session detected — $(extra_data)</description>
    <group>prometheus,ssh,audit,</group>
  </rule>

</group>
XML
chown wazuh:wazuh "$OSSEC/etc/rules/prometheus_monitoring.xml"

echo "=== Step 5: Add logcollector to ossec.conf ==="
# Check if already added
if grep -q "prometheus-wazuh.log" "$OSSEC/etc/ossec.conf"; then
  echo "  logcollector entry already exists, skipping."
else
  # Insert before closing </ossec_config>
  sed -i '/<\/ossec_config>/i \
  <!-- Prometheus monitoring bridge -->\
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/log/prometheus-wazuh.log</location>\
  </localfile>' "$OSSEC/etc/ossec.conf"
  echo "  logcollector entry added."
fi

echo "=== Step 6: Create systemd timer ==="
cat > /etc/systemd/system/prom-to-wazuh.service << 'SVC'
[Unit]
Description=Push Prometheus metrics to Wazuh log
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/prom-to-wazuh.sh
SVC

cat > /etc/systemd/system/prom-to-wazuh.timer << 'TMR'
[Unit]
Description=Run Prometheus-to-Wazuh bridge every 60 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now prom-to-wazuh.timer

echo "=== Step 7: Restart Wazuh manager ==="
systemctl restart wazuh-manager

echo ""
echo "=== Deployment complete ==="
echo "  Decoder:  $OSSEC/etc/decoders/prometheus_monitoring.xml"
echo "  Rules:    $OSSEC/etc/rules/prometheus_monitoring.xml"
echo "  Log:      /var/log/prometheus-wazuh.log"
echo "  Timer:    prom-to-wazuh.timer (every 60s)"
echo "  Bridge:   /usr/local/bin/prom-to-wazuh.sh"
echo ""
echo "Verify with: tail -f /var/log/prometheus-wazuh.log"
echo "Check Wazuh: tail -f /var/ossec/logs/alerts/alerts.json | grep prometheus"
