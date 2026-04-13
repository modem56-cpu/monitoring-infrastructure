#!/usr/bin/env bash
set -euo pipefail

cat > /var/ossec/etc/rules/prometheus_monitoring.xml << 'XML'
<group name="prometheus,">

  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^prometheus$</field>
    <description>Prometheus: $(alertname) on $(instance)</description>
    <group>prometheus,monitoring,</group>
  </rule>

  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="alertname">^NodeDown$</field>
    <description>CRITICAL: Node $(instance) is DOWN</description>
    <group>prometheus,availability,</group>
  </rule>

  <rule id="100202" level="8">
    <if_sid>100200</if_sid>
    <field name="alertname">^HighCPU$</field>
    <description>WARNING: High CPU on $(instance) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <rule id="100203" level="7">
    <if_sid>100200</if_sid>
    <field name="alertname">^HighCPUProcess$</field>
    <description>WARNING: High CPU process on $(instance) — $(summary)</description>
    <group>prometheus,performance,process,</group>
  </rule>

  <rule id="100204" level="8">
    <if_sid>100200</if_sid>
    <field name="alertname">^MemoryPressure$</field>
    <description>WARNING: Memory pressure on $(instance) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <rule id="100205" level="10">
    <if_sid>100200</if_sid>
    <field name="alertname">^DiskAlmostFull$</field>
    <description>CRITICAL: Disk almost full on $(instance) — $(summary)</description>
    <group>prometheus,storage,</group>
  </rule>

  <rule id="100206" level="6">
    <if_sid>100200</if_sid>
    <field name="alertname">^SwapPressure$</field>
    <description>WARNING: Swap pressure on $(instance) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>

  <rule id="100207" level="3">
    <if_sid>100200</if_sid>
    <field name="alertname">^SSHSession$</field>
    <description>INFO: SSH session detected — $(summary)</description>
    <group>prometheus,ssh,audit,</group>
  </rule>

</group>
XML

chown wazuh:wazuh /var/ossec/etc/rules/prometheus_monitoring.xml
systemctl restart wazuh-manager
echo "Done. Rules updated to 100200-100207."
