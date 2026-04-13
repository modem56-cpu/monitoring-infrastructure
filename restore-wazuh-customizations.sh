#!/usr/bin/env bash
set -euo pipefail

OSSEC="/var/ossec"

echo "============================================"
echo "  Restoring Wazuh Custom Rules & Decoders"
echo "============================================"

echo ""
echo "=== Step 1: Create directories ==="
mkdir -p "$OSSEC/etc/rules" "$OSSEC/etc/decoders" "$OSSEC/etc/shared/default"
chown wazuh:wazuh "$OSSEC/etc/rules" "$OSSEC/etc/decoders"

echo ""
echo "=== Step 2: Prometheus monitoring rules (100300-100307) ==="
cp /opt/monitoring/prometheus_monitoring_rules.xml "$OSSEC/etc/rules/prometheus_monitoring.xml" 2>/dev/null || \
cat > "$OSSEC/etc/rules/prometheus_monitoring.xml" << 'XML'
<group name="prometheus,">
  <rule id="100300" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^prometheus$</field>
    <description>Prometheus: $(alertname) on $(instance)</description>
    <group>prometheus,monitoring,</group>
  </rule>
  <rule id="100301" level="12">
    <if_sid>100300</if_sid>
    <field name="alertname">^NodeDown$</field>
    <description>CRITICAL: Node $(instance) is DOWN</description>
    <group>prometheus,availability,</group>
  </rule>
  <rule id="100302" level="8">
    <if_sid>100300</if_sid>
    <field name="alertname">^HighCPU$</field>
    <description>WARNING: High CPU on $(instance) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>
  <rule id="100303" level="7">
    <if_sid>100300</if_sid>
    <field name="alertname">^HighCPUProcess$</field>
    <description>WARNING: High CPU process on $(instance) — $(summary)</description>
    <group>prometheus,performance,process,</group>
  </rule>
  <rule id="100304" level="8">
    <if_sid>100300</if_sid>
    <field name="alertname">^MemoryPressure$</field>
    <description>WARNING: Memory pressure on $(instance) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>
  <rule id="100305" level="10">
    <if_sid>100300</if_sid>
    <field name="alertname">^DiskAlmostFull$</field>
    <description>CRITICAL: Disk almost full on $(instance) — $(summary)</description>
    <group>prometheus,storage,</group>
  </rule>
  <rule id="100306" level="6">
    <if_sid>100300</if_sid>
    <field name="alertname">^SwapPressure$</field>
    <description>WARNING: Swap pressure on $(instance) — $(summary)</description>
    <group>prometheus,performance,</group>
  </rule>
  <rule id="100307" level="3">
    <if_sid>100300</if_sid>
    <field name="alertname">^SSHSession$</field>
    <description>INFO: SSH session detected — $(summary)</description>
    <group>prometheus,ssh,audit,</group>
  </rule>
</group>
XML

echo ""
echo "=== Step 3: UDM firewall rules (100401-100405) ==="
cat > "$OSSEC/etc/rules/udm_firewall.xml" << 'XML'
<group name="udm,firewall,network,">
  <rule id="100401" level="3">
    <if_sid>100010</if_sid>
    <match>DESCR="Allow</match>
    <description>UDM Allow: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,allowed,</group>
  </rule>
  <rule id="100402" level="6">
    <if_sid>100010</if_sid>
    <match>DESCR="Drop</match>
    <description>UDM Blocked: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,blocked,</group>
  </rule>
  <rule id="100403" level="5">
    <if_sid>100010</if_sid>
    <match>DESCR="Default</match>
    <description>UDM Default Policy: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,default_policy,</group>
  </rule>
  <rule id="100405" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100402</if_matched_sid>
    <same_source_ip/>
    <description>UDM: Possible port scan from $(srcip)</description>
    <group>udm,firewall,scan,</group>
  </rule>
</group>
XML

echo ""
echo "=== Step 4: Google Workspace rules (100500-100508) ==="
cat > "$OSSEC/etc/rules/google_workspace.xml" << 'XML'
<group name="google_workspace,">
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^google_workspace$</field>
    <description>Google Workspace: $(alertname)</description>
    <group>google_workspace,</group>
  </rule>
  <rule id="100501" level="10">
    <if_sid>100500</if_sid>
    <match>login_failure</match>
    <description>Google Workspace: Login failure — $(summary)</description>
    <group>google_workspace,authentication_failed,</group>
  </rule>
  <rule id="100502" level="12">
    <if_sid>100500</if_sid>
    <match>suspicious_login</match>
    <description>CRITICAL: Google Workspace suspicious login — $(summary)</description>
    <group>google_workspace,authentication,suspicious,</group>
  </rule>
  <rule id="100503" level="12">
    <if_sid>100500</if_sid>
    <match>account_disabled_password_leak</match>
    <description>CRITICAL: Google Workspace password leak — $(summary)</description>
    <group>google_workspace,credential_leak,</group>
  </rule>
  <rule id="100504" level="5">
    <if_sid>100500</if_sid>
    <match>admin_action</match>
    <description>Google Workspace admin action — $(summary)</description>
    <group>google_workspace,admin,audit,</group>
  </rule>
  <rule id="100505" level="7">
    <if_sid>100500</if_sid>
    <match>external_share</match>
    <description>Google Workspace: External file sharing — $(summary)</description>
    <group>google_workspace,data_loss,</group>
  </rule>
  <rule id="100506" level="7">
    <if_sid>100500</if_sid>
    <match>over_quota</match>
    <description>Google Workspace: User over 50GB — $(summary)</description>
    <group>google_workspace,storage,compliance,</group>
  </rule>
  <rule id="100507" level="10">
    <if_sid>100500</if_sid>
    <match>security_</match>
    <description>Google Workspace Security Alert — $(summary)</description>
    <group>google_workspace,security_alert,</group>
  </rule>
  <rule id="100508" level="6">
    <if_sid>100500</if_sid>
    <match>quota_summary</match>
    <description>Google Workspace: Storage quota summary — $(summary)</description>
    <group>google_workspace,storage,compliance,</group>
  </rule>
</group>
XML

echo ""
echo "=== Step 5: VM Backup rules (100600-100603) ==="
cat > "$OSSEC/etc/rules/vmbackup.xml" << 'XML'
<group name="vmbackup,backup,">
  <rule id="100600" level="3">
    <decoded_as>vmbackup-status</decoded_as>
    <description>VM Backup status: $(extra_data) age=$(data) days</description>
    <group>vmbackup,</group>
  </rule>
  <rule id="100601" level="10">
    <if_sid>100600</if_sid>
    <match>age_days=8|age_days=9</match>
    <description>WARNING: VM backup stale — $(extra_data)</description>
    <group>vmbackup,stale,</group>
  </rule>
  <rule id="100602" level="12">
    <decoded_as>vmbackup-missing</decoded_as>
    <description>CRITICAL: VM $(extra_data) has NO backup</description>
    <group>vmbackup,missing,</group>
  </rule>
  <rule id="100603" level="8">
    <if_sid>100600</if_sid>
    <match>size=0|latest=NONE</match>
    <description>WARNING: VM backup for $(extra_data) empty</description>
    <group>vmbackup,empty,</group>
  </rule>
</group>
XML

echo ""
echo "=== Step 6: UDM firewall decoder ==="
cat > "$OSSEC/etc/decoders/udm_firewall.xml" << 'XML'
<decoder name="udm-firewall">
  <prematch>] DESCR=</prematch>
  <regex offset="after_prematch">"([^"]+)" IN=(\S+) OUT=(\S+) \S+ SRC=(\S+) DST=(\S+) \S+ \S+ \S+ \S+ \S+ PROTO=(\S+) SPT=(\d+) DPT=(\d+)</regex>
  <order>fw_action, srcintf, dstintf, srcip, dstip, protocol, srcport, dstport</order>
</decoder>
XML

echo ""
echo "=== Step 7: VM Backup decoder ==="
cat > "$OSSEC/etc/decoders/vmbackup.xml" << 'XML'
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

echo ""
echo "=== Step 8: Set permissions ==="
chown -R wazuh:wazuh "$OSSEC/etc/rules/" "$OSSEC/etc/decoders/"

echo ""
echo "=== Step 9: Restore logcollector entries ==="
CONF="$OSSEC/etc/ossec.conf"
for logfile in "/var/log/prometheus-wazuh.log" "/var/log/gworkspace-wazuh.log"; do
  if ! grep -q "$logfile" "$CONF" 2>/dev/null; then
    sed -i "/<\/ossec_config>/i\\
  <localfile>\\
    <log_format>json</log_format>\\
    <location>$logfile</location>\\
  </localfile>" "$CONF"
    echo "  Added logcollector: $logfile"
  fi
done

echo ""
echo "=== Step 10: Restore shared agent config ==="
cat > "$OSSEC/etc/shared/default/agent.conf" << 'AGENT'
<agent_config>
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/var/spool/cron/crontabs</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>
    <directories check_all="yes" realtime="yes">/etc/wireguard</directories>
  </syscheck>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</agent_config>
AGENT
chown wazuh:wazuh "$OSSEC/etc/shared/default/agent.conf"

echo ""
echo "=== Step 11: Restart Wazuh Manager ==="
systemctl restart wazuh-manager
echo "  Done"

echo ""
echo "============================================"
echo "  Restored:"
echo "    Rules: prometheus, udm_firewall, google_workspace, vmbackup"
echo "    Decoders: udm_firewall, vmbackup"
echo "    Logcollector: prometheus-wazuh.log, gworkspace-wazuh.log"
echo "    Shared agent config: FIM + auditd"
echo "============================================"
