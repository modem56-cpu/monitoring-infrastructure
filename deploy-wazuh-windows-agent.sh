#!/usr/bin/env bash
set -euo pipefail

# deploy-wazuh-windows-agent.sh
# Configures Wazuh SIEM for the Windows 11 VM (agent 004, 192.168.1.253)
#
# What this does:
#   1. Creates a "windows" agent group in Wazuh
#   2. Assigns agent 004 (win11-vm) to that group
#   3. Deploys Windows-specific agent.conf (Event Logs, FIM, Registry)
#   4. Installs Windows-specific detection rules (100800-100815)
#   5. Reloads the Wazuh manager
#
# Run as root on wazuh-server (192.168.10.20)
# Usage: sudo bash /opt/monitoring/deploy-wazuh-windows-agent.sh

OSSEC="/var/ossec"
AGENT_ID="004"
GROUP="windows"
RULES_FILE="$OSSEC/etc/rules/windows_vm.xml"

echo "============================================"
echo "  Wazuh Windows Agent Configuration"
echo "  Agent: $AGENT_ID (win11-vm @ 192.168.1.253)"
echo "============================================"

# ── Step 1: Create windows group directory ────────────────────────────────────
echo ""
echo "=== Step 1: Create 'windows' agent group ==="
mkdir -p "$OSSEC/etc/shared/$GROUP"
chown wazuh:wazuh "$OSSEC/etc/shared/$GROUP"
echo "  Created: $OSSEC/etc/shared/$GROUP"

# ── Step 2: Assign agent 004 to windows group ─────────────────────────────────
echo ""
echo "=== Step 2: Assign agent 004 to 'windows' group ==="
# Use CLI first (Wazuh 4.x); fall back to flat-file if already assigned (error 1751 = already in group)
"$OSSEC/bin/agent_groups" -a -i "$AGENT_ID" -g "$GROUP" -q 2>&1 | grep -v "Error 1751" || true
echo "  Agent $AGENT_ID → group: $GROUP"

# ── Step 3: Deploy Windows-specific agent.conf ───────────────────────────────
echo ""
echo "=== Step 3: Deploy Windows agent.conf ==="
cat > "$OSSEC/etc/shared/$GROUP/agent.conf" << 'AGENTCONF'
<agent_config os="Windows">

  <!-- ── Windows Event Log Collection ───────────────────────────────────── -->
  <!-- Security: logon/logoff, privilege use, account management, policy change -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
    <!-- Exclude noisy network connection allow/block events (5156/5157) -->
    <query>Event/System[EventID != 5156 and EventID != 5157]</query>
  </localfile>

  <!-- System: service start/stop, driver load, hardware errors -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>System</location>
  </localfile>

  <!-- Application: app crashes, install events, .NET errors -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Application</location>
  </localfile>

  <!-- PowerShell: script block logging, module logging -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-PowerShell/Operational</location>
  </localfile>

  <!-- Windows Defender: malware detections, scan results -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
  </localfile>

  <!-- Task Scheduler: scheduled task creation/modification (common persistence) -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
  </localfile>

  <!-- ── File Integrity Monitoring ──────────────────────────────────────── -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>

    <!-- Startup folders — common persistence mechanism -->
    <directories check_all="yes" realtime="yes" report_changes="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>

    <!-- System32 drivers — rootkit/driver-based attack detection -->
    <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers</directories>

    <!-- WMI repository — fileless malware persistence -->
    <directories check_all="yes" realtime="yes">C:\Windows\System32\wbem</directories>

    <!-- Program installation directories -->
    <directories check_all="yes">C:\Program Files</directories>
    <directories check_all="yes">C:\Program Files (x86)</directories>

    <!-- Hosts file — DNS poisoning detection -->
    <directories check_all="yes" realtime="yes" report_changes="yes">C:\Windows\System32\drivers\etc</directories>

    <!-- ── Registry FIM ────────────────────────────────────────────────── -->
    <!-- Run keys — persistence via autorun -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry arch="both">HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>

    <!-- Services — new service installation (common privilege escalation) -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>

    <!-- Winlogon — credential theft, logon script injection -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>

    <!-- Browser extensions — supply chain/adware -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Google\Chrome\Extensions</windows_registry>

    <!-- Exclusions — reduce noise from frequent Windows updates -->
    <ignore>C:\Windows\System32\drivers\etc\hosts.ics</ignore>
    <ignore type="sregex">\.tmp$|\.log$|\.etl$</ignore>
  </syscheck>

  <!-- ── Vulnerability Detection ────────────────────────────────────────── -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

</agent_config>
AGENTCONF

chown wazuh:wazuh "$OSSEC/etc/shared/$GROUP/agent.conf"
echo "  Written: $OSSEC/etc/shared/$GROUP/agent.conf"

# ── Step 4: Windows-specific detection rules (100800–100815) ─────────────────
echo ""
echo "=== Step 4: Install Windows detection rules (100800-100815) ==="
cat > "$RULES_FILE" << 'XML'
<!-- Windows VM custom rules — 100800-100815 -->
<!-- Complements Wazuh built-in Windows rules (60000+) with -->
<!-- platform-specific alerting for win11-vm (192.168.1.253)  -->
<group name="windows,win11_vm,">

  <!-- ── Authentication ─────────────────────────────────────────────────── -->
  <!-- EventID 4625: Failed logon — fire at level 6, escalate on repeat -->
  <rule id="100800" level="6">
    <if_sid>60122</if_sid>
    <description>win11-vm: Windows failed logon attempt (EventID 4625)</description>
    <group>windows,authentication_failed,</group>
  </rule>

  <rule id="100801" level="12" frequency="5" timeframe="120">
    <if_matched_sid>100800</if_matched_sid>
    <same_source_ip/>
    <description>win11-vm: Brute-force — 5 failed logons in 2 min from same IP</description>
    <group>windows,brute_force,authentication_failed,</group>
  </rule>

  <!-- EventID 4648: Explicit credential use (pass-the-hash indicator) -->
  <rule id="100802" level="8">
    <if_sid>60103</if_sid>
    <description>win11-vm: Explicit credentials used — possible lateral movement (EventID 4648)</description>
    <group>windows,authentication,lateral_movement,</group>
  </rule>

  <!-- ── Privilege Escalation ───────────────────────────────────────────── -->
  <!-- EventID 4672: Special privileges assigned to new logon (admin logon) -->
  <rule id="100803" level="5">
    <if_sid>60106</if_sid>
    <description>win11-vm: Admin/privileged logon detected (EventID 4672)</description>
    <group>windows,authentication,privilege,audit,</group>
  </rule>

  <!-- EventID 4698/4702: Scheduled task created/modified -->
  <rule id="100804" level="8">
    <if_sid>60263</if_sid>
    <description>win11-vm: Scheduled task created/modified — possible persistence (EventID 4698/4702)</description>
    <group>windows,persistence,</group>
  </rule>

  <!-- ── PowerShell ─────────────────────────────────────────────────────── -->
  <!-- EventID 4104: Script block logging — catch encoded/obfuscated PS -->
  <rule id="100805" level="6">
    <if_sid>91802</if_sid>
    <description>win11-vm: PowerShell script block executed</description>
    <group>windows,powershell,</group>
  </rule>

  <rule id="100806" level="12">
    <if_sid>91802</if_sid>
    <match>-EncodedCommand|-enc |-W Hidden|-WindowStyle Hidden|DownloadString|IEX |Invoke-Expression|bypass</match>
    <description>win11-vm: Suspicious PowerShell — encoded/hidden/download execution</description>
    <group>windows,powershell,malware,attack,</group>
  </rule>

  <!-- ── Windows Defender ───────────────────────────────────────────────── -->
  <!-- Defender detects malware/PUP -->
  <rule id="100807" level="12">
    <if_sid>61118</if_sid>
    <description>win11-vm: Windows Defender malware detected — immediate review required</description>
    <group>windows,malware,virus,</group>
  </rule>

  <!-- Defender disabled — major security gap -->
  <rule id="100808" level="14">
    <if_sid>61119</if_sid>
    <description>win11-vm: CRITICAL — Windows Defender disabled</description>
    <group>windows,malware,configuration,</group>
  </rule>

  <!-- ── FIM / Registry ─────────────────────────────────────────────────── -->
  <!-- Registry Run key modification — persistence -->
  <rule id="100809" level="10">
    <if_sid>550</if_sid>
    <field name="file">CurrentVersion\\Run</field>
    <description>win11-vm: Registry Run key modified — possible persistence</description>
    <group>windows,fim,registry,persistence,</group>
  </rule>

  <!-- Services registry change — driver/service install -->
  <rule id="100810" level="8">
    <if_sid>550</if_sid>
    <field name="file">CurrentControlSet\\Services</field>
    <description>win11-vm: Services registry key modified — new service or driver</description>
    <group>windows,fim,registry,</group>
  </rule>

  <!-- Hosts file change — DNS poisoning -->
  <rule id="100811" level="10">
    <if_sid>550</if_sid>
    <field name="file">drivers\\etc\\hosts</field>
    <description>win11-vm: Hosts file modified — possible DNS hijack</description>
    <group>windows,fim,dns,attack,</group>
  </rule>

  <!-- System32/drivers change — rootkit detection -->
  <rule id="100812" level="10">
    <if_sid>554</if_sid>
    <field name="file">System32\\drivers</field>
    <description>win11-vm: New file in System32\drivers — possible rootkit/driver install</description>
    <group>windows,fim,rootkit,</group>
  </rule>

  <!-- ── Account Management ─────────────────────────────────────────────── -->
  <!-- EventID 4720: New local account created -->
  <rule id="100813" level="8">
    <if_sid>60144</if_sid>
    <description>win11-vm: New local user account created (EventID 4720)</description>
    <group>windows,account_management,</group>
  </rule>

  <!-- EventID 4732: User added to local Administrators group -->
  <rule id="100814" level="10">
    <if_sid>60153</if_sid>
    <field name="win.system.message">Administrators</field>
    <description>win11-vm: User added to local Administrators group (EventID 4732)</description>
    <group>windows,account_management,privilege_escalation,</group>
  </rule>

  <!-- ── System Events ──────────────────────────────────────────────────── -->
  <!-- EventID 1102: Security audit log cleared — active attack indicator -->
  <rule id="100815" level="14">
    <if_sid>63103</if_sid>
    <description>win11-vm: CRITICAL — Security audit log cleared (EventID 1102)</description>
    <group>windows,audit,log_clear,attack,</group>
  </rule>

</group>
XML

chown wazuh:wazuh "$RULES_FILE"
echo "  Written: $RULES_FILE"
echo "  Rules: 100800–100815 (16 rules)"

# ── Step 5: Reload Wazuh manager ─────────────────────────────────────────────
echo ""
echo "=== Step 5: Reload Wazuh manager ==="
kill -HUP "$(cat $OSSEC/var/run/wazuh-analysisd.pid 2>/dev/null)" 2>/dev/null || \
  systemctl reload wazuh-manager 2>/dev/null || \
  systemctl restart wazuh-manager
echo "  Manager reloaded"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "=== Verification ==="
echo -n "  Group directory:    "
ls "$OSSEC/etc/shared/$GROUP/" | tr '\n' ' '
echo ""
echo -n "  Agent 004 group:    "
"$OSSEC/bin/agent_groups" -s -i "$AGENT_ID" 2>/dev/null | grep -oP "groups: \K.*" || echo "(not found)"
echo -n "  Rules file:         "
grep -c '<rule id' "$RULES_FILE" 2>/dev/null && echo " rules" || echo "error"
echo -n "  Manager status:     "
systemctl is-active wazuh-manager

echo ""
echo "============================================"
echo "  Done. Windows agent config active."
echo ""
echo "  Agent 004 (win11-vm @ 192.168.1.253)"
echo "  Group: windows"
echo "  Event logs: Security, System, Application,"
echo "              PowerShell, Defender, TaskScheduler"
echo "  FIM: Startup, System32/drivers, hosts file,"
echo "       Program Files, Registry Run/Services/Winlogon"
echo "  Rules: 100800-100815"
echo ""
echo "  NOTE: Agent will pull new config on next"
echo "  check-in (up to 10 min). Verify in Wazuh"
echo "  dashboard → Agents → 004 → Configuration."
echo "============================================"
