#!/usr/bin/env bash
set -euo pipefail
#
# deploy-security-enhancements.sh
# Adds: FIM tuning, auditd rules, agent-shared config
# Run as: sudo bash /opt/monitoring/deploy-security-enhancements.sh
#

OSSEC="/var/ossec"

echo "============================================"
echo "  Security Enhancements Deployment"
echo "============================================"

# ============================================================
# 1. FIM: Add missing high-value directories to manager
# ============================================================
echo ""
echo "=== Step 1: Tune FIM (syscheck) ==="

# Add directories if not already present
CONF="$OSSEC/etc/ossec.conf"

add_fim_dir() {
  local path="$1"
  local opts="${2:-}"
  if grep -q ">${path}<" "$CONF" 2>/dev/null; then
    echo "  FIM: $path already monitored"
  else
    # Insert before </syscheck>
    sed -i "/<\/syscheck>/i\\    <directories check_all=\"yes\" realtime=\"yes\" report_changes=\"yes\">${path}</directories>" "$CONF"
    echo "  FIM: Added $path (realtime + report_changes)"
  fi
}

add_fim_dir "/root/.ssh"
add_fim_dir "/home/wazuh-admin/.ssh"
add_fim_dir "/var/spool/cron/crontabs"
add_fim_dir "/etc/wireguard"
add_fim_dir "/opt/monitoring/docker-compose.yml"
add_fim_dir "/opt/monitoring/prometheus.yml"

echo "  FIM tuning complete."

# ============================================================
# 2. Shared agent config: FIM + auditd for all agents
# ============================================================
echo ""
echo "=== Step 2: Create shared agent config ==="

SHARED="$OSSEC/etc/shared/default/agent.conf"
if [ ! -f "$SHARED" ] || ! grep -q "auditd" "$SHARED" 2>/dev/null; then
  cat > "$SHARED" << 'AGENTCONF'
<agent_config>

  <!-- FIM: High-value directories for all agents -->
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/var/spool/cron/crontabs</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/crontab</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers.d</directories>
    <directories check_all="yes" realtime="yes">/etc/wireguard</directories>
  </syscheck>

  <!-- Auditd log collection -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- Docker daemon logs -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/docker.log</location>
  </localfile>

</agent_config>
AGENTCONF
  chown wazuh:wazuh "$SHARED"
  echo "  Shared agent config written."
else
  echo "  Shared agent config already has auditd, skipping."
fi

# ============================================================
# 3. Install and configure auditd on this host
# ============================================================
echo ""
echo "=== Step 3: Install auditd ==="

if ! command -v auditd &>/dev/null; then
  apt-get update -qq && apt-get install -y -qq auditd audispd-plugins
  echo "  auditd installed."
else
  echo "  auditd already installed."
fi

echo "=== Step 4: Configure audit rules ==="
cat > /etc/audit/rules.d/wazuh-security.rules << 'AUDIT'
## Wazuh Security Audit Rules

# Self-auditing — detect attempts to tamper with audit
-w /var/log/audit/ -p wa -k audit_log_access
-w /etc/audit/ -p wa -k audit_config_change
-w /sbin/auditctl -p x -k audit_tool
-w /sbin/auditd -p x -k audit_tool

# Identity and access
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/gshadow -p wa -k identity_change
-w /etc/sudoers -p wa -k sudo_change
-w /etc/sudoers.d/ -p wa -k sudo_change

# SSH keys
-w /root/.ssh/ -p wa -k ssh_key_change
-w /home/ -p wa -k home_dir_change

# Login and authentication
-w /var/log/faillog -p wa -k login_failures
-w /var/log/lastlog -p wa -k login_records
-w /var/run/utmp -p wa -k session_records
-w /var/log/wtmp -p wa -k session_records
-w /var/log/btmp -p wa -k session_records

# Privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k root_command

# User/group management commands
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k group_mgmt
-w /usr/sbin/groupdel -p x -k group_mgmt
-w /usr/sbin/groupmod -p x -k group_mgmt

# Cron changes
-w /etc/crontab -p wa -k cron_change
-w /etc/cron.d/ -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change

# Systemd service changes
-w /etc/systemd/system/ -p wa -k systemd_change
-w /usr/lib/systemd/system/ -p wa -k systemd_change

# Network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
-w /etc/netplan/ -p wa -k network_config

# WireGuard
-w /etc/wireguard/ -p wa -k vpn_config

# Docker
-w /usr/bin/docker -p x -k docker_command
-w /etc/docker/ -p wa -k docker_config

# Kernel module loading
-a always,exit -F arch=b64 -S init_module,finit_module -k kernel_module
-a always,exit -F arch=b32 -S init_module,finit_module -k kernel_module
AUDIT

echo "  Audit rules written to /etc/audit/rules.d/wazuh-security.rules"

# Reload audit rules
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/wazuh-security.rules 2>/dev/null
systemctl enable auditd
systemctl restart auditd

echo "  auditd restarted with new rules."

# ============================================================
# 4. Wazuh Active Response — auto-block repeated SSH brute force
# ============================================================
echo ""
echo "=== Step 5: Configure Active Response ==="

if grep -q "firewall-drop" "$CONF" 2>/dev/null; then
  echo "  Active response (firewall-drop) already configured."
else
  sed -i "/<\/ossec_config>/i\\
  <!-- Active Response: block SSH brute force (5 failures in 3 min) -->\\
  <active-response>\\
    <command>firewall-drop</command>\\
    <location>local</location>\\
    <rules_id>5763</rules_id>\\
    <timeout>3600</timeout>\\
  </active-response>" "$CONF"
  echo "  Active response added: firewall-drop on rule 5763 (SSH brute force), 1hr block."
fi

# ============================================================
# 5. Restart Wazuh Manager
# ============================================================
echo ""
echo "=== Step 6: Restart Wazuh Manager ==="
systemctl restart wazuh-manager
echo "  Wazuh manager restarted."

echo ""
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo ""
echo "  Enhancements applied:"
echo "    [x] FIM: +6 high-value directories (SSH keys, cron, WireGuard, compose)"
echo "    [x] Shared agent config: FIM + auditd log collection for all agents"
echo "    [x] auditd: 20+ rules (identity, SSH, priv-esc, cron, systemd, docker, VPN)"
echo "    [x] Active Response: auto-block SSH brute force (1hr)"
echo ""
echo "  Next steps for remote agents:"
echo "    - Install auditd: sudo apt install auditd"
echo "    - Copy /etc/audit/rules.d/wazuh-security.rules to each agent"
echo "    - Or let Wazuh shared config push the audit log collection"
echo ""
echo "  Verify:"
echo "    sudo ausearch -k identity_change --start recent"
echo "    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep audit"
