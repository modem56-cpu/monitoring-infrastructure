#!/usr/bin/env bash
set -euo pipefail

echo "=== Updating Google Workspace collector ==="
cp /opt/monitoring/gworkspace-collector-v2.py /opt/monitoring/bin/gworkspace-collector.py
chmod +x /opt/monitoring/bin/gworkspace-collector.py
echo "  Collector updated (removed 2FA, added 50GB storage monitoring)"

echo ""
echo "=== Updating Wazuh rules ==="
cat > /var/ossec/etc/rules/google_workspace.xml << 'XML'
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
    <description>Google Workspace: User over 50GB storage quota — $(summary)</description>
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
    <description>Google Workspace: Storage quota violation summary — $(summary)</description>
    <group>google_workspace,storage,compliance,</group>
  </rule>

</group>
XML
chown wazuh:wazuh /var/ossec/etc/rules/google_workspace.xml
echo "  Rules updated (added over_quota + quota_summary rules)"

echo ""
echo "=== Restarting Wazuh ==="
systemctl restart wazuh-manager

echo ""
echo "=== Test run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Done ==="
echo "  Changes:"
echo "    - Removed 2FA compliance check"
echo "    - Added 50GB Drive storage monitoring per user"
echo "    - Exempt users: dan@agapay, calvin@yokly, it_dept@yokly, dm@yokly, tim@agapay, eddie@agapay"
echo "    - Wazuh rule 100506: user over quota alert"
echo "    - Wazuh rule 100508: quota summary alert"
echo "    - Prometheus: gworkspace_drive_usage_bytes, gworkspace_drive_over_quota, gworkspace_drive_users_over_quota"
