#!/usr/bin/env bash
set -euo pipefail

# Rules that build on existing 100010 base rule
cat > /var/ossec/etc/rules/udm_firewall.xml << 'XML'
<group name="udm,firewall,network,">

  <!-- Allow rules (audit) — child of existing 100010 -->
  <rule id="100401" level="3">
    <if_sid>100010</if_sid>
    <match>DESCR="Allow</match>
    <description>UDM Allow: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,allowed,</group>
  </rule>

  <!-- Deny/Drop rules -->
  <rule id="100402" level="6">
    <if_sid>100010</if_sid>
    <match>DESCR="Drop</match>
    <description>UDM Blocked: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,blocked,</group>
  </rule>

  <rule id="100406" level="6">
    <if_sid>100010</if_sid>
    <match>DESCR="Deny</match>
    <description>UDM Denied: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,blocked,</group>
  </rule>

  <rule id="100407" level="6">
    <if_sid>100010</if_sid>
    <match>DESCR="Reject</match>
    <description>UDM Rejected: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,blocked,</group>
  </rule>

  <!-- Default policy -->
  <rule id="100403" level="5">
    <if_sid>100010</if_sid>
    <match>DESCR="Default</match>
    <description>UDM Default Policy: $(srcip) -> $(dstip)</description>
    <group>udm,firewall,default_policy,</group>
  </rule>

  <!-- Port scan detection: 10+ blocks in 60s -->
  <rule id="100405" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100402</if_matched_sid>
    <same_source_ip/>
    <description>UDM: Possible port scan from $(srcip) — 10+ blocks in 60s</description>
    <group>udm,firewall,scan,</group>
  </rule>

</group>
XML

chown wazuh:wazuh /var/ossec/etc/rules/udm_firewall.xml
systemctl restart wazuh-manager && echo "OK — Wazuh restarted"
