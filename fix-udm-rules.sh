#!/usr/bin/env bash
set -euo pipefail

cat > /var/ossec/etc/rules/udm_firewall.xml << 'XML'
<group name="udm,firewall,network,">

  <rule id="100400" level="3">
    <decoded_as>udm-firewall</decoded_as>
    <description>UDM Firewall: $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,</group>
  </rule>

  <rule id="100401" level="3">
    <if_sid>100400</if_sid>
    <match>DESCR="Allow</match>
    <description>UDM Allow: $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,allowed,</group>
  </rule>

  <rule id="100402" level="6">
    <if_sid>100400</if_sid>
    <match>DESCR="Drop|DESCR="Deny|DESCR="Reject|DESCR="Block</match>
    <description>UDM Blocked: $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,blocked,</group>
  </rule>

  <rule id="100403" level="5">
    <if_sid>100400</if_sid>
    <match>DESCR="Default</match>
    <description>UDM Default Policy: $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,default_policy,</group>
  </rule>

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
