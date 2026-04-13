#!/usr/bin/env bash
set -euo pipefail

echo "=== Creating UDM Pro decoder ==="
cat > /var/ossec/etc/decoders/udm_firewall.xml << 'XML'
<!--
  UDM Pro / UniFi firewall log decoder
  Format: hostname [RULE_NAME] DESCR="..." IN=... OUT=... SRC=... DST=... PROTO=... SPT=... DPT=...
-->
<decoder name="udm-firewall">
  <prematch>] DESCR=</prematch>
  <regex offset="after_prematch">"(\S+)" IN=(\S+) OUT=(\S+) \S+ SRC=(\S+) DST=(\S+) \S+ \S+ \S+ \S+ \S+ PROTO=(\S+) SPT=(\d+) DPT=(\d+)</regex>
  <order>action, srcintf, dstintf, srcip, dstip, protocol, srcport, dstport</order>
</decoder>
XML
chown wazuh:wazuh /var/ossec/etc/decoders/udm_firewall.xml

echo "=== Creating UDM Pro rules ==="
cat > /var/ossec/etc/rules/udm_firewall.xml << 'XML'
<group name="udm,firewall,network,">

  <!-- Base: any UDM firewall event -->
  <rule id="100400" level="3">
    <decoded_as>udm-firewall</decoded_as>
    <description>UDM Firewall: $(action) | $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,</group>
  </rule>

  <!-- Allow rules (audit) -->
  <rule id="100401" level="3">
    <if_sid>100400</if_sid>
    <field name="action">^Allow</field>
    <description>UDM Allow: $(action) | $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,allowed,</group>
  </rule>

  <!-- Deny/Drop rules -->
  <rule id="100402" level="6">
    <if_sid>100400</if_sid>
    <field name="action">^Drop|^Deny|^Reject|^Block</field>
    <description>UDM Blocked: $(action) | $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,blocked,</group>
  </rule>

  <!-- Default policy deny -->
  <rule id="100403" level="5">
    <if_sid>100400</if_sid>
    <field name="action">^Default</field>
    <description>UDM Default Policy: $(protocol) $(srcip):$(srcport) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,default_policy,</group>
  </rule>

  <!-- High-value: traffic to/from internet on non-standard ports -->
  <rule id="100404" level="8">
    <if_sid>100402</if_sid>
    <field name="dstport">^(22|3389|445|139|23|21|25)$</field>
    <description>UDM Blocked suspicious port: $(protocol) $(srcip) -> $(dstip):$(dstport)</description>
    <group>udm,firewall,blocked,suspicious,</group>
  </rule>

  <!-- Multiple blocks from same source (potential scan) -->
  <rule id="100405" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100402</if_matched_sid>
    <same_source_ip/>
    <description>UDM: Possible port scan from $(srcip) — 10+ blocks in 60s</description>
    <group>udm,firewall,scan,</group>
  </rule>

</group>
XML
chown wazuh:wazuh /var/ossec/etc/rules/udm_firewall.xml

echo "=== Restarting Wazuh ==="
systemctl restart wazuh-manager

echo ""
echo "=== Done ==="
echo "  Decoder: /var/ossec/etc/decoders/udm_firewall.xml"
echo "  Rules:   /var/ossec/etc/rules/udm_firewall.xml (100400-100405)"
echo ""
echo "  Rule levels:"
echo "    100400 (3): Base firewall event"
echo "    100401 (3): Allow (audit)"
echo "    100402 (6): Block/Deny"
echo "    100403 (5): Default policy"
echo "    100404 (8): Blocked suspicious port"
echo "    100405 (10): Port scan detection (10+ blocks/min)"
