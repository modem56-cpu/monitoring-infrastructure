#!/usr/bin/env bash
set -euo pipefail

echo "=== Adding UDM Pro SNMP alert rules ==="
cat >> /opt/monitoring/rules/infrastructure.rules.yml << 'RULES'

  # --- UDM Pro (SNMP) ---
  - alert: UDM_Down
    expr: up{job="snmp_udm_pro"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "UDM Pro ({{ $labels.instance }}) SNMP unreachable"

  - alert: UDM_HighInterfaceUtilization
    expr: rate(ifHCInOctets{job="snmp_udm_pro"}[5m]) * 8 > 800000000
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "UDM Pro interface {{ $labels.ifDescr }} receiving > 800Mbps"
RULES

echo "=== Configuring Wazuh syslog listener ==="
CONF="/var/ossec/etc/ossec.conf"
if grep -q "192.168.10.1" "$CONF" 2>/dev/null && grep -q "<remote>" "$CONF" 2>/dev/null; then
  echo "  Syslog remote already configured"
else
  # Add remote syslog listener if not present
  if ! grep -q "<remote>" "$CONF" 2>/dev/null; then
    sed -i '/<\/ossec_config>/i \
  <!-- UDM Pro syslog ingestion -->\
  <remote>\
    <connection>syslog</connection>\
    <port>514</port>\
    <protocol>udp</protocol>\
    <allowed-ips>192.168.10.1</allowed-ips>\
  </remote>' "$CONF"
    echo "  Added syslog remote listener for 192.168.10.1"
  else
    echo "  Remote section exists, check manually"
  fi
fi

echo "=== Starting snmp-exporter + restarting Prometheus ==="
cd /opt/monitoring
docker compose up -d snmp-exporter prometheus 2>&1

echo "=== Restarting Wazuh manager ==="
systemctl restart wazuh-manager

echo ""
echo "=== Done ==="
echo "  SNMP exporter: snmp-exporter:9116"
echo "  UDM Pro scrape: every 60s via if_mib module"
echo "  Wazuh syslog: UDP 514 from 192.168.10.1"
echo ""
echo "  Configure UDM Pro syslog:"
echo "    Settings → System → Advanced → Remote Syslog"
echo "    Server: 192.168.10.20  Port: 514  Protocol: UDP"
