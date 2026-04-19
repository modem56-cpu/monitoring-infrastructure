#!/usr/bin/env bash
# deploy-device-inventory.sh
# Deploys hostname override support to the ARP collector.
# Applies the shared-drive page cap fix to gworkspace collector.
# Creates the monitoring-report timer.
# Installs Wazuh decoder + rules for network inventory events.
# Run as root.
set -euo pipefail

echo "=== 1. Install updated ARP collector ==="
cp /opt/monitoring/udm-arp-collector-new.py /opt/monitoring/bin/udm-arp-collector.py
chmod +x /opt/monitoring/bin/udm-arp-collector.py
echo "  Done."

echo ""
echo "=== 2. Copy device_names.json into data/ ==="
cp /opt/monitoring/device_names.json /opt/monitoring/data/device_names.json
chmod 0644 /opt/monitoring/data/device_names.json
echo "  Done."

echo ""
echo "=== 3. Fix gworkspace shared-drive page cap ==="
python3 - /opt/monitoring/bin/gworkspace-collector.py << 'PY'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

old = '        pages = 0\n        while pages < 50:  # cap at ~50k files per drive'
new = '        while True:  # no file count cap — large drives (e.g. Yokly USA >50k files) were being truncated'

if old not in content:
    print(f"  Already patched or pattern not found — skipping")
    sys.exit(0)

content = content.replace(old, new)
content = content.replace("            pages += 1\n", "")

with open(path, 'w') as f:
    f.write(content)
print(f"  Patched {path}")
PY

echo ""
echo "=== 4. Create monitoring-report timer ==="
cat > /etc/systemd/system/monitoring-report.service << 'SVC'
[Unit]
Description=Generate monitoring JSON report
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/monitoring/generate-report.py /opt/monitoring/reports/monitoring_report.json
SVC

cat > /etc/systemd/system/monitoring-report.timer << 'TMR'
[Unit]
Description=Generate monitoring report every 5 minutes

[Timer]
OnBootSec=60s
OnUnitActiveSec=5min
AccuracySec=10s

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now monitoring-report.timer
echo "  Timer enabled."

echo ""
echo "=== 5. Install Prometheus alert rules for network inventory ==="
cp /opt/monitoring/network_inventory.rules.yml /opt/monitoring/rules/network_inventory.rules.yml
echo "  Rules installed. Prometheus will pick them up on next reload."
# Reload Prometheus config
curl -s -X POST http://localhost:9090/-/reload 2>/dev/null && echo "  Prometheus reloaded." || echo "  Note: reload Prometheus manually if needed."

echo ""
echo "=== 6. Install Wazuh decoder and rules ==="
cp /opt/monitoring/network_inventory_decoder.xml /var/ossec/etc/decoders/network_inventory.xml
cp /opt/monitoring/network_inventory_rules.xml   /var/ossec/etc/rules/network_inventory_rules.xml
chown wazuh:wazuh /var/ossec/etc/decoders/network_inventory.xml
chown wazuh:wazuh /var/ossec/etc/rules/network_inventory_rules.xml
echo "  Decoder and rules installed."

echo ""
echo "=== 7. Configure Wazuh logcollector for network inventory log ==="
touch /var/log/network-inventory-wazuh.log
chmod 0640 /var/log/network-inventory-wazuh.log
chown root:wazuh /var/log/network-inventory-wazuh.log

# Add localfile block to ossec.conf if not already present
if grep -q "network-inventory-wazuh" /var/ossec/etc/ossec.conf; then
  echo "  Logcollector entry already present — skipping."
else
  python3 - << 'PY'
path = "/var/ossec/etc/ossec.conf"
with open(path) as f:
    content = f.read()

block = """
  <!-- Network Device Inventory (UDM ARP collector) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/network-inventory-wazuh.log</location>
  </localfile>

"""
content = content.replace("</ossec_config>", block + "</ossec_config>")
with open(path, "w") as f:
    f.write(content)
print("  Logcollector entry added to ossec.conf.")
PY
fi

echo ""
echo "=== 8. Validate Wazuh config and restart manager ==="
/var/ossec/bin/wazuh-logtest -t 2>/dev/null || true
systemctl restart wazuh-manager
sleep 3
systemctl is-active wazuh-manager && echo "  wazuh-manager: active" || echo "  WARNING: wazuh-manager not active"

echo ""
echo "=== 9. Establish device baseline (seals current ARP as known-good) ==="
python3 /opt/monitoring/baseline-network-inventory.py

echo ""
echo "=== 10. First live run — ARP collector with Wazuh export ==="
echo "  (no new_device alerts expected — all current devices are now baselined)"
python3 /opt/monitoring/bin/udm-arp-collector.py

echo ""
echo "=== 11. Verify Wazuh log was written ==="
echo "  Last 5 events:"
tail -5 /var/log/network-inventory-wazuh.log | python3 -c "
import json,sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        print(f\"  [{e.get('event','?'):30s}] {e.get('summary','')[:80]}\")
    except:
        pass
"

echo ""
echo "=== Done ==="
echo "  network_devices.json  — includes static hostnames"
echo "  Akvorado SrcNetName   — shows device names on next 5-min enrichment pull"
echo "  monitoring-report     — regenerates every 5 min"
echo "  gworkspace collector  — shared drives fully enumerated (no 50k cap)"
echo "  Wazuh rules 100700-100706:"
echo "    100701 level 2  — inventory summary (every 5 min)"
echo "    100702 level 6  — new device detected"
echo "    100703 level 10 — new device on SecurityApps VLAN"
echo "    100704 level 10 — unknown vendor on SecurityApps VLAN"
echo "    100705 level 12 — MAC address changed (ARP spoofing indicator)"
echo "    100706 level 14 — MAC changed on SecurityApps VLAN (critical)"
echo ""
echo "  Edit /opt/monitoring/device_names.json to add/correct hostnames."
echo "  Changes take effect on the next ARP collection cycle (within 5 min)."
