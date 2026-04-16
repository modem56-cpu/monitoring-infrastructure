#!/usr/bin/env bash
set -euo pipefail

# Wire UDM ARP data into Akvorado network-sources enrichment.
# Extends udm-arp-collector to write JSON, adds HTTP server on :9117,
# updates Akvorado config with real subnets + per-device /32 source.
# Run as: sudo bash /opt/monitoring/deploy-akvorado-network-sources.sh

BINDIR="/opt/monitoring/bin"
DATADIR="/opt/monitoring/data"
AKVORADO_CFG="/opt/akvorado/config/akvorado.yaml"
JSON_PORT=9117
HOST_IP="247.16.14.1"   # Akvorado bridge gateway — reachable from all akvorado containers

mkdir -p "$DATADIR"

# ── 1. Patch udm-arp-collector to also write JSON ─────────────────────────────
cat > "$BINDIR/udm-arp-collector.py" << 'PYEOF'
#!/usr/bin/env python3
"""
UDM Pro ARP Collector — SNMP ARP table + OUI vendor + reverse DNS
Writes:
  /opt/monitoring/textfile_collector/network_devices.prom  (Prometheus)
  /opt/monitoring/data/network_devices.json                (Akvorado)
"""

import json, re, socket, subprocess, sys, time
from pathlib import Path
from collections import Counter

ROUTER       = "192.168.10.1"
COMMUNITY    = "public"
SNMP_VERSION = "2c"
PROM_FILE    = Path("/opt/monitoring/textfile_collector/network_devices.prom")
JSON_FILE    = Path("/opt/monitoring/data/network_devices.json")
OUI_FILE     = Path("/usr/share/ieee-data/oui.txt")
DNS_TIMEOUT  = 1.0

VLAN_LABELS = {
    "br0":  ("1",  "LAN"),
    "br10": ("10", "SecurityApps"),
    "br4":  ("4",  "VLAN4"),
    "br5":  ("5",  "Dev"),
}

def load_oui(path):
    oui = {}
    try:
        with path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)', line)
                if m:
                    oui[m.group(1).replace("-","").upper()] = m.group(2).strip()
    except Exception as e:
        print(f"WARN: OUI load failed: {e}", file=sys.stderr)
    return oui

def snmpwalk(oid):
    r = subprocess.run(
        ["snmpwalk", f"-v{SNMP_VERSION}", "-c", COMMUNITY, "-t", "5", "-r", "1",
         ROUTER, oid],
        capture_output=True, text=True, timeout=15
    )
    return r.stdout.splitlines()

def get_interfaces():
    ifaces = {}
    for line in snmpwalk("1.3.6.1.2.1.2.2.1.2"):
        m = re.match(r'.*\.(\d+)\s+=\s+STRING:\s+"(.+)"', line)
        if m:
            ifaces[m.group(1)] = m.group(2)
    return ifaces

def get_arp(ifaces, oui):
    entries = []
    for line in snmpwalk("1.3.6.1.2.1.4.22.1.2"):
        m = re.search(
            r'\.4\.22\.1\.2\.(\d+)\.(\d+\.\d+\.\d+\.\d+)\s+=\s+Hex-STRING:\s+(.+)', line
        )
        if not m:
            continue
        ifidx, ip, mac_hex = m.group(1), m.group(2), m.group(3)
        mac    = ":".join(mac_hex.strip().split()).lower()
        ifname = ifaces.get(ifidx, f"if{ifidx}")
        if ifname not in VLAN_LABELS:
            continue
        vlan_id, vlan_name = VLAN_LABELS[ifname]
        vendor = oui.get(mac.replace(":","")[:6].upper(), "unknown")
        entries.append({"ip": ip, "mac": mac, "vlan_id": vlan_id,
                        "vlan_name": vlan_name, "vendor": vendor})
    return entries

def rdns(ip):
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        host = socket.gethostbyaddr(ip)[0]
        # Strip .localdomain suffix — not useful in Akvorado
        return host.replace(".localdomain", "")
    except Exception:
        return ""

def esc(s):
    return s.replace("\\","\\\\").replace('"','\\"').replace("\n","\\n")

def write_prom(entries, elapsed):
    lines = [
        "# HELP network_device_info Device on LAN discovered via UDM Pro ARP (SNMP)",
        "# TYPE network_device_info gauge",
    ]
    seen = set()
    for e in entries:
        k = (e["ip"], e["vlan_id"])
        if k in seen:
            continue
        seen.add(k)
        lbl = (f'ip="{esc(e["ip"])}",'
               f'mac="{esc(e["mac"])}",'
               f'vlan_id="{esc(e["vlan_id"])}",'
               f'vlan="{esc(e["vlan_name"])}",'
               f'vendor="{esc(e["vendor"])}",'
               f'hostname="{esc(e["hostname"])}"')
        lines.append(f"network_device_info{{{lbl}}} 1")

    counts = Counter((e["vlan_id"], e["vlan_name"]) for e in entries)
    lines += ["",
              "# HELP network_device_count Active devices per VLAN",
              "# TYPE network_device_count gauge"]
    for (vid, vname), n in sorted(counts.items()):
        lines.append(f'network_device_count{{vlan_id="{vid}",vlan="{vname}"}} {n}')

    lines += ["",
              "# HELP network_arp_collector_last_run Unix timestamp of last successful run",
              "# TYPE network_arp_collector_last_run gauge",
              f"network_arp_collector_last_run {int(time.time())}",
              "",
              "# HELP network_arp_collector_duration_seconds Duration of last collection",
              "# TYPE network_arp_collector_duration_seconds gauge",
              f"network_arp_collector_duration_seconds {elapsed:.3f}",
              ""]
    tmp = PROM_FILE.with_suffix(".prom.tmp")
    tmp.write_text("\n".join(lines))
    tmp.replace(PROM_FILE)

def write_json(entries):
    """Write Akvorado-consumable JSON: array of device objects."""
    out = []
    seen = set()
    for e in entries:
        if e["ip"] in seen:
            continue
        seen.add(e["ip"])
        out.append({
            "ip":       e["ip"],
            "hostname": e["hostname"],
            "vendor":   e["vendor"],
            "vlan":     e["vlan_name"],
            "vlan_id":  e["vlan_id"],
            "mac":      e["mac"],
        })
    tmp = JSON_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, indent=2))
    tmp.replace(JSON_FILE)

def main():
    t0 = time.time()
    oui     = load_oui(OUI_FILE)
    ifaces  = get_interfaces()
    entries = get_arp(ifaces, oui)
    if not entries:
        print("ERROR: no ARP entries — check SNMP", file=sys.stderr)
        sys.exit(1)

    # Enrich with reverse DNS
    for e in entries:
        e["hostname"] = rdns(e["ip"])

    elapsed = time.time() - t0
    write_prom(entries, elapsed)
    write_json(entries)
    print(f"OK: {len(entries)} devices — prom+json written ({elapsed:.1f}s)")

if __name__ == "__main__":
    main()
PYEOF
chmod +x "$BINDIR/udm-arp-collector.py"

# ── 2. JSON HTTP server on port 9117 ─────────────────────────────────────────
cat > /etc/systemd/system/device-json-server.service << EOF
[Unit]
Description=Device JSON server for Akvorado network-sources (:${JSON_PORT})
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server ${JSON_PORT} --directory ${DATADIR} --bind 0.0.0.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now device-json-server.service

# Warm up JSON file before Akvorado restart
python3 "$BINDIR/udm-arp-collector.py"

# Verify JSON server is reachable
sleep 2
curl -s "http://127.0.0.1:${JSON_PORT}/network_devices.json" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(f'JSON server OK: {len(d)} devices')"

# ── 3. Update Akvorado config ─────────────────────────────────────────────────
python3 - "$AKVORADO_CFG" "$HOST_IP" "$JSON_PORT" << 'PYEOF'
import sys, re

cfg_path = sys.argv[1]
host_ip  = sys.argv[2]
port     = sys.argv[3]

with open(cfg_path) as f:
    content = f.read()

# Replace the entire clickhouse networks + network-sources block
old_block = re.search(
    r'clickhouse:.*?(?=^kafka:|^geoip:|^inlet:|^outlet:|^console:|$)',
    content, re.DOTALL | re.MULTILINE
)

new_clickhouse = f"""clickhouse:
  orchestrator-url: http://akvorado-orchestrator:8080
  prometheus-endpoint: /metrics
  asns:
    64501: ACME Corporation
  networks:
    192.168.1.0/24:
      name: LAN
      tenant: LAN
    192.168.10.0/24:
      name: SecurityApps
      tenant: SecurityApps
    192.168.5.0/24:
      name: Dev
      tenant: Dev
    192.168.4.0/24:
      name: VLAN4
      tenant: VLAN4
  network-sources:
    local-devices:
      url: http://{host_ip}:{port}/network_devices.json
      interval: 5m
      transform: |
        .[] |
        {{
          prefix: (.ip + "/32"),
          name: (if .hostname != "" then .hostname else .ip end),
          tenant: .vlan,
          role: .vendor
        }}

"""

if old_block:
    content = content[:old_block.start()] + new_clickhouse + content[old_block.end():]
else:
    # Append before inlet: !include line
    content = content.replace(
        'inlet: !include "inlet.yaml"',
        new_clickhouse + 'inlet: !include "inlet.yaml"'
    )

with open(cfg_path, "w") as f:
    f.write(content)

print(f"Akvorado config updated: {cfg_path}")
PYEOF

# ── 4. Restart Akvorado orchestrator to pick up new config ───────────────────
echo "Restarting Akvorado orchestrator..."
docker restart akvorado-akvorado-orchestrator-1

echo ""
echo "=== Waiting 10s for orchestrator to apply config ==="
sleep 10

echo ""
echo "=== Checking orchestrator logs ==="
docker logs akvorado-akvorado-orchestrator-1 --tail 15 2>&1

echo ""
echo "=== Verifying network-sources in ClickHouse (wait ~5min for first poll) ==="
echo "Run this to check after 5 min:"
echo "  docker exec akvorado-clickhouse-1 clickhouse-client \\"
echo "    --query \"SELECT SrcNetName, DstNetName, count() FROM default.flows_5m0s WHERE EventTime > now()-600 AND SrcNetName != '' GROUP BY SrcNetName, DstNetName ORDER BY count() DESC LIMIT 10\""
