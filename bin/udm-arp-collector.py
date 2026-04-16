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
