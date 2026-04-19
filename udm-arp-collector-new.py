#!/usr/bin/env python3
"""
UDM Pro ARP Collector — SNMP ARP table + OUI vendor + reverse DNS
                        + static hostname overrides + Wazuh JSON export
Writes:
  /opt/monitoring/textfile_collector/network_devices.prom  (Prometheus)
  /opt/monitoring/data/network_devices.json                (Akvorado + inventory)
  /opt/monitoring/data/network_inventory_state.json        (state: new device / MAC change detection)
  /var/log/network-inventory-wazuh.log                     (Wazuh JSON ingest)
"""

import json, re, socket, subprocess, sys, time, datetime
from pathlib import Path
from collections import Counter

ROUTER       = "192.168.10.1"
COMMUNITY    = "public"
SNMP_VERSION = "2c"
PROM_FILE    = Path("/opt/monitoring/textfile_collector/network_devices.prom")
JSON_FILE    = Path("/opt/monitoring/data/network_devices.json")
STATE_FILE   = Path("/opt/monitoring/data/network_inventory_state.json")
NAMES_FILE   = Path("/opt/monitoring/device_names.json")
WAZUH_LOG    = Path("/var/log/network-inventory-wazuh.log")
OUI_FILE     = Path("/usr/share/ieee-data/oui.txt")
DNS_TIMEOUT  = 1.0

# VLANs considered sensitive — unknown devices here get flagged
SENSITIVE_VLANS = {"SecurityApps"}

VLAN_LABELS = {
    "br0":  ("1",  "LAN"),
    "br10": ("10", "SecurityApps"),
    "br4":  ("4",  "VLAN4"),
    "br5":  ("5",  "Dev"),
}

# ── helpers ──────────────────────────────────────────────────────────────────

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

def load_names(path):
    try:
        raw = json.loads(path.read_text())
        return {k: v for k, v in raw.items() if not k.startswith("_")}
    except Exception as e:
        print(f"WARN: device_names.json load failed: {e}", file=sys.stderr)
        return {}

def load_state(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}

def save_state(path, state):
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(path)

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
        return host.replace(".localdomain", "")
    except Exception:
        return ""

def esc(s):
    return s.replace("\\","\\\\").replace('"','\\"').replace("\n","\\n")

# ── Wazuh events ─────────────────────────────────────────────────────────────

wazuh_events = []

def wazuh_emit(event_type, level, summary, **fields):
    evt = {
        "timestamp": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source":    "network_inventory",
        "event":     event_type,
        "level":     level,
        "summary":   summary,
    }
    evt.update(fields)
    wazuh_events.append(json.dumps(evt))

def flush_wazuh():
    if not wazuh_events:
        return
    try:
        with WAZUH_LOG.open("a") as f:
            for e in wazuh_events:
                f.write(e + "\n")
    except Exception as ex:
        print(f"WARN: wazuh log write failed: {ex}", file=sys.stderr)

# ── state diffing ─────────────────────────────────────────────────────────────

def diff_and_update(entries, state):
    """
    MAC-centric state tracking — correct for DHCP environments.

    State structure:
      by_mac: {mac → {ip, hostname, vendor, vlan, first_seen, last_seen}}
      by_ip:  {ip  → mac}   ← secondary index for ARP conflict detection

    Events emitted:
      new_device              : new MAC never seen before (real new device)
      dhcp_ip_changed         : known MAC, IP changed (normal DHCP renewal)
      arp_conflict            : known IP now maps to a different MAC (spoofing risk)
      unknown_device_sensitive_vlan : unknown vendor first seen on sensitive VLAN
      inventory_summary       : per-run totals
    """
    now_ts        = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_count     = 0
    ip_change_count = 0
    arp_conflict_count = 0

    by_mac         = state.get("by_mac", {})
    by_ip          = state.get("by_ip",  {})
    conflict_log   = state.get("arp_conflicts", [])

    # Deduplicate: one entry per MAC (first seen wins if duplicated across VLANs)
    seen_macs = {}
    for e in entries:
        if e["mac"] not in seen_macs:
            seen_macs[e["mac"]] = e

    for mac, e in seen_macs.items():
        ip       = e["ip"]
        hostname = e.get("hostname", "")
        vendor   = e["vendor"]
        vlan     = e["vlan_name"]

        # ── ARP conflict: known IP now has a different MAC ──────────────────
        prev_mac_for_ip = by_ip.get(ip)
        if prev_mac_for_ip and prev_mac_for_ip != mac:
            arp_conflict_count += 1
            prev_entry = by_mac.get(prev_mac_for_ip, {})
            wazuh_emit(
                "arp_conflict", "warning",
                f"ARP conflict: {ip} was {prev_mac_for_ip} ({prev_entry.get('vendor','?')})"
                f" → now {mac} ({vendor}) on {vlan}",
                ip=ip, old_mac=prev_mac_for_ip, new_mac=mac,
                old_vendor=prev_entry.get("vendor", ""),
                hostname=hostname, vendor=vendor,
                vlan=vlan, vlan_id=e["vlan_id"],
            )
            # Persist conflict event for Prometheus/Grafana audit trail
            conflict_log.append({
                "timestamp": now_ts, "ip": ip,
                "old_mac": prev_mac_for_ip, "new_mac": mac,
                "old_vendor": prev_entry.get("vendor", ""), "vendor": vendor,
                "vlan": vlan,
            })
            conflict_log = conflict_log[-200:]  # keep last 200 events

        # ── New MAC — physically new device ─────────────────────────────────
        if mac not in by_mac:
            new_count += 1
            wazuh_emit(
                "new_device", "info",
                f"New device: {ip} MAC={mac} ({hostname or vendor}) VLAN={vlan}",
                ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                vlan=vlan, vlan_id=e["vlan_id"],
            )
            if vendor == "unknown" and vlan in SENSITIVE_VLANS:
                wazuh_emit(
                    "unknown_device_sensitive_vlan", "warning",
                    f"Unknown vendor device on sensitive VLAN {vlan}: {ip} ({mac})",
                    ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                    vlan=vlan, vlan_id=e["vlan_id"],
                )

        # ── Known MAC, IP changed — normal DHCP renewal ─────────────────────
        elif by_mac[mac].get("ip") != ip:
            ip_change_count += 1
            old_ip = by_mac[mac].get("ip", "?")
            wazuh_emit(
                "dhcp_ip_changed", "info",
                f"DHCP IP change: {mac} ({hostname or vendor}) {old_ip} → {ip} on {vlan}",
                mac=mac, old_ip=old_ip, new_ip=ip,
                hostname=hostname, vendor=vendor,
                vlan=vlan, vlan_id=e["vlan_id"],
            )

        # ── Update state ─────────────────────────────────────────────────────
        first_seen = by_mac.get(mac, {}).get("first_seen", now_ts)
        by_mac[mac] = {
            "ip": ip, "hostname": hostname, "vendor": vendor,
            "vlan": vlan, "first_seen": first_seen, "last_seen": now_ts,
        }
        by_ip[ip] = mac

    total   = len(seen_macs)
    named   = sum(1 for e in seen_macs.values() if e.get("hostname"))
    unnamed = total - named

    wazuh_emit(
        "inventory_summary", "info",
        f"Network inventory: {total} devices ({named} named, {unnamed} unnamed) — "
        f"{new_count} new, {ip_change_count} DHCP changes, {arp_conflict_count} ARP conflicts",
        total=total, named=named, unnamed=unnamed,
        new_this_run=new_count, dhcp_changes=ip_change_count,
        arp_conflicts=arp_conflict_count,
    )

    return {"by_mac": by_mac, "by_ip": by_ip, "arp_conflicts": conflict_log}

# ── output writers ────────────────────────────────────────────────────────────

def write_prom_inventory_state(state):
    """
    Write inventory audit metrics derived from the state file.
    These power the Grafana audit dashboard and Prometheus alert rules.

    Emits:
      network_inventory_baseline_total        — devices in baseline
      network_inventory_discovered_total      — post-baseline new devices
      network_inventory_arp_conflicts_total   — ARP conflicts ever recorded
      network_inventory_discovered_device{}   — per-device gauge for table panels
      network_inventory_arp_conflict_event{}  — per-conflict gauge with timestamp
    """
    by_mac = state.get("by_mac", {})

    baseline_devices    = [e for e in by_mac.values() if e.get("source") == "baseline"]
    discovered_devices  = [e for e in by_mac.values() if e.get("source") != "baseline"]
    conflict_events     = state.get("arp_conflicts", [])

    lines = [
        "# HELP network_inventory_baseline_total Devices in the known-good baseline",
        "# TYPE network_inventory_baseline_total gauge",
        f"network_inventory_baseline_total {len(baseline_devices)}",
        "",
        "# HELP network_inventory_discovered_total New devices seen after baseline was set",
        "# TYPE network_inventory_discovered_total gauge",
        f"network_inventory_discovered_total {len(discovered_devices)}",
        "",
        "# HELP network_inventory_arp_conflicts_total ARP conflicts detected (possible spoofing)",
        "# TYPE network_inventory_arp_conflicts_total gauge",
        f"network_inventory_arp_conflicts_total {len(conflict_events)}",
        "",
    ]

    # Per-discovered-device — shows up as a table in Grafana
    if discovered_devices:
        lines += [
            "# HELP network_inventory_discovered_device Post-baseline device (value = first_seen unix ts)",
            "# TYPE network_inventory_discovered_device gauge",
        ]
        for mac, e in by_mac.items():
            if e.get("source") == "baseline":
                continue
            # Convert ISO timestamp to unix for Grafana time display
            try:
                import calendar
                dt = datetime.datetime.strptime(e["first_seen"], "%Y-%m-%dT%H:%M:%SZ")
                ts = int(calendar.timegm(dt.timetuple()))
            except Exception:
                ts = 0
            lbl = (f'mac="{esc(mac)}",'
                   f'ip="{esc(e.get("ip",""))}",'
                   f'hostname="{esc(e.get("hostname",""))}",'
                   f'vendor="{esc(e.get("vendor","unknown"))}",'
                   f'vlan="{esc(e.get("vlan",""))}"')
            lines.append(f"network_inventory_discovered_device{{{lbl}}} {ts}")
        lines.append("")

    # Per-ARP-conflict event — table of conflicts with timestamps
    if conflict_events:
        lines += [
            "# HELP network_inventory_arp_conflict_event ARP conflict event (value = unix ts)",
            "# TYPE network_inventory_arp_conflict_event gauge",
        ]
        for evt in conflict_events[-50:]:  # keep last 50
            try:
                import calendar
                dt = datetime.datetime.strptime(evt["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
                ts = int(calendar.timegm(dt.timetuple()))
            except Exception:
                ts = 0
            lbl = (f'ip="{esc(evt.get("ip",""))}",'
                   f'old_mac="{esc(evt.get("old_mac",""))}",'
                   f'new_mac="{esc(evt.get("new_mac",""))}",'
                   f'vendor="{esc(evt.get("vendor",""))}",'
                   f'vlan="{esc(evt.get("vlan",""))}"')
            lines.append(f"network_inventory_arp_conflict_event{{{lbl}}} {ts}")
        lines.append("")

    # Append to the existing prom file (network_device_info is written first)
    with PROM_FILE.open("a") as f:
        f.write("\n".join(lines) + "\n")

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

def write_inventory_stdout(entries, elapsed):
    from ipaddress import ip_address
    named   = sum(1 for e in entries if e.get("hostname"))
    unnamed = len(entries) - named
    print(f"OK: {len(entries)} devices ({named} named, {unnamed} unnamed) — {elapsed:.1f}s")
    for e in sorted(entries, key=lambda e: (e["vlan_name"], ip_address(e["ip"]))):
        tag = "  " if e["hostname"] else "? "
        print(f"  {tag}{e['ip']:18s}  {e['mac']:19s}  {e.get('hostname') or '':25s}"
              f"  {e['vendor'][:30]}  [{e['vlan_name']}]")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    t0      = time.time()
    oui     = load_oui(OUI_FILE)
    names   = load_names(NAMES_FILE)
    state   = load_state(STATE_FILE)
    ifaces  = get_interfaces()
    entries = get_arp(ifaces, oui)

    if not entries:
        print("ERROR: no ARP entries — check SNMP", file=sys.stderr)
        sys.exit(1)

    # Enrich: rDNS → static override fallback
    for e in entries:
        hostname = rdns(e["ip"])
        if not hostname:
            hostname = names.get(e["ip"], "")
        e["hostname"] = hostname

    elapsed = time.time() - t0

    # Diff against state → build Wazuh events
    updated_state = diff_and_update(entries, state)

    # Write all outputs
    write_prom(entries, elapsed)             # network_device_info + per-VLAN counts
    write_prom_inventory_state(updated_state)  # audit metrics: discovered/conflicts
    write_json(entries)
    save_state(STATE_FILE, updated_state)
    flush_wazuh()
    write_inventory_stdout(entries, elapsed)

if __name__ == "__main__":
    main()
