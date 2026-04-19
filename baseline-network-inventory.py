#!/usr/bin/env python3
"""
baseline-network-inventory.py
Establishes the current ARP table as the known-good device baseline.

Run once after deploying the inventory system. All devices currently visible
in network_devices.json are written into the state file as "baseline" entries.
Future collector runs will only fire new_device alerts for MACs NOT in this baseline.

Usage:
  python3 /opt/monitoring/baseline-network-inventory.py [--dry-run]
"""
import json, sys, datetime
from pathlib import Path

JSON_FILE  = Path("/opt/monitoring/data/network_devices.json")
STATE_FILE = Path("/opt/monitoring/data/network_inventory_state.json")
NAMES_FILE = Path("/opt/monitoring/device_names.json")

dry_run = "--dry-run" in sys.argv

# ── Load current ARP data ─────────────────────────────────────────────────────
try:
    devices = json.loads(JSON_FILE.read_text())
except Exception as e:
    print(f"ERROR: cannot read {JSON_FILE}: {e}")
    sys.exit(1)

# ── Load static hostname overrides ───────────────────────────────────────────
try:
    raw = json.loads(NAMES_FILE.read_text())
    names = {k: v for k, v in raw.items() if not k.startswith("_")}
except Exception:
    names = {}

# ── Check for existing state ──────────────────────────────────────────────────
existing_state = {}
if STATE_FILE.exists():
    try:
        existing_state = json.loads(STATE_FILE.read_text())
    except Exception:
        pass

existing_macs = set(existing_state.get("by_mac", {}).keys())
if existing_macs:
    print(f"WARNING: state file already has {len(existing_macs)} known MACs.")
    print("  Re-baselining will mark all current devices as baseline.")
    print("  Previously discovered (non-baseline) devices will be preserved.")
    print()

# ── Build new state from current ARP ─────────────────────────────────────────
now_ts  = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
by_mac  = existing_state.get("by_mac", {})
by_ip   = existing_state.get("by_ip",  {})

# Deduplicate: one entry per MAC
seen_macs = {}
for d in devices:
    mac = d.get("mac", "")
    if mac and mac not in seen_macs:
        hostname = d.get("hostname", "") or names.get(d["ip"], "")
        seen_macs[mac] = {
            "ip":           d["ip"],
            "hostname":     hostname,
            "vendor":       d.get("vendor", "unknown"),
            "vlan":         d.get("vlan", ""),
            "source":       "baseline",
            "baseline_set": now_ts,
            "first_seen":   by_mac.get(mac, {}).get("first_seen", now_ts),
            "last_seen":    now_ts,
        }

# Merge into state — baseline entries overwrite existing for same MAC
added   = 0
updated = 0
for mac, entry in seen_macs.items():
    if mac in by_mac:
        by_mac[mac].update(entry)
        updated += 1
    else:
        by_mac[mac] = entry
        added += 1
    by_ip[entry["ip"]] = mac

new_state = {"by_mac": by_mac, "by_ip": by_ip}

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"Baseline: {len(seen_macs)} devices ({added} new, {updated} already known)")
print()

# Print the full baseline table
from ipaddress import ip_address
sorted_entries = sorted(seen_macs.items(),
                        key=lambda x: (x[1]["vlan"], ip_address(x[1]["ip"])))

print(f"  {'IP':18s}  {'MAC':19s}  {'Hostname':25s}  {'Vendor':30s}  VLAN")
print(f"  {'-'*18}  {'-'*19}  {'-'*25}  {'-'*30}  ----")
for mac, e in sorted_entries:
    print(f"  {e['ip']:18s}  {mac:19s}  {e['hostname'] or '(unnamed)':25s}"
          f"  {e['vendor'][:30]:30s}  {e['vlan']}")

print()

if dry_run:
    print("DRY RUN — state file not written. Remove --dry-run to commit.")
    sys.exit(0)

# ── Write state ───────────────────────────────────────────────────────────────
tmp = STATE_FILE.with_suffix(".json.tmp")
tmp.write_text(json.dumps(new_state, indent=2))
tmp.replace(STATE_FILE)

print(f"Baseline committed → {STATE_FILE}")
print(f"  {len(by_mac)} total known MACs in state.")
print()
print("From this point on:")
print("  new_device  (level 6)  — fires only for MACs not in this baseline")
print("  arp_conflict (level 12) — fires if a known IP maps to a new MAC")
print("  dhcp_ip_changed (level 3) — fires when a known MAC gets a new IP (silent)")
print()
print("To add new authorized devices to the baseline later:")
print("  python3 /opt/monitoring/baseline-network-inventory.py")
print("  (re-run any time to fold the current ARP table into the baseline)")
