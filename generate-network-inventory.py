#!/usr/bin/env python3
"""
Network Device Inventory HTML Generator
Reads network_devices.json (ARP+OUI+hostname) and writes a searchable/sortable
inventory page to reports/network_inventory.html.
"""
import json, datetime, os, sys
from pathlib import Path

JSON_FILE = Path(os.environ.get("JSON_FILE", "/opt/monitoring/data/network_devices.json"))
OUT_FILE  = Path(os.environ.get("OUT_FILE",  "/opt/monitoring/reports/network_inventory.html"))

try:
    devices = json.loads(JSON_FILE.read_text())
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)

# Sort: named first, then by VLAN, then IP
from ipaddress import ip_address as ipa
devices.sort(key=lambda d: (
    0 if d.get("hostname") else 1,
    d.get("vlan", ""),
    ipa(d["ip"])
))

now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
named   = sum(1 for d in devices if d.get("hostname"))
unknown = len(devices) - named

VLAN_COLORS = {
    "LAN":           "#1e6fba",
    "SecurityApps":  "#b45309",
    "Dev":           "#166534",
    "VLAN4":         "#6b21a8",
}

def vlan_badge(vlan):
    color = VLAN_COLORS.get(vlan, "#334155")
    return f'<span class="badge" style="background:{color}20;border-color:{color}60;color:{color}">{vlan}</span>'

rows = ""
for d in devices:
    ip       = d.get("ip", "")
    mac      = d.get("mac", "")
    hostname = d.get("hostname", "")
    vendor   = d.get("vendor", "unknown")
    vlan     = d.get("vlan", "")
    named_cls = "" if hostname else ' style="opacity:0.55"'
    rows += f"""<tr{named_cls}>
      <td>{ip}</td>
      <td><span class="mono">{mac}</span></td>
      <td><b>{hostname}</b></td>
      <td>{vendor}</td>
      <td>{vlan_badge(vlan)}</td>
    </tr>\n"""

html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Network Inventory</title>
<meta http-equiv="refresh" content="300">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:Arial,Helvetica,sans-serif;background:#0b0f14;color:#e8eef7;padding:16px}}
  h1{{font-size:20px;margin-bottom:4px}}
  .meta{{opacity:.65;font-size:12px;margin-bottom:14px}}
  .card{{background:#121a24;border:1px solid #1f2a3a;border-radius:10px;padding:14px;margin-bottom:14px}}
  .stats{{display:flex;gap:24px;margin-bottom:14px;flex-wrap:wrap}}
  .stat{{background:#121a24;border:1px solid #1f2a3a;border-radius:8px;padding:10px 18px}}
  .stat .k{{opacity:.65;font-size:11px}}
  .stat .v{{font-size:22px;font-weight:700}}
  input{{background:#0e1520;border:1px solid #2b3a50;color:#e8eef7;padding:7px 12px;
         border-radius:6px;width:320px;font-size:13px;margin-bottom:10px;outline:none}}
  input:focus{{border-color:#3b82f6}}
  table{{width:100%;border-collapse:collapse}}
  th{{opacity:.65;font-size:11px;text-align:left;padding:6px 10px;border-bottom:1px solid #1f2a3a;
      cursor:pointer;user-select:none;white-space:nowrap}}
  th:hover{{opacity:1;color:#60a5fa}}
  td{{padding:6px 10px;border-bottom:1px solid #141e2c;font-size:13px;vertical-align:middle}}
  tr:hover td{{background:#161f2e}}
  .mono{{font-family:monospace;font-size:12px;color:#94a3b8}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid;font-size:11px;font-weight:600}}
  #count{{opacity:.65;font-size:12px;margin-bottom:8px}}
</style>
</head>
<body>

<h1>Network Device Inventory</h1>
<div class="meta">ARP table via UDM Pro SNMP · OUI vendor lookup · refreshes every 5 min &nbsp;|&nbsp; Generated: {now}</div>

<div class="stats">
  <div class="stat"><div class="k">TOTAL DEVICES</div><div class="v">{len(devices)}</div></div>
  <div class="stat"><div class="k">NAMED</div><div class="v" style="color:#4ade80">{named}</div></div>
  <div class="stat"><div class="k">UNNAMED</div><div class="v" style="color:#f59e0b">{unknown}</div></div>
</div>

<div class="card">
  <input type="text" id="search" placeholder="Search IP, MAC, hostname, vendor, VLAN…" oninput="filter()">
  <div id="count"></div>
  <table id="tbl">
    <thead>
      <tr>
        <th onclick="sort(0)">IP ⇅</th>
        <th onclick="sort(1)">MAC ⇅</th>
        <th onclick="sort(2)">Hostname ⇅</th>
        <th onclick="sort(3)">Vendor ⇅</th>
        <th onclick="sort(4)">VLAN ⇅</th>
      </tr>
    </thead>
    <tbody id="tbody">
{rows}
    </tbody>
  </table>
</div>

<script>
const tbody = document.getElementById('tbody');
const allRows = Array.from(tbody.querySelectorAll('tr'));
let sortCol = -1, sortAsc = true;

function filter() {{
  const q = document.getElementById('search').value.toLowerCase();
  let vis = 0;
  allRows.forEach(r => {{
    const match = !q || r.textContent.toLowerCase().includes(q);
    r.style.display = match ? '' : 'none';
    if (match) vis++;
  }});
  document.getElementById('count').textContent = q ? `${{vis}} of ${{allRows.length}} devices` : '';
}}

function sort(col) {{
  if (sortCol === col) sortAsc = !sortAsc;
  else {{ sortCol = col; sortAsc = true; }}
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {{
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    // IP sort numerically
    if (col === 0) {{
      const an = av.split('.').map(Number);
      const bn = bv.split('.').map(Number);
      for (let i=0;i<4;i++) {{ if (an[i]!==bn[i]) return sortAsc ? an[i]-bn[i] : bn[i]-an[i]; }}
      return 0;
    }}
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

filter();
</script>
</body>
</html>
"""

OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUT_FILE.write_text(html)
print(f"OK: {len(devices)} devices → {OUT_FILE} ({named} named, {unknown} unnamed)")
