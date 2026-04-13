#!/usr/bin/env bash
set -euo pipefail

PROM="http://127.0.0.1:9090"
OUT="/opt/monitoring/reports/vps_movement_strategy.html"
TARGET="31.170.165.94"
ALIAS="movement-strategy"

python3 - <<'PY'
import json, urllib.parse, urllib.request, datetime, html, math

PROM="http://127.0.0.1:9090"
OUT="/opt/monitoring/reports/vps_movement_strategy.html"
TARGET="31.170.165.94"
ALIAS="movement-strategy"

def q(query: str):
    url = PROM + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    with urllib.request.urlopen(url, timeout=8) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data.get("data", {}).get("result", [])

def one(query: str):
    r = q(query)
    if not r: return None
    try: return float(r[0]["value"][1])
    except Exception: return None

def esc(s): return html.escape("" if s is None else str(s))
def fmt(x, nd=1): return "—" if x is None or (isinstance(x,float) and math.isnan(x)) else f"{x:.{nd}f}"
def b2g(x): return x/1024/1024/1024
def b2m(x): return x/1024/1024
def bps(x):
    if x is None or x < 0: return "—"
    # keep it simple but readable
    if x < 1024: return f"{int(x)} B/s"
    if x < 1024**2: return f"{x/1024:.1f} KiB/s"
    if x < 1024**3: return f"{x/1024/1024:.2f} MiB/s"
    return f"{x/1024/1024/1024:.2f} GiB/s"

now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Core status
up = one(f'vps_ssh_up{{target="{TARGET}"}}')
ssh_total = one(f'vps_ssh_sessions{{target="{TARGET}"}}')
dock_run = one(f'vps_docker_running{{target="{TARGET}"}}')
dock_tot = one(f'vps_docker_total{{target="{TARGET}"}}')

# System stats
cpu_busy = one(f'vps_cpu_busy_percent{{target="{TARGET}"}}')
uptime = one(f'vps_uptime_seconds{{target="{TARGET}"}}')
load1 = one(f'vps_load1{{target="{TARGET}"}}')
root_pct = one(f'vps_rootfs_used_percent{{target="{TARGET}"}}')

mem_total = one(f'vps_mem_total_bytes{{target="{TARGET}"}}')
mem_avail = one(f'vps_mem_avail_bytes{{target="{TARGET}"}}')
mem_cache = one(f'vps_mem_cache_bytes{{target="{TARGET}"}}')

swap_total = one(f'vps_swap_total_bytes{{target="{TARGET}"}}')
swap_used = one(f'vps_swap_used_bytes{{target="{TARGET}"}}')
swap_pct  = one(f'vps_swap_used_percent{{target="{TARGET}"}}')

net_rx_s = one(f'vps_net_rx_bytes_per_sec{{target="{TARGET}"}}')
net_tx_s = one(f'vps_net_tx_bytes_per_sec{{target="{TARGET}"}}')
net_rx_t = one(f'vps_net_rx_bytes_total{{target="{TARGET}"}}')
net_tx_t = one(f'vps_net_tx_bytes_total{{target="{TARGET}"}}')

disk_r_s = one(f'vps_disk_read_bytes_per_sec{{target="{TARGET}"}}')
disk_w_s = one(f'vps_disk_write_bytes_per_sec{{target="{TARGET}"}}')
disk_r_t = one(f'vps_disk_read_bytes_total{{target="{TARGET}"}}')
disk_w_t = one(f'vps_disk_write_bytes_total{{target="{TARGET}"}}')

# Avg Mbps since boot (best-effort)
avg_rx_mbps = None
avg_tx_mbps = None
if uptime and uptime > 0 and net_rx_t is not None and net_tx_t is not None and net_rx_t >= 0 and net_tx_t >= 0:
    avg_rx_mbps = (net_rx_t * 8.0) / uptime / 1e6
    avg_tx_mbps = (net_tx_t * 8.0) / uptime / 1e6

# SSH sessions table A (remote-only)
sess = q(f'vps_ssh_sessions_user_src{{target="{TARGET}"}}')  # now remote-only from exporter
sess_rows = []
for r in sess:
    m = r.get("metric", {})
    user = m.get("user","")
    src  = m.get("src","")
    val  = float(r["value"][1])
    sess_rows.append((val, user, src))
sess_rows.sort(reverse=True)

# Top processes maps (for joining)
rss_map = {(r["metric"].get("pid"), r["metric"].get("cmd")): float(r["value"][1])
           for r in q(f'vps_topproc_rss_kb{{target="{TARGET}"}}')}
mem_map = {(r["metric"].get("pid"), r["metric"].get("cmd")): float(r["value"][1])
           for r in q(f'vps_topproc_mem_percent{{target="{TARGET}"}}')}

# Top by RSS
rss_vec = q(f'topk(15, vps_topproc_rss_kb{{target="{TARGET}"}})')
top_rss=[]
for r in rss_vec:
    m=r["metric"]
    pid=m.get("pid","")
    user=m.get("user","")
    cmd=m.get("cmd","")
    rss_kb=float(r["value"][1])
    cpu_val = one(f'vps_topproc_cpu_percent{{target="{TARGET}",pid="{pid}",cmd="{cmd}"}}')
    mem_val = mem_map.get((pid,cmd))
    top_rss.append((user,pid,cmd,cpu_val,mem_val,rss_kb))

# Top by CPU
cpu_vec = q(f'topk(15, vps_topproc_cpu_percent{{target="{TARGET}"}})')
top_cpu=[]
for r in cpu_vec:
    m=r["metric"]
    pid=m.get("pid","")
    user=m.get("user","")
    cmd=m.get("cmd","")
    cpu_val=float(r["value"][1])
    mem_val = mem_map.get((pid,cmd))
    rss_kb = rss_map.get((pid,cmd))
    top_cpu.append((user,pid,cmd,cpu_val,mem_val,rss_kb))

h=[]
h.append("<!doctype html><html><head><meta charset='utf-8'>")
h.append("<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>")
h.append("<meta http-equiv='Pragma' content='no-cache'><meta http-equiv='Expires' content='0'>")
h.append("""
<style>
body{margin:0;background:#0b1220;color:#e5e7eb;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}
.wrap{padding:18px}
.card{background:#0f1a2b;border:1px solid #1f2a3a;border-radius:14px;padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:18px;align-items:start}
.k{color:#9aa4b2;font-size:12px}
.v{font-size:20px;font-weight:700;line-height:1.1;margin-top:2px}
.right{justify-self:end;text-align:right}
.line{margin-top:8px;color:#d7dde6;font-size:13px}
h3{margin:0 0 12px 0;font-size:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px 10px;border-top:1px solid #1f2a3a}
th{color:#9aa4b2;text-align:left;font-weight:600}
</style>
""")
h.append("</head><body><div class='wrap'>")

h.append("<div class='card'><div class='grid'>")
h.append(f"<div><div class='k'>Instance</div><div class='v'>{esc(TARGET)}</div></div>")
h.append(f"<div><div class='k'>Alias</div><div class='v'>{esc(ALIAS)}</div></div>")
h.append(f"<div><div class='k'>Job</div><div class='v'>ssh-collector</div></div>")
h.append(f"<div class='right'><div class='k'>Up</div><div class='v'>{'1' if up==1 else ('0' if up==0 else '—')}</div></div>")
h.append("</div>")

if dock_run is not None and dock_run >= 0 and dock_tot is not None and dock_tot >= 0:
    h.append(f"<div class='line'>Docker: {int(dock_run)} running / {int(dock_tot)} total</div>")
else:
    h.append("<div class='line'>Docker: N/A</div>")

h.append(f"<div class='line'>CPU Utilization: {fmt(cpu_busy,1)} % busy</div>")

if mem_total and mem_avail:
    used = mem_total - mem_avail
    pct = (used * 100.0 / mem_total) if mem_total > 0 else None
    cache_g = b2g(mem_cache) if mem_cache is not None and mem_cache >= 0 else None
    cache_part = f"; Cache {cache_g:.1f} GiB" if cache_g is not None else ""
    h.append(f"<div class='line'>Memory Usage: {b2g(used):.1f} GiB of {b2g(mem_total):.1f} GiB ({fmt(pct,1)} %) {esc(cache_part)}</div>")
else:
    h.append("<div class='line'>Memory Usage: —</div>")

if swap_total is not None and swap_total >= 0:
    if swap_total > 0:
        h.append(f"<div class='line'>Swap Usage: {b2g(swap_used):.1f} GiB of {b2g(swap_total):.1f} GiB ({fmt(swap_pct,1)} %)</div>")
    else:
        h.append("<div class='line'>Swap Usage: 0.0 GiB of 0.0 GiB (0.0 %)</div>")
else:
    h.append("<div class='line'>Swap Usage: —</div>")

h.append(f"<div class='line'>Network I/O: {bps(net_rx_s)} receive, {bps(net_tx_s)} send</div>")
if net_rx_t is not None and net_tx_t is not None and net_rx_t >= 0 and net_tx_t >= 0:
    avg = ""
    if avg_rx_mbps is not None and avg_tx_mbps is not None:
        avg = f" (avg: RX {avg_rx_mbps:.3f} Mbps, TX {avg_tx_mbps:.3f} Mbps since boot)"
    h.append(f"<div class='line'>Network Totals: RX {int(net_rx_t)} B, TX {int(net_tx_t)} B{avg}</div>")
else:
    h.append("<div class='line'>Network Totals: —</div>")

h.append(f"<div class='line'>Disk I/O: {bps(disk_r_s)} read, {bps(disk_w_s)} write</div>")
if disk_r_t is not None and disk_w_t is not None and disk_r_t >= 0 and disk_w_t >= 0:
    h.append(f"<div class='line'>Disk Totals: read {b2g(disk_r_t):.1f} GiB, written {b2g(disk_w_t):.1f} GiB</div>")
else:
    h.append("<div class='line'>Disk Totals: —</div>")

h.append(f"<div class='line'>Filesystem: Root {fmt(root_pct,1)} %</div>")
h.append(f"<div class='line'>Load1: {fmt(load1,2)}</div>")
h.append(f"<div class='line'>SSH sessions: {int(ssh_total) if ssh_total is not None else 0}</div>")
h.append(f"<div class='line'>Generated: {esc(now)} via {esc(PROM)}</div>")
h.append("</div>")

# SSH Sessions table A
h.append("<div class='card'><h3>SSH sessions (active)</h3>")
h.append("<table><tr><th>User</th><th>Source IP</th><th>Sessions</th></tr>")
if sess_rows:
    for val,user,src in sess_rows[:50]:
        h.append(f"<tr><td>{esc(user)}</td><td>{esc(src)}</td><td>{int(val)}</td></tr>")
else:
    h.append("<tr><td colspan='3'>No remote SSH sessions detected.</td></tr>")
h.append("</table></div>")

# Top CPU
h.append("<div class='card'><h3>Top processes (by CPU)</h3>")
h.append("<table><tr><th>Rank</th><th>User</th><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>RSS (MB)</th></tr>")
for i,(user,pid,cmd,cpu_val,mem_val,rss_kb) in enumerate(top_cpu, start=1):
    rss_mb = (rss_kb/1024) if rss_kb is not None else None
    h.append(
        f"<tr><td>{i}</td><td>{esc(user)}</td><td>{esc(pid)}</td><td>{esc(cmd)}</td>"
        f"<td>{fmt(cpu_val,1)}</td><td>{fmt(mem_val,1)}</td><td>{fmt(rss_mb,1)}</td></tr>"
    )
h.append("</table></div>")

# Top RSS
h.append("<div class='card'><h3>Top processes (by RSS)</h3>")
h.append("<table><tr><th>Rank</th><th>User</th><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>RSS (MB)</th></tr>")
for i,(user,pid,cmd,cpu_val,mem_val,rss_kb) in enumerate(top_rss, start=1):
    h.append(
        f"<tr><td>{i}</td><td>{esc(user)}</td><td>{esc(pid)}</td><td>{esc(cmd)}</td>"
        f"<td>{fmt(cpu_val,1)}</td><td>{fmt(mem_val,1)}</td><td>{(rss_kb/1024):.1f}</td></tr>"
    )
h.append("</table></div>")

h.append("</div></body></html>")
open(OUT,"w",encoding="utf-8").write("".join(h))
print("OK wrote:", OUT)
PY
