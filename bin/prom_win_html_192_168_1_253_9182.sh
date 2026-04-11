#!/usr/bin/env bash
set -euo pipefail

PROM="http://127.0.0.1:9090"
OUT="/opt/monitoring/reports/win_192_168_1_253_9182.html"
INSTANCE="192.168.1.253:9182"
ALIAS="win11-vm"

python3 - <<'PY'
import json, urllib.parse, urllib.request, datetime, html, math

PROM="http://127.0.0.1:9090"
OUT="/opt/monitoring/reports/win_192_168_1_253_9182.html"
INSTANCE="192.168.1.253:9182"
ALIAS="win11-vm"

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

def first(*queries):
    for qq in queries:
        v = one(qq)
        if v is not None:
            return v
    return None

def esc(s): return html.escape("" if s is None else str(s))
def fmt(x, nd=1):
    if x is None: return "—"
    if isinstance(x,float) and math.isnan(x): return "—"
    return f"{x:.{nd}f}"

def b2g(x): return x/1024/1024/1024
def fmt_bytes(x):
    if x is None or x < 0: return "—"
    x = float(x)
    units = ["B","KiB","MiB","GiB","TiB"]
    for u in units:
        if x < 1024 or u == units[-1]:
            return f"{x:.2f} {u}"
        x /= 1024

def fmt_bps(x):
    if x is None or x < 0: return "—"
    x = float(x)
    if x < 1024: return f"{x:.2f} B/s"
    if x < 1024**2: return f"{x/1024:.2f} KiB/s"
    if x < 1024**3: return f"{x/1024/1024:.2f} MiB/s"
    return f"{x/1024/1024/1024:.2f} GiB/s"

now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Core
up = one('up{{instance="{instance}"}}'.format(instance=INSTANCE))
tf_err = one('windows_textfile_scrape_error{{instance="{instance}"}}'.format(instance=INSTANCE))

# CPU busy % (1-idle) over 5m
cpu_busy = one('(1 - avg(rate(windows_cpu_time_total{{instance="{instance}",mode="idle"}}[5m]))) * 100'.format(instance=INSTANCE))

# Memory used/total
mem_total = one('windows_cs_physical_memory_bytes{{instance="{instance}"}}'.format(instance=INSTANCE))
mem_free  = one('windows_os_physical_memory_free_bytes{{instance="{instance}"}}'.format(instance=INSTANCE))
mem_used = None
mem_used_pct = None
if mem_total is not None and mem_free is not None:
    mem_used = mem_total - mem_free
    mem_used_pct = (mem_used * 100.0 / mem_total) if mem_total > 0 else None

# Swap/pagefile (try multiple variants; some exporters expose commit instead)
swap_used = first(
    'sum(windows_pagefile_usage_bytes{{instance="{instance}"}})'.format(instance=INSTANCE),
)
swap_total = first(
    'sum(windows_pagefile_total_bytes{{instance="{instance}"}})'.format(instance=INSTANCE),
)
commit_used = first(
    'windows_memory_committed_bytes{{instance="{instance}"}}'.format(instance=INSTANCE),
    'windows_memory_commit_bytes{{instance="{instance}"}}'.format(instance=INSTANCE),
)
commit_limit = first(
    'windows_memory_commit_limit_bytes{{instance="{instance}"}}'.format(instance=INSTANCE),
    'windows_memory_commit_limit{{instance="{instance}"}}'.format(instance=INSTANCE),
)

swap_line = "Swap Usage: —"
if swap_used is not None and swap_total is not None and swap_total > 0:
    swap_pct = (swap_used * 100.0 / swap_total)
    swap_line = f"Swap Usage: {fmt_bytes(swap_used)} of {fmt_bytes(swap_total)} ({fmt(swap_pct,1)} %)"
elif commit_used is not None and commit_limit is not None and commit_limit > 0:
    pct = (commit_used * 100.0 / commit_limit)
    swap_line = f"Commit Usage (RAM+pagefile): {fmt_bytes(commit_used)} of {fmt_bytes(commit_limit)} ({fmt(pct,1)} %)"

# Network totals + bps (try variants)
net_rx_total = first(
    'sum(windows_net_bytes_total{{instance="{instance}",direction="received"}})'.format(instance=INSTANCE),
    'sum(windows_net_bytes_total{{instance="{instance}",direction="receive"}})'.format(instance=INSTANCE),
    'sum(windows_net_bytes_received_total{{instance="{instance}"}})'.format(instance=INSTANCE),
)
net_tx_total = first(
    'sum(windows_net_bytes_total{{instance="{instance}",direction="sent"}})'.format(instance=INSTANCE),
    'sum(windows_net_bytes_total{{instance="{instance}",direction="transmit"}})'.format(instance=INSTANCE),
    'sum(windows_net_bytes_sent_total{{instance="{instance}"}})'.format(instance=INSTANCE),
)

net_rx_bps = first(
    'sum(rate(windows_net_bytes_total{{instance="{instance}",direction="received"}}[5m]))'.format(instance=INSTANCE),
    'sum(rate(windows_net_bytes_total{{instance="{instance}",direction="receive"}}[5m]))'.format(instance=INSTANCE),
    'sum(rate(windows_net_bytes_received_total{{instance="{instance}"}}[5m]))'.format(instance=INSTANCE),
)
net_tx_bps = first(
    'sum(rate(windows_net_bytes_total{{instance="{instance}",direction="sent"}}[5m]))'.format(instance=INSTANCE),
    'sum(rate(windows_net_bytes_total{{instance="{instance}",direction="transmit"}}[5m]))'.format(instance=INSTANCE),
    'sum(rate(windows_net_bytes_sent_total{{instance="{instance}"}}[5m]))'.format(instance=INSTANCE),
)

# Filesystem C:
c_size = one('windows_logical_disk_size_bytes{{instance="{instance}",volume="C:"}}'.format(instance=INSTANCE))
c_free = one('windows_logical_disk_free_bytes{{instance="{instance}",volume="C:"}}'.format(instance=INSTANCE))
c_used_pct = None
if c_size is not None and c_free is not None and c_size > 0:
    c_used_pct = ((c_size - c_free) * 100.0) / c_size

# Textfile inputs
files = q('windows_textfile_mtime_seconds{{instance="{instance}"}}'.format(instance=INSTANCE))
file_rows = []
for r in files:
    m=r.get("metric",{})
    file_rows.append((m.get("file",""), float(r["value"][1])))
file_rows.sort()

# SSH/SMB custom metrics
ssh_total = one('win_ssh_sessions_total{{instance="{instance}"}}'.format(instance=INSTANCE)) or 0
smb_sess  = one('win_smb_sessions_total{{instance="{instance}"}}'.format(instance=INSTANCE)) or 0
smb_open  = one('win_smb_open_files_total{{instance="{instance}"}}'.format(instance=INSTANCE)) or 0
shares    = one('win_smb_shares_defined_total{{instance="{instance}"}}'.format(instance=INSTANCE)) or 0

# --- Top processes (by RSS + CPU + MEM) from textfile metrics ---
def vec(query: str):
    return q(query)

rss_vec = vec('topk(15, sys_topproc_rss_kb{{instance="{instance}"}})'.format(instance=INSTANCE))
cpu_vec = vec('sys_topproc_pcpu_percent{{instance="{instance}"}}'.format(instance=INSTANCE))
mem_vec = vec('sys_topproc_pmem_percent{{instance="{instance}"}}'.format(instance=INSTANCE))

cpu_map = {}
for r in cpu_vec:
    m=r.get("metric",{})
    key=(m.get("pid",""), m.get("cmd",""), m.get("name",""))
    cpu_map[key]=float(r["value"][1])

mem_map = {}
for r in mem_vec:
    m=r.get("metric",{})
    key=(m.get("pid",""), m.get("cmd",""), m.get("name",""))
    mem_map[key]=float(r["value"][1])

top_rss=[]
for r in rss_vec:
    m=r.get("metric",{})
    pid=m.get("pid","")
    cmd=m.get("cmd","")
    name=m.get("name","")
    key=(pid,cmd,name)
    rss_kb=float(r["value"][1])
    top_rss.append((name,pid,cmd,cpu_map.get(key),mem_map.get(key),rss_kb))

# Top by CPU
top_cpu_raw = vec('topk(15, sys_topproc_pcpu_percent{{instance="{instance}"}})'.format(instance=INSTANCE))
top_cpu=[]
rss_map = {(m.get("pid",""), m.get("cmd",""), m.get("name","")): float(r["value"][1])
           for r in vec('sys_topproc_rss_kb{{instance="{instance}"}}'.format(instance=INSTANCE))
           for m in [r.get("metric",{})]}
for r in top_cpu_raw:
    m=r.get("metric",{})
    pid=m.get("pid","")
    cmd=m.get("cmd","")
    name=m.get("name","")
    key=(pid,cmd,name)
    cpuv=float(r["value"][1])
    memv=mem_map.get(key)
    rsskb=rss_map.get(key)
    top_cpu.append((name,pid,cmd,cpuv,memv,rsskb))
top_cpu.sort(key=lambda x: x[3], reverse=True)

# Build HTML
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
h.append(f"<div><div class='k'>Instance</div><div class='v'>{esc(INSTANCE)}</div></div>")
h.append(f"<div><div class='k'>Alias</div><div class='v'>{esc(ALIAS)}</div></div>")
h.append("<div><div class='k'>Job</div><div class='v'>windows_exporter</div></div>")
h.append(f"<div class='right'><div class='k'>Up</div><div class='v'>{'1' if up==1 else ('0' if up==0 else '—')}</div></div>")
h.append("</div>")
h.append(f"<div class='line'>Textfile scrape error: {int(tf_err) if tf_err is not None else '—'}</div>")
h.append(f"<div class='line'>Generated: {esc(now)} via {esc(PROM)}</div>")
h.append("</div>")

h.append("<div class='card'><h3>System stats</h3>")
h.append(f"<div class='line'>CPU Utilization: {fmt(cpu_busy,1)} % busy</div>")
if mem_total is not None and mem_used is not None:
    h.append(f"<div class='line'>Memory Usage: {b2g(mem_used):.1f} GiB of {b2g(mem_total):.1f} GiB ({fmt(mem_used_pct,1)} %)</div>")
else:
    h.append("<div class='line'>Memory Usage: —</div>")
h.append(f"<div class='line'>{esc(swap_line)}</div>")
h.append(f"<div class='line'>Network I/O: {fmt_bps(net_rx_bps)} receive, {fmt_bps(net_tx_bps)} send</div>")
if net_rx_total is not None and net_tx_total is not None:
    h.append(f"<div class='line'>Network Totals: RX {fmt_bytes(net_rx_total)}, TX {fmt_bytes(net_tx_total)}</div>")
else:
    h.append("<div class='line'>Network Totals: —</div>")
h.append(f"<div class='line'>Filesystem: C: {fmt(c_used_pct,1)} %</div>" if c_used_pct is not None else "<div class='line'>Filesystem: —</div>")
h.append("</div>")

h.append("<div class='card'><h3>Textfile inputs</h3>")
h.append("<table><tr><th>File</th><th>mtime (unix)</th></tr>")
for f,mt in file_rows:
    h.append(f"<tr><td>{esc(f)}</td><td>{int(mt)}</td></tr>")
h.append("</table></div>")

h.append("<div class='card'><h3>SSH / SMB</h3>")
h.append(f"<div class='line'>Active SSH sessions: {int(ssh_total)}</div>")
h.append(f"<div class='line'>Active SMB sessions: {int(smb_sess)} | Open SMB files: {int(smb_open)} | Shares defined (non-admin): {int(shares)}</div>")
h.append("</div>")

h.append("<div class='card'><h3>Top processes (by CPU)</h3>")
h.append("<table><tr><th>Rank</th><th>Name</th><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>RSS (MB)</th></tr>")
for i,(name,pid,cmd,cpuv,memv,rsskb) in enumerate(top_cpu, start=1):
    rssmb = (rsskb/1024.0) if rsskb is not None else None
    h.append(f"<tr><td>{i}</td><td>{esc(name)}</td><td>{esc(pid)}</td><td>{esc(cmd)}</td><td>{fmt(cpuv,1)}</td><td>{fmt(memv,1)}</td><td>{fmt(rssmb,1)}</td></tr>")
h.append("</table></div>")

h.append("<div class='card'><h3>Top processes (by RSS)</h3>")
h.append("<table><tr><th>Rank</th><th>Name</th><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>RSS (MB)</th></tr>")
for i,(name,pid,cmd,cpuv,memv,rss_kb) in enumerate(top_rss, start=1):
    h.append(f"<tr><td>{i}</td><td>{esc(name)}</td><td>{esc(pid)}</td><td>{esc(cmd)}</td><td>{fmt(cpuv,1)}</td><td>{fmt(memv,1)}</td><td>{(rss_kb/1024.0):.1f}</td></tr>")
h.append("</table></div>")

h.append("<div class='card'><div class='line'>Docker section: N/A (Windows)</div></div>")
h.append("</div></body></html>")

open(OUT,"w",encoding="utf-8").write("".join(h))
print("OK wrote:", OUT)
PY
