#!/usr/bin/env bash
set -euo pipefail

PROM="${PROM:-http://127.0.0.1:9090}"
INSTANCE="${1:-}"
TOPN="${2:-100}"

if [[ -z "$INSTANCE" ]]; then
  echo "Usage: $(basename "$0") <instance:port> [topN]"
  exit 2
fi
[[ "$TOPN" =~ ^[0-9]+$ ]] || { echo "ERROR: topN must be an integer"; exit 2; }

REPORT_DIR="/opt/monitoring/reports"
sudo install -d -m 0755 "$REPORT_DIR"

SAFE_INSTANCE="$(printf '%s' "$INSTANCE" | tr ':.' '_')"
OUTFILE="$REPORT_DIR/tower_${SAFE_INSTANCE}.html"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

python3 - "$PROM" "$INSTANCE" "$TOPN" > "$TMP" <<'PY'
import sys, json, html
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from datetime import datetime, timezone

prom = sys.argv[1].rstrip("/")
instance = sys.argv[2]
topn = int(sys.argv[3])

def api_query(q: str):
    data = urlencode({"query": q}).encode("utf-8")
    req = Request(f"{prom}/api/v1/query", data=data, method="POST")
    with urlopen(req, timeout=12) as r:
        raw = r.read().decode("utf-8", "replace")
    j = json.loads(raw)
    if j.get("status") != "success":
        raise RuntimeError(f"Prometheus status={j.get('status')}")
    return j["data"]["resultType"], j["data"]["result"]

def scalar(q: str, default=None):
    try:
        rtype, res = api_query(q)
        if rtype == "scalar":
            return float(res[1])
        if rtype == "vector" and res:
            return float(res[0]["value"][1])
    except Exception:
        return default
    return default

def vector(q: str):
    try:
        rtype, res = api_query(q)
        return res if rtype == "vector" else []
    except Exception:
        return []

def first_label(v, key, default=""):
    if isinstance(v, list) and v:
        return v[0].get("metric", {}).get(key, default) or default
    return default

def human_bytes(n):
    if n is None:
        return "N/A"
    n = float(n)
    units = ["B","KiB","MiB","GiB","TiB","PiB"]
    u = 0
    while n >= 1024 and u < len(units)-1:
        n /= 1024.0
        u += 1
    if u == 0:
        return f"{n:.0f} {units[u]}"
    return f"{n:.2f} {units[u]}"

def human_bps(n):
    if n is None:
        return "N/A"
    return f"{human_bytes(n)}/s"

now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Identity
uname = vector(f'node_uname_info{{instance="{instance}"}}')
upv   = scalar(f'up{{instance="{instance}"}}', default=None)

alias    = first_label(uname, "alias", "N/A")
nodename = first_label(uname, "nodename", "N/A")
release  = first_label(uname, "release", "N/A")
jobname  = first_label(uname, "job", "N/A")

cpuinfo   = vector(f'node_cpu_info{{instance="{instance}"}}')
cpu_model = first_label(cpuinfo, "model_name", "N/A")

uptime_s = scalar(f'time() - node_boot_time_seconds{{instance="{instance}"}}', default=None)

cpu_busy = scalar(
    f'100 * (1 - avg(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[1m])))',
    default=None
)
cpu_peak = scalar(
    f'100 * (1 - min(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[1m])))',
    default=None
)

mem_total = scalar(f'node_memory_MemTotal_bytes{{instance="{instance}"}}', default=None)
mem_avail = scalar(f'node_memory_MemAvailable_bytes{{instance="{instance}"}}', default=None)
mem_cached= scalar(f'node_memory_Cached_bytes{{instance="{instance}"}}', default=None)
mem_used  = None if (mem_total is None or mem_avail is None) else max(mem_total - mem_avail, 0.0)
mem_pct   = None if (mem_total in (None,0) or mem_used is None) else (mem_used / mem_total * 100.0)

swap_total= scalar(f'node_memory_SwapTotal_bytes{{instance="{instance}"}}', default=None)
swap_free = scalar(f'node_memory_SwapFree_bytes{{instance="{instance}"}}', default=None)
swap_used = None if (swap_total is None or swap_free is None) else max(swap_total - swap_free, 0.0)
swap_pct  = None if (swap_total in (None,0) or swap_used is None) else (swap_used / swap_total * 100.0)

# Network (exclude noisy virtual devices)
dev_re = r'lo|docker.*|veth.*|br.*|virbr.*'
rx_rate = scalar(f'sum(rate(node_network_receive_bytes_total{{instance="{instance}",device!~"{dev_re}"}}[1m]))', default=None)
tx_rate = scalar(f'sum(rate(node_network_transmit_bytes_total{{instance="{instance}",device!~"{dev_re}"}}[1m]))', default=None)
rx_total= scalar(f'sum(node_network_receive_bytes_total{{instance="{instance}",device!~"{dev_re}"}})', default=None)
tx_total= scalar(f'sum(node_network_transmit_bytes_total{{instance="{instance}",device!~"{dev_re}"}})', default=None)

rx_avg_mbps = None
tx_avg_mbps = None
if uptime_s and uptime_s > 0 and rx_total is not None and tx_total is not None:
    rx_avg_mbps = (rx_total * 8.0) / uptime_s / 1e6
    tx_avg_mbps = (tx_total * 8.0) / uptime_s / 1e6

# Disk I/O (bytes/sec)
rd_rate = scalar(f'sum(rate(node_disk_read_bytes_total{{instance="{instance}"}}[1m]))', default=None)
wr_rate = scalar(f'sum(rate(node_disk_written_bytes_total{{instance="{instance}"}}[1m]))', default=None)
rd_tot  = scalar(f'sum(node_disk_read_bytes_total{{instance="{instance}"}})', default=None)
wr_tot  = scalar(f'sum(node_disk_written_bytes_total{{instance="{instance}"}})', default=None)

def fs_used_pct(mount: str):
    size = scalar(f'node_filesystem_size_bytes{{instance="{instance}",mountpoint="{mount}",fstype!~"tmpfs|overlay"}}', default=None)
    avail= scalar(f'node_filesystem_avail_bytes{{instance="{instance}",mountpoint="{mount}",fstype!~"tmpfs|overlay"}}', default=None)
    if size is None or avail is None or size == 0:
        return None
    used = max(size - avail, 0.0)
    return used / size * 100.0

root_pct = fs_used_pct("/")
mnt_user_pct = fs_used_pct("/mnt/user")
mnt_cache_pct= fs_used_pct("/mnt/cache")

# Top processes (from your sys_topproc textfile metrics)
rss_q = f'topk({topn}, sys_topproc_rss_kb{{instance="{instance}"}})'
rss = vector(rss_q)

rows = []
for it in rss:
    m = it.get("metric", {})
    v = it.get("value", [None, None])[1]
    if v is None:
        continue
    try:
        rss_kb = float(v)
    except Exception:
        continue
    rows.append({
        "pid": m.get("pid",""),
        "user": m.get("user",""),
        "comm": m.get("comm",""),
        "exe":  m.get("exe",""),
        "rank": m.get("rank",""),
        "rss_kb": rss_kb,
    })
rows.sort(key=lambda r: r["rss_kb"], reverse=True)

def get_map(metric: str, pids):
    if not pids:
        return {}
    pid_re = "|".join(pids)  # numeric only
    q = f'{metric}{{instance="{instance}",pid=~"{pid_re}"}}'
    res = vector(q)
    out = {}
    for it in res:
        pid = it.get("metric", {}).get("pid")
        val = it.get("value", [None, None])[1]
        if pid is None or val is None:
            continue
        try:
            out[pid] = float(val)
        except Exception:
            pass
    return out

pids = [r["pid"] for r in rows if r["pid"]]
pcpu = get_map("sys_topproc_pcpu_percent", pids)
pmem = get_map("sys_topproc_pmem_percent", pids)
vsz  = get_map("sys_topproc_vsz_kb", pids)

def f2(x):
    try: return f"{float(x):.2f}"
    except: return "0.00"

def i0(x):
    try: return str(int(float(x)))
    except: return "0"

# Precompute strings (avoids f-string nesting bugs)
up_str = "N/A" if upv is None else str(int(upv))
status = "✅ OK" if (upv == 1 and (cpu_busy is None or cpu_busy < 70) and (mem_pct is None or mem_pct < 85)) else "⚠️ Review"
cpu_busy_str = "N/A" if cpu_busy is None else f"{cpu_busy:.2f} %"
cpu_peak_str = "N/A" if cpu_peak is None else f"{cpu_peak:.2f} %"

ram_str = "N/A"
if mem_total is not None and mem_used is not None and mem_pct is not None:
    ram_str = f"{human_bytes(mem_total)} — Usage {mem_pct:.2f} % ({human_bytes(mem_used)} used, {human_bytes(mem_avail)} avail; Cache {human_bytes(mem_cached) if mem_cached is not None else 'N/A'})"

swap_used_str  = "N/A" if swap_used is None else human_bytes(swap_used)
swap_total_str = "N/A" if swap_total is None else human_bytes(swap_total)
swap_pct_str   = "N/A" if swap_pct is None else f"{swap_pct:.2f} %"

uptime_str = "N/A" if uptime_s is None else f"{uptime_s/3600.0:.2f} hours"
net_totals_str = "N/A"
if rx_total is not None and tx_total is not None:
    rx_avg = "N/A" if rx_avg_mbps is None else f"{rx_avg_mbps:.3f} Mbps"
    tx_avg = "N/A" if tx_avg_mbps is None else f"{tx_avg_mbps:.3f} Mbps"
    net_totals_str = f"RX {human_bytes(rx_total)}, TX {human_bytes(tx_total)} (avg: RX {rx_avg}, TX {tx_avg} since boot)"

fs_str = f"Root {('N/A' if root_pct is None else f'{root_pct:.1f} %')} ; /mnt/user {('N/A' if mnt_user_pct is None else f'{mnt_user_pct:.1f} %')} ; /mnt/cache {('N/A' if mnt_cache_pct is None else f'{mnt_cache_pct:.1f} %')}"

title = f"Tower Dashboard (Prometheus) — {instance}"
sub = f"Generated: {now} | Alias: {alias} | Host: {nodename} | Kernel: {release} | Job: {jobname} | up={up_str}"

print("<!doctype html><html><head><meta charset='utf-8'>")
print("<meta name='viewport' content='width=device-width, initial-scale=1'>")
print(f"<title>{html.escape(title)}</title>")
print("<style>")
print("""
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:22px;color:#111}
h1{margin:0 0 6px 0;font-size:18px}
.small{color:#444;margin:0 0 14px 0;font-size:12px;line-height:1.35}
h2{margin:18px 0 10px 0;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:10px;margin:10px 0 14px 0}
.card{border:1px solid #e3e3e3;border-radius:10px;padding:10px 12px;background:#fff}
.k{font-size:11px;color:#555;margin:0}
.v{font-size:12px;margin:2px 0 0 0;font-weight:600}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{border:1px solid #ddd;padding:6px 8px;vertical-align:top}
th{background:#f6f6f6;text-align:left;position:sticky;top:0}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.bad{background:#fff1f1}
.warn{background:#fff9e6}
.note{margin-top:10px;color:#444;font-size:11px}
ul{margin:6px 0 0 18px}
""")
print("</style></head><body>")

print(f"<h1>{html.escape(title)}</h1>")
print(f"<div class='small'>{html.escape(sub)}</div>")

print("<h2>🧠 System & Processor Performance Summary</h2>")
print("<ul>")
print(f"<li><b>Status:</b> {html.escape(status)}</li>")
print(f"<li><b>CPU:</b> {html.escape(cpu_model)} — Load ≈ {html.escape(cpu_busy_str)} (peak core ≈ {html.escape(cpu_peak_str)})</li>")
print(f"<li><b>RAM:</b> {html.escape(ram_str)}</li>")
print(f"<li><b>Swap:</b> {html.escape(swap_used_str)} of {html.escape(swap_total_str)} ({html.escape(swap_pct_str)})</li>")
print("</ul>")
print("<div class='note'>Unraid-only details (parity/temps/WG peers/docker counts) need extra textfile metrics or an Unraid exporter.</div>")

print("<h2>🌐 Network Uptime & Performance</h2>")
print("<ul>")
print(f"<li><b>Uptime:</b> {html.escape(uptime_str)}</li>")
print(f"<li><b>Network I/O:</b> {html.escape(human_bps(rx_rate))} receive, {html.escape(human_bps(tx_rate))} send</li>")
print(f"<li><b>Network Totals:</b> {html.escape(net_totals_str)}</li>")
print("</ul>")

print("<h2>📦 Disk / Cache Overview</h2>")
print("<ul>")
print(f"<li><b>Disk I/O:</b> {html.escape(human_bps(rd_rate))} read, {html.escape(human_bps(wr_rate))} write; Total read {html.escape(human_bytes(rd_tot))}, Total written {html.escape(human_bytes(wr_tot))}</li>")
print(f"<li><b>Filesystem:</b> {html.escape(fs_str)}</li>")
print("</ul>")

print("<h2>System Sample</h2>")
print("<div class='grid'>")
print(f"<div class='card'><div class='k'>CPU Utilization</div><div class='v'>{html.escape(cpu_busy_str)} busy</div></div>")
print(f"<div class='card'><div class='k'>Memory Usage</div><div class='v'>{html.escape(ram_str)}</div></div>")
print(f"<div class='card'><div class='k'>Swap Usage</div><div class='v'>{html.escape(swap_used_str)} of {html.escape(swap_total_str)} ({html.escape(swap_pct_str)})</div></div>")
print(f"<div class='card'><div class='k'>Network I/O</div><div class='v'>{html.escape(human_bps(rx_rate))} receive, {html.escape(human_bps(tx_rate))} send</div></div>")
print(f"<div class='card'><div class='k'>Network Totals</div><div class='v'>{html.escape(net_totals_str)}</div></div>")
print(f"<div class='card'><div class='k'>Disk I/O</div><div class='v'>{html.escape(human_bps(rd_rate))} read, {html.escape(human_bps(wr_rate))} write; Total read {html.escape(human_bytes(rd_tot))}, Total written {html.escape(human_bytes(wr_tot))}</div></div>")
print(f"<div class='card'><div class='k'>Filesystem</div><div class='v'>{html.escape(fs_str)}</div></div>")
print("</div>")

print(f"<h2>Top Processes by RSS (Top {topn})</h2>")
print(f"<div class='small mono'>PromQL: {html.escape(rss_q)}</div>")

print("<table><thead><tr>"
      "<th>#</th><th>USER</th><th>PID</th><th>%CPU</th><th>%MEM</th>"
      "<th>VSZ (KB)</th><th>RSS (KB)</th><th>COMM</th><th>EXE_PATH</th>"
      "</tr></thead><tbody>")

for idx, r in enumerate(rows, start=1):
    pid = r["pid"]
    cpu = pcpu.get(pid, 0.0)
    mem = pmem.get(pid, 0.0)
    vsz_kb = vsz.get(pid, 0.0)

    cls = ""
    if cpu >= 80:
        cls = "bad"
    elif cpu >= 30 or mem >= 10:
        cls = "warn"

    print(f"<tr class='{cls}'>"
          f"<td class='num mono'>{idx}</td>"
          f"<td>{html.escape(r['user'])}</td>"
          f"<td class='num mono'>{html.escape(pid)}</td>"
          f"<td class='num mono'>{f2(cpu)}</td>"
          f"<td class='num mono'>{f2(mem)}</td>"
          f"<td class='num mono'>{i0(vsz_kb)}</td>"
          f"<td class='num mono'>{i0(r['rss_kb'])}</td>"
          f"<td class='mono'>{html.escape(r['comm'])}</td>"
          f"<td class='mono'>{html.escape(r['exe'])}</td>"
          f"</tr>")

print("</tbody></table>")
print("</body></html>")
PY

sudo install -m 0644 "$TMP" "$OUTFILE"
echo "Saved: $OUTFILE"
echo "Open URL: http://<WAZUH-SERVER-IP>:8088/$(basename "$OUTFILE")"
