#!/usr/bin/env bash
set -euo pipefail

PROM="${PROM:-http://127.0.0.1:9090}"
INSTANCE="${1:-}"
TOPN="${2:-100}"

[[ -n "$INSTANCE" ]] || { echo "Usage: $0 <instance:port> [topN]"; exit 2; }
[[ "$TOPN" =~ ^[0-9]+$ ]] || { echo "ERROR: topN must be an integer"; exit 2; }

REPORT_DIR="/opt/monitoring/reports"
install -d -m 0755 -o wazuh-admin -g wazuh-admin "$REPORT_DIR"

SAFE_INSTANCE="$(printf '%s' "$INSTANCE" | tr ':.' '__')"
OUTFILE="$REPORT_DIR/vm_dashboard_${SAFE_INSTANCE}.html"

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

def prom_query(q: str):
    data = urlencode({"query": q}).encode("utf-8")
    req = Request(f"{prom}/api/v1/query", data=data, method="POST")
    try:
        with urlopen(req, timeout=10) as r:
            raw = r.read().decode("utf-8", "replace")
    except Exception as e:
        return {"__error__": f"{type(e).__name__}: {e}"}

    try:
        d = json.loads(raw)
    except Exception as e:
        return {"__error__": f"JSON parse error: {e}", "__raw__": raw[:400]}

    if d.get("status") != "success":
        return {"__error__": f"Prometheus status != success: {d.get('status')}", "__resp__": d}

    return d.get("data", {}).get("result", [])

def one_value(res):
    # expects a vector with 0 or 1 sample
    if isinstance(res, dict) and "__error__" in res:
        return None
    if not isinstance(res, list) or not res:
        return None
    try:
        return float(res[0]["value"][1])
    except Exception:
        return None

def first_label(res, key, default=""):
    if isinstance(res, list) and res:
        return res[0].get("metric", {}).get(key, default)
    return default

def human_bytes(x):
    if x is None:
        return "N/A"
    try:
        x = float(x)
    except:
        return "N/A"
    units = ["B","KiB","MiB","GiB","TiB","PiB"]
    i = 0
    while x >= 1024 and i < len(units)-1:
        x /= 1024.0
        i += 1
    return f"{x:.2f} {units[i]}"

def f2(x):
    try:
        return f"{float(x):.2f}"
    except:
        return "N/A"

def pct(x):
    try:
        return f"{float(x):.2f} %"
    except:
        return "N/A"

now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Identity
uname = prom_query(f'node_uname_info{{instance="{instance}"}}')
upv   = prom_query(f'up{{instance="{instance}"}}')

alias   = first_label(uname, "alias", "")
nodename= first_label(uname, "nodename", "")
kernel  = first_label(uname, "release", "")
jobname = first_label(upv, "job", "") or first_label(uname, "job", "")
up_val  = one_value(upv)
up_str  = "N/A" if up_val is None else str(int(up_val))

# System sample (standard node_exporter metrics)
q_up = f'up{{instance="{instance}"}}'
q_cpu_avg = f'100*(1-avg(rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[5m])))'
q_cpu_peak = f'max(100*(1-rate(node_cpu_seconds_total{{instance="{instance}",mode="idle"}}[5m])))'

q_mem_total = f'node_memory_MemTotal_bytes{{instance="{instance}"}}'
q_mem_avail = f'node_memory_MemAvailable_bytes{{instance="{instance}"}}'
q_mem_cache = f'node_memory_Cached_bytes{{instance="{instance}"}}'

q_swap_total = f'node_memory_SwapTotal_bytes{{instance="{instance}"}}'
q_swap_free  = f'node_memory_SwapFree_bytes{{instance="{instance}"}}'

q_uptime = f'time() - node_boot_time_seconds{{instance="{instance}"}}'

# Network: sum all non-loopback / non-virtual-ish
net_dev_re = r'lo|docker.*|veth.*|br-.*|virbr.*|flannel.*|cali.*|tun.*|wg.*'
q_net_rx_s = f'sum(rate(node_network_receive_bytes_total{{instance="{instance}",device!~"{net_dev_re}"}}[5m]))'
q_net_tx_s = f'sum(rate(node_network_transmit_bytes_total{{instance="{instance}",device!~"{net_dev_re}"}}[5m]))'
q_net_rx_t = f'sum(node_network_receive_bytes_total{{instance="{instance}",device!~"{net_dev_re}"}})'
q_net_tx_t = f'sum(node_network_transmit_bytes_total{{instance="{instance}",device!~"{net_dev_re}"}})'

# Disk IO: sum all non-loop/ram/sr/dm
disk_dev_re = r'loop.*|ram.*|fd.*|sr.*|dm-.*'
q_disk_r_s = f'sum(rate(node_disk_read_bytes_total{{instance="{instance}",device!~"{disk_dev_re}"}}[5m]))'
q_disk_w_s = f'sum(rate(node_disk_written_bytes_total{{instance="{instance}",device!~"{disk_dev_re}"}}[5m]))'
q_disk_r_t = f'sum(node_disk_read_bytes_total{{instance="{instance}",device!~"{disk_dev_re}"}})'
q_disk_w_t = f'sum(node_disk_written_bytes_total{{instance="{instance}",device!~"{disk_dev_re}"}})'

# Filesystem: root + optional iso/cdrom
fs_re = r'tmpfs|overlay|squashfs|aufs|ramfs|autofs|devtmpfs'
q_root_pct = f'100*(1-(node_filesystem_avail_bytes{{instance="{instance}",mountpoint="/",fstype!~"{fs_re}"}} / node_filesystem_size_bytes{{instance="{instance}",mountpoint="/",fstype!~"{fs_re}"}}))'
q_iso_pct  = f'100*(1-(node_filesystem_avail_bytes{{instance="{instance}",mountpoint=~"/(cdrom|iso)",fstype!~"{fs_re}"}} / node_filesystem_size_bytes{{instance="{instance}",mountpoint=~"/(cdrom|iso)",fstype!~"{fs_re}"}}))'

# sys_sample metrics seen (optional textfile metrics)
q_sys_sample_seen = f'count({{__name__=~"sys_sample_.*",instance="{instance}"}})'

cpu_avg = one_value(prom_query(q_cpu_avg))
cpu_peak = one_value(prom_query(q_cpu_peak))

mem_total = one_value(prom_query(q_mem_total))
mem_avail = one_value(prom_query(q_mem_avail))
mem_cache = one_value(prom_query(q_mem_cache))
mem_used = None if (mem_total is None or mem_avail is None) else (mem_total - mem_avail)
mem_pct = None if (mem_total is None or mem_used is None) else (100.0 * mem_used / mem_total)

swap_total = one_value(prom_query(q_swap_total))
swap_free  = one_value(prom_query(q_swap_free))
swap_used  = None if (swap_total is None or swap_free is None) else (swap_total - swap_free)
swap_pct   = None if (swap_total is None or swap_used is None or swap_total == 0) else (100.0 * swap_used / swap_total)

uptime_s = one_value(prom_query(q_uptime))

net_rx_s = one_value(prom_query(q_net_rx_s))
net_tx_s = one_value(prom_query(q_net_tx_s))
net_rx_t = one_value(prom_query(q_net_rx_t))
net_tx_t = one_value(prom_query(q_net_tx_t))

disk_r_s = one_value(prom_query(q_disk_r_s))
disk_w_s = one_value(prom_query(q_disk_w_s))
disk_r_t = one_value(prom_query(q_disk_r_t))
disk_w_t = one_value(prom_query(q_disk_w_t))

root_pct = one_value(prom_query(q_root_pct))
iso_pct  = one_value(prom_query(q_iso_pct))

sys_sample_seen = one_value(prom_query(q_sys_sample_seen))
sys_sample_seen_str = "N/A" if sys_sample_seen is None else str(int(sys_sample_seen))

# Averages since boot (Mbps)
rx_mbps = None
tx_mbps = None
if uptime_s and uptime_s > 0 and net_rx_t is not None and net_tx_t is not None:
    rx_mbps = (net_rx_t * 8.0 / uptime_s) / 1e6
    tx_mbps = (net_tx_t * 8.0 / uptime_s) / 1e6

# --- Top Processes by RSS ---
rss_q = f'topk({topn}, sys_topproc_rss_kb{{instance="{instance}"}})'
rss_res = prom_query(rss_q)

def get_pid_map(metric_name: str, pid_re: str):
    q = f'{metric_name}{{instance="{instance}",pid=~"{pid_re}"}}'
    res = prom_query(q)
    if isinstance(res, dict) and "__error__" in res:
        return {}
    m = {}
    for item in res:
        pid = item.get("metric", {}).get("pid")
        val = item.get("value", [None, None])[1]
        if not pid or val is None:
            continue
        try:
            m[pid] = float(val)
        except:
            pass
    return m

rows = []
if isinstance(rss_res, list):
    for item in rss_res:
        m = item.get("metric", {})
        v = item.get("value", [None, None])[1]
        if v is None:
            continue
        try:
            rss_kb = float(v)
        except:
            continue
        rows.append({
            "pid": m.get("pid",""),
            "user": m.get("user",""),
            "comm": m.get("comm",""),
            "exe":  m.get("exe",""),
            "rss_kb": rss_kb,
        })

pcpu = {}
pmem = {}
vsz  = {}
if rows:
    pids = [r["pid"] for r in rows if r["pid"]]
    pid_re = "|".join(pids)  # numeric pids => safe
    pcpu = get_pid_map("sys_topproc_pcpu_percent", pid_re)
    pmem = get_pid_map("sys_topproc_pmem_percent", pid_re)
    vsz  = get_pid_map("sys_topproc_vsz_kb", pid_re)

# HTML
title = f"VM Dashboard (Prometheus) — {instance}"
subtitle = f"Alias: {alias or 'N/A'} | Host: {nodename or 'N/A'} | Kernel: {kernel or 'N/A'} | Job: {jobname or 'N/A'} | up={up_str}"

print("<!doctype html><html><head><meta charset='utf-8'>")
print("<meta name='viewport' content='width=device-width, initial-scale=1'>")
print(f"<title>{html.escape(title)}</title>")
print("<style>")
print("""
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:20px;color:#111}
h1{margin:0 0 6px 0;font-size:20px}
.small{color:#444;margin:0 0 14px 0;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(240px,1fr));gap:12px}
.card{border:1px solid #e5e5e5;border-radius:10px;padding:12px;background:#fff}
.card h3{margin:0 0 6px 0;font-size:13px;color:#333}
.card .v{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:10px}
th,td{border:1px solid #ddd;padding:6px 8px;vertical-align:top}
th{background:#f6f6f6;text-align:left;position:sticky;top:0}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
.note{margin-top:10px;color:#444;font-size:12px}
""")
print("</style></head><body>")

print(f"<h1>{html.escape(title)}</h1>")
print(f"<p class='small'>Generated: <span class='mono'>{now}</span><br>{html.escape(subtitle)}</p>")

print("<h2 style='font-size:14px;margin:14px 0 8px 0'>System Sample (sys_sample_*)</h2>")
print("<div class='grid'>")

print("<div class='card'><h3>CPU Utilization</h3><div class='v'>" + (pct(cpu_avg) if cpu_avg is not None else "N/A") + " busy</div></div>")

mem_line = "N/A"
if mem_total is not None and mem_used is not None and mem_pct is not None:
    mem_line = f"{human_bytes(mem_used)} of {human_bytes(mem_total)} ({mem_pct:.2f} %) ; Cache {human_bytes(mem_cache)}"
print("<div class='card'><h3>Memory Usage</h3><div class='v'>" + html.escape(mem_line) + "</div></div>")

swap_line = "N/A"
if swap_total is not None and swap_used is not None:
    if swap_total == 0:
        swap_line = f"{human_bytes(swap_used)} of {human_bytes(swap_total)} (N/A)"
    else:
        swap_line = f"{human_bytes(swap_used)} of {human_bytes(swap_total)} ({swap_pct:.2f} %)"
print("<div class='card'><h3>Swap Usage</h3><div class='v'>" + html.escape(swap_line) + "</div></div>")

netio_line = "N/A B/s receive, N/A B/s send"
if net_rx_s is not None and net_tx_s is not None:
    netio_line = f"{human_bytes(net_rx_s)}/s receive, {human_bytes(net_tx_s)}/s send"
print("<div class='card'><h3>Network I/O</h3><div class='v'>" + html.escape(netio_line) + "</div></div>")

nett_line = "RX N/A B, TX N/A B (avg: RX N/A Mbps, TX N/A Mbps since boot)"
if net_rx_t is not None and net_tx_t is not None and rx_mbps is not None and tx_mbps is not None:
    nett_line = f"RX {human_bytes(net_rx_t)}, TX {human_bytes(net_tx_t)} (avg: RX {rx_mbps:.3f} Mbps, TX {tx_mbps:.3f} Mbps since boot)"
print("<div class='card'><h3>Network Totals</h3><div class='v'>" + html.escape(nett_line) + "</div></div>")

disk_line = "N/A read, N/A write; Total read: N/A, Total written: N/A"
if disk_r_s is not None and disk_w_s is not None and disk_r_t is not None and disk_w_t is not None:
    disk_line = f"{human_bytes(disk_r_s)}/s read, {human_bytes(disk_w_s)}/s write; Total read: {human_bytes(disk_r_t)}, Total written: {human_bytes(disk_w_t)}"
print("<div class='card'><h3>Disk I/O</h3><div class='v'>" + html.escape(disk_line) + "</div></div>")

fs_line = f"Root {('N/A' if root_pct is None else f'{root_pct:.1f} %')} , ISO {('N/A' if iso_pct is None else f'{iso_pct:.1f} %')}"
print("<div class='card'><h3>Filesystem</h3><div class='v'>" + html.escape(fs_line) + "</div></div>")

print("<div class='card'><h3>sys_sample metrics seen</h3><div class='v'>" + html.escape(sys_sample_seen_str) + "</div></div>")

print("</div>")  # grid

print("<h2 style='font-size:14px;margin:16px 0 6px 0'>Top Processes by RSS (Top %d)</h2>" % topn)
print("<div class='note mono'>PromQL: " + html.escape(rss_q) + "</div>")

if not rows:
    print("<p class='note'>No sys_topproc_* data found for this instance. (Textfile metrics not being exposed or not scraped.)</p>")
else:
    rows.sort(key=lambda r: r["rss_kb"], reverse=True)
    print("<table><thead><tr>"
          "<th>#</th><th>USER</th><th>PID</th><th>%CPU</th><th>%MEM</th><th>VSZ (KB)</th><th>RSS (KB)</th><th>COMM</th><th>EXE_PATH</th>"
          "</tr></thead><tbody>")
    for i, r in enumerate(rows, 1):
        pid = r["pid"]
        cpu = pcpu.get(pid, None)
        mem = pmem.get(pid, None)
        vsz_kb = vsz.get(pid, None)
        print("<tr>"
              f"<td class='num mono'>{i}</td>"
              f"<td>{html.escape(r['user'])}</td>"
              f"<td class='num mono'>{html.escape(pid)}</td>"
              f"<td class='num mono'>{('N/A' if cpu is None else f'{cpu:.2f}')}</td>"
              f"<td class='num mono'>{('N/A' if mem is None else f'{mem:.2f}')}</td>"
              f"<td class='num mono'>{('N/A' if vsz_kb is None else str(int(vsz_kb)))}</td>"
              f"<td class='num mono'>{str(int(r['rss_kb']))}</td>"
              f"<td class='mono'>{html.escape(r['comm'])}</td>"
              f"<td class='mono'>{html.escape(r['exe'])}</td>"
              "</tr>")
    print("</tbody></table>")

print("<div class='note mono'>PromQL used (instance-filtered):<br>")
for q in (q_up,q_cpu_avg,q_cpu_peak,q_mem_total,q_mem_avail,q_root_pct,rss_q):
    print(html.escape(q) + "<br>")
print("</div>")

print("</body></html>")
PY

install -m 0644 -o wazuh-admin -g wazuh-admin "$TMP" "$OUTFILE"
echo "Saved: $OUTFILE"
