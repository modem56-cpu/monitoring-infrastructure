#!/usr/bin/env bash
set -euo pipefail

PROM="${PROM:-http://127.0.0.1:9090}"

usage() {
  cat <<USG
Usage:
  $(basename "$0") <instance:port> [topN]

Examples:
  $(basename "$0") 192.168.5.131:9100 100
  PROM=http://127.0.0.1:9090 $(basename "$0") 192.168.5.131:9100 50
USG
}

INSTANCE="${1:-}"
TOPN="${2:-100}"

[[ -n "$INSTANCE" ]] || { usage; exit 2; }
[[ "$TOPN" =~ ^[0-9]+$ ]] || { echo "ERROR: topN must be an integer"; exit 2; }

REPORT_DIR="/opt/monitoring/reports"
mkdir -p "$REPORT_DIR"
chmod 0755 "$REPORT_DIR" 2>/dev/null || true

SAFE_INSTANCE="$(printf '%s' "$INSTANCE" | tr ':.' '__')"
OUTFILE="$REPORT_DIR/topproc_${SAFE_INSTANCE}.html"

TMP="$(mktemp "$REPORT_DIR/.topproc_${SAFE_INSTANCE}.XXXXXX")"
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
        return {"__error__": f"JSON parse error: {e}", "__raw__": raw[:500]}
    if d.get("status") != "success":
        return {"__error__": f"Prometheus status != success: {d.get('status')}", "__resp__": d}
    return d.get("data", {}).get("result", [])

def get_value_map(metric_name: str, pid_re: str):
    q = f'{metric_name}{{instance="{instance}",pid=~"{pid_re}"}}'
    res = prom_query(q)
    if isinstance(res, dict) and "__error__" in res:
        return res
    m = {}
    for item in res:
        pid = item.get("metric", {}).get("pid")
        val = item.get("value", [None, None])[1]
        if pid is None or val is None:
            continue
        try:
            m[pid] = float(val)
        except:
            pass
    return m

now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

uname = prom_query(f'node_uname_info{{instance="{instance}"}}')
upv   = prom_query(f'up{{instance="{instance}"}}')

def first_label(res, key, default=""):
    if isinstance(res, list) and res:
        return res[0].get("metric", {}).get(key, default)
    return default

alias = first_label(uname, "alias", "")
nodename = first_label(uname, "nodename", "")
release  = first_label(uname, "release", "")
jobname  = first_label(upv, "job", "") or first_label(uname, "job", "")

up_val = "N/A"
if isinstance(upv, list) and upv:
    up_val = upv[0].get("value", ["",""])[1] or "N/A"

rss_q = f'topk({topn}, sys_topproc_rss_kb{{instance="{instance}"}})'
rss_res = prom_query(rss_q)

err = None
if isinstance(rss_res, dict) and "__error__" in rss_res:
    err = rss_res["__error__"]

rows = []
if not err:
    for item in rss_res:
        m = item.get("metric", {})
        v = item.get("value", [None, None])[1]
        if v is None:
            continue
        pid = m.get("pid", "")
        try:
            rss_kb = float(v)
        except:
            continue
        rows.append({
            "pid": pid,
            "user": m.get("user", ""),
            "comm": m.get("comm", ""),
            "exe":  m.get("exe", ""),
            "rank": m.get("rank", ""),
            "rss_kb": rss_kb,
        })

pcpu = {}
pmem = {}
vsz  = {}
if rows:
    pids = [r["pid"] for r in rows if r["pid"]]
    pid_re = "|".join(pids)
    pcpu = get_value_map("sys_topproc_pcpu_percent", pid_re)
    pmem = get_value_map("sys_topproc_pmem_percent", pid_re)
    vsz  = get_value_map("sys_topproc_vsz_kb", pid_re)

def f2(x):
    try: return f"{float(x):.2f}"
    except: return "0.00"

def i0(x):
    try: return str(int(float(x)))
    except: return "0"

rows.sort(key=lambda r: r["rss_kb"], reverse=True)

title = f"Top Processes (Prometheus) — {instance}"
subtitle = f"Alias: {alias or 'N/A'} | Host: {nodename or 'N/A'} | Kernel: {release or 'N/A'} | Job: {jobname or 'N/A'} | up={up_val}"

print("<!doctype html><html><head><meta charset='utf-8'>")
print("<meta name='viewport' content='width=device-width, initial-scale=1'>")
print(f"<title>{html.escape(title)}</title>")
print("<style>")
print("""
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:20px;color:#111}
h1{margin:0 0 6px 0;font-size:20px}
.small{color:#444;margin:0 0 14px 0;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #ddd;padding:6px 8px;vertical-align:top}
th{background:#f6f6f6;text-align:left;position:sticky;top:0}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace}
.bad{background:#fff1f1}
.warn{background:#fff9e6}
.note{margin-top:10px;color:#444;font-size:12px}
""")
print("</style></head><body>")
print(f"<h1>{html.escape(title)}</h1>")
print(f"<p class='small'>Generated: <span class='mono'>{now}</span><br>{html.escape(subtitle)}</p>")

if err:
    print("<p class='bad'><b>Error:</b> " + html.escape(err) + "</p></body></html>")
    sys.exit(0)

if not rows:
    print("<p class='warn'><b>No data</b> for sys_topproc_rss_kb on this instance.</p></body></html>")
    sys.exit(0)

print("<table><thead><tr>"
      "<th>#</th><th>USER</th><th>PID</th><th>%CPU</th><th>%MEM</th>"
      "<th>VSZ (KB)</th><th>RSS (KB)</th><th>COMM</th><th>EXE_PATH</th>"
      "</tr></thead><tbody>")

for idx, r in enumerate(rows, start=1):
    pid = r["pid"]
    cpu = pcpu.get(pid, 0.0) if isinstance(pcpu, dict) else 0.0
    mem = pmem.get(pid, 0.0) if isinstance(pmem, dict) else 0.0
    vsz_kb = vsz.get(pid, 0.0) if isinstance(vsz, dict) else 0.0

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
          f"<td class='mono'>{html.escape(r['exe'])}</td></tr>")

print("</tbody></table>")
print("<div class='note mono'>PromQL used:<br>" + html.escape(rss_q) + "</div>")
print("</body></html>")
PY

install -m 0644 "$TMP" "$OUTFILE"
chmod 0644 "$OUTFILE" 2>/dev/null || true

# Also create dot-style alias: topproc_192.168.10.10_9100.html -> topproc_192_168_10_10_9100.html
if [[ "$INSTANCE" =~ ^([0-9.]+):([0-9]+)$ ]]; then
  DOT_ALIAS="$REPORT_DIR/topproc_${BASH_REMATCH[1]}_${BASH_REMATCH[2]}.html"
  rm -f "$DOT_ALIAS" 2>/dev/null || true
  ln -sf "$(basename "$OUTFILE")" "$DOT_ALIAS"
  chmod 0644 "$DOT_ALIAS" 2>/dev/null || true
fi

echo "Saved: $OUTFILE"
echo "Open URL: http://<WAZUH-SERVER-IP>:8088/$(basename "$OUTFILE")"
