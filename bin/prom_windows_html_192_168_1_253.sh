#!/usr/bin/env bash
set -euo pipefail

PROM="http://127.0.0.1:9090"
OUT="/opt/monitoring/reports/win_192_168_1_253_9182.html"
INSTANCE="192.168.1.253:9182"

python3 - <<'PY'
import json, urllib.parse, urllib.request, datetime, html

PROM="http://127.0.0.1:9090"
OUT="/opt/monitoring/reports/win_192_168_1_253_9182.html"
INSTANCE="192.168.1.253:9182"

def q(query: str):
    url = PROM + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    with urllib.request.urlopen(url, timeout=6) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data.get("data", {}).get("result", [])

def one(query: str):
    r = q(query)
    if not r: return None
    try: return float(r[0]["value"][1])
    except Exception: return None

def esc(s): return html.escape("" if s is None else str(s))

def fmt(x, nd=1):
    return "—" if x is None else f"{x:.{nd}f}"

def short_user(u: str) -> str:
    # Turn DOMAIN\\User into User (keep full if no slash)
    if not u: return ""
    return u.split("\\")[-1]

now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Up + labels (job/alias)
up_res = q(f'up{{instance="{INSTANCE}"}}')
up = None
job = ""
alias = ""
if up_res:
    up = float(up_res[0]["value"][1])
    m = up_res[0].get("metric", {})
    job = m.get("job","")
    alias = m.get("alias","")

# Textfile health
tfe = one(f'windows_textfile_scrape_error{{instance="{INSTANCE}"}}')

# SSH + SMB summaries
ssh_total = one(f'win_ssh_sessions_total{{instance="{INSTANCE}"}}') or 0.0
ssh_users = q(f'win_ssh_sessions{{instance="{INSTANCE}"}}')
ssh_user_summ = []
for r in ssh_users:
    u = r["metric"].get("user","")
    v = r["value"][1]
    if u:
        ssh_user_summ.append(f"{short_user(u)} ({v})")
ssh_user_line = ", ".join(sorted(ssh_user_summ)) if ssh_user_summ else "—"

smb_total = one(f'win_smb_sessions_total{{instance="{INSTANCE}"}}') or 0.0
smb_users = q(f'win_smb_sessions{{instance="{INSTANCE}"}}')
smb_user_summ = []
for r in smb_users:
    u = r["metric"].get("user","")
    v = r["value"][1]
    if u:
        smb_user_summ.append(f"{u} ({v})")
smb_user_line = ", ".join(sorted(smb_user_summ)) if smb_user_summ else "—"

shares = q(f'win_smb_share_info{{instance="{INSTANCE}"}}')
share_names = sorted({r["metric"].get("share","") for r in shares if r["metric"].get("share","")})
share_line = ", ".join(share_names) if share_names else "—"

# Top processes (ranked by RSS)
rss = q(f'topk(15, sys_topproc_rss_kb{{instance="{INSTANCE}"}})')
cpu = {r["metric"].get("pid"): float(r["value"][1]) for r in q(f'sys_topproc_pcpu_percent{{instance="{INSTANCE}"}}')}
mem = {r["metric"].get("pid"): float(r["value"][1]) for r in q(f'sys_topproc_pmem_percent{{instance="{INSTANCE}"}}')}

rows = []
for r in rss:
    m = r.get("metric", {})
    pid = m.get("pid","")
    name = m.get("name","")
    cmd  = m.get("cmd","")  # best-effort
    rss_kb = float(r["value"][1])
    rows.append((pid, name, cmd, cpu.get(pid), mem.get(pid), rss_kb))

# HTML (tower-style)
h = []
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
  td{color:#e5e7eb}
</style>
""")
h.append("</head><body><div class='wrap'>")

# Top summary card
h.append("<div class='card'>")
h.append("<div class='grid'>")
h.append(f"<div><div class='k'>Instance</div><div class='v'>{esc(INSTANCE)}</div></div>")
h.append(f"<div><div class='k'>Alias</div><div class='v'>{esc(alias or 'win11-vm')}</div></div>")
h.append(f"<div><div class='k'>Job</div><div class='v'>{esc(job or '—')}</div></div>")
h.append(f"<div class='right'><div class='k'>Up</div><div class='v'>{'1' if up==1 else ('0' if up==0 else '—')}</div></div>")
h.append("</div>")  # grid

# Lines (tower-style)
h.append(f"<div class='line'>Docker: N/A</div>")
h.append(f"<div class='line'>Running containers: N/A</div>")
h.append(f"<div class='line'>SSH sessions: {int(ssh_total)}</div>")
h.append(f"<div class='line'>SSH users: {esc(ssh_user_line)}</div>")
h.append(f"<div class='line'>SMB sessions: {int(smb_total)}</div>")
h.append(f"<div class='line'>SMB users (active): {esc(smb_user_line)}</div>")
h.append(f"<div class='line'>SMB shares: {esc(share_line)}</div>")
h.append(f"<div class='line'>Textfile scrape error: {fmt(tfe,0)}</div>")
h.append(f"<div class='line'>Generated: {esc(now)} via {esc(PROM)}</div>")
h.append("</div>")  # card

# Top processes card
h.append("<div class='card'>")
h.append("<h3>Top processes (by RSS)</h3>")
h.append("<table>")
h.append("<tr><th>Rank</th><th>User</th><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>RSS (MB)</th></tr>")
for i,(pid,name,cmd,c,m,rss_kb) in enumerate(rows, start=1):
    rss_mb = rss_kb/1024.0
    command = name or cmd or ""
    h.append(
        "<tr>"
        f"<td>{i}</td>"
        f"<td>N/A</td>"
        f"<td>{esc(pid)}</td>"
        f"<td>{esc(command)}</td>"
        f"<td>{fmt(c,1)}</td>"
        f"<td>{fmt(m,1)}</td>"
        f"<td>{rss_mb:.1f}</td>"
        "</tr>"
    )
h.append("</table>")
h.append("</div>")

# Docker card (tower-style but N/A)
h.append("<div class='card'>")
h.append("<h3>Docker container list</h3>")
h.append("<div class='line'>Docker containers (running): N/A</div>")
h.append("</div>")

h.append("</div></body></html>")

open(OUT, "w", encoding="utf-8").write("".join(h))
print("OK wrote:", OUT)
PY
