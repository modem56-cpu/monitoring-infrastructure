#!/usr/bin/env bash
set -euo pipefail

INSTANCE="${1:-}"
PROM_URL="${PROM_URL:-http://127.0.0.1:9090}"

if [[ -z "$INSTANCE" ]]; then
  echo "Usage: $0 <instance_ip:9100>"
  exit 2
fi

SAFE_INSTANCE="$(echo "$INSTANCE" | tr '.:' '___')"
OUT="/opt/monitoring/reports/tower_${SAFE_INSTANCE}.html"

python3 - "$OUT" "$INSTANCE" "$PROM_URL" <<'PY'
import json, sys
import urllib.parse, urllib.request
from datetime import datetime, timezone

out_path, instance, prom_url = sys.argv[1], sys.argv[2], sys.argv[3]

def q(query: str):
    url = f"{prom_url}/api/v1/query?{urllib.parse.urlencode({'query': query})}"
    with urllib.request.urlopen(url, timeout=8) as r:
        data = json.loads(r.read().decode("utf-8"))
    res = data.get("data", {}).get("result", [])
    if not res:
        return None
    # vector -> take first sample
    v = res[0].get("value", [None, None])[1]
    try:
        return float(v)
    except Exception:
        return v

def qv(query: str):
    """Return full vector results (list)."""
    url = f"{prom_url}/api/v1/query?{urllib.parse.urlencode({'query': query})}"
    with urllib.request.urlopen(url, timeout=8) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data.get("data", {}).get("result", [])

def fmt_num(v, digits=2):
    if v is None:
        return "N/A"
    if isinstance(v, (int, float)):
        if abs(v) >= 1000:
            return f"{v:,.0f}"
        return f"{v:.{digits}f}".rstrip("0").rstrip(".")
    return str(v)

def esc(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

# Core availability
up = q(f'up{{instance="{instance}"}}')

# Tower extras
docker_running = q(f'tower_docker_running{{instance="{instance}"}}')
docker_total   = q(f'tower_docker_total{{instance="{instance}"}}')
ssh_sessions   = q(f'tower_ssh_sessions{{instance="{instance}"}}')

# Processes (Top 15 by RSS)
rows = qv(f'topk(15, sys_topproc_rss_kb{{instance="{instance}"}})')
proc = []
# Build map by rank (or by rss order if no rank label)
for r in rows:
    m = r.get("metric", {})
    rss = float(r.get("value", [0,0])[1])
    proc.append({
        "rank": m.get("rank",""),
        "user": m.get("user",""),
        "pid": m.get("pid",""),
        "comm": m.get("comm",""),
        "exe": m.get("exe",""),
        "rss_kb": rss,
    })

# Sort rank numerically if present else by rss desc
def rk(x):
    try: return int(x["rank"])
    except: return 10**9
proc.sort(key=lambda x: (rk(x), -x["rss_kb"]))

gen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Tower Dashboard (Ubuntu) — {esc(instance)}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 18px; color:#111; }}
  .sub {{ color:#444; font-size: 13px; margin-bottom: 12px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; }}
  .card {{ border:1px solid #ddd; border-radius:10px; padding:12px 14px; min-width: 240px; }}
  .k {{ font-size: 12px; color:#555; }}
  .v {{ font-size: 18px; font-weight: 700; margin-top: 6px; }}
  table {{ width:100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ border-bottom:1px solid #eee; padding:8px 6px; font-size: 13px; text-align:left; vertical-align: top; }}
  th {{ background:#fafafa; }}
  .muted {{ color:#777; }}
</style>
</head>
<body>
  <h2>Tower Dashboard (Ubuntu) — {esc(instance)}</h2>
  <div class="sub">Generated: {gen} | Prometheus: {esc(prom_url)} | up={fmt_num(up,0)}</div>

  <div class="cards">
    <div class="card">
      <div class="k">Tower Extras (textfile metrics)</div>
      <div class="v">Docker: {fmt_num(docker_running,0)} running / {fmt_num(docker_total,0)} total</div>
      <div class="muted" style="margin-top:6px;">SSH sessions: {fmt_num(ssh_sessions,0)}</div>
    </div>
  </div>

  <h3 style="margin-top:18px;">Top processes by RSS</h3>
  <table>
    <thead>
      <tr>
        <th>#</th><th>User</th><th>PID</th><th>RSS KB</th><th>COMM</th><th>EXE</th>
      </tr>
    </thead>
    <tbody>
"""
if not proc:
    html += '<tr><td colspan="6" class="muted">No sys_topproc data found for this instance.</td></tr>\n'
else:
    for i, p in enumerate(proc, start=1):
        html += (
            f"<tr>"
            f"<td>{esc(str(p.get('rank') or i))}</td>"
            f"<td>{esc(p.get('user',''))}</td>"
            f"<td>{esc(p.get('pid',''))}</td>"
            f"<td>{esc(fmt_num(p.get('rss_kb',0),0))}</td>"
            f"<td>{esc(p.get('comm',''))}</td>"
            f"<td style='max-width:520px; word-break:break-word;'>{esc(p.get('exe',''))}</td>"
            f"</tr>\n"
        )

html += """    </tbody>
  </table>
</body>
</html>
"""

with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)

print(f"Saved: {out_path}")
PY
