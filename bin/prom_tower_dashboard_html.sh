#!/usr/bin/env bash
set -euo pipefail

INSTANCE="${1:-}"
if [[ -z "$INSTANCE" ]]; then
  echo "Usage: $0 <ip:9100>"
  exit 1
fi

PROM_URL="${PROM_URL:-http://127.0.0.1:9090}"
OUTDIR="/opt/monitoring/reports"
mkdir -p "$OUTDIR"

# Run the restored base generator
/opt/monitoring/bin/prom_tower_dashboard_html.base.sh "$INSTANCE"

# Determine output filename (support both styles that exist in your env)
OUT_UNDERSCORE="$OUTDIR/tower_${INSTANCE//[:.]/_}.html"
OUT_DOT="$OUTDIR/tower_${INSTANCE//:/_}.html"

OUT=""
if [[ -f "$OUT_UNDERSCORE" ]]; then OUT="$OUT_UNDERSCORE"; fi
if [[ -z "$OUT" && -f "$OUT_DOT" ]]; then OUT="$OUT_DOT"; fi
if [[ -z "$OUT" ]]; then
  echo "WARN: could not find output HTML for $INSTANCE (tried: $OUT_UNDERSCORE and $OUT_DOT)"
  exit 0
fi

python3 - "$INSTANCE" "$PROM_URL" "$OUT" <<'PY'
import json, sys, html
from urllib.request import urlopen
from urllib.parse import urlencode

instance = sys.argv[1]
prom = sys.argv[2].rstrip("/")
out = sys.argv[3]
target_ip = instance.split(":")[0]

def h(x): return html.escape(str(x), quote=True)

def prom_query(q: str):
    url = f"{prom}/api/v1/query?{urlencode({'query': q})}"
    with urlopen(url, timeout=8) as r:
        data = json.loads(r.read().decode("utf-8"))
    if data.get("status") != "success":
        return []
    return data.get("data", {}).get("result", []) or []

def q_one(q: str):
    r = prom_query(q)
    if not r: return None
    try:
        return float(r[0]["value"][1])
    except Exception:
        return None

# Docker list from textfile collector (target label)
dock = prom_query(f'tower_docker_container_running{{target="{target_ip}"}}')
docker_names = sorted({x.get("metric", {}).get("name","") for x in dock if x.get("metric", {}).get("name")})

docker_html = []
docker_html.append("<div class='card'>")
docker_html.append("<div class='v'>Docker container list</div>")
docker_html.append(f"<div class='small'><b>Docker containers (running): {len(docker_names)}</b></div>")
if docker_names:
    docker_html.append("<div class='small'>" + "<br>".join(h(n) for n in docker_names) + "</div>")
else:
    docker_html.append("<div class='small'>No docker list data found (check tower_docker_list_up / SSH).</div>")
docker_html.append("</div>")
docker_block = "".join(docker_html)

# Unraid summary (only for 192.168.10.10)
unraid_block = ""
if target_ip == "192.168.10.10":
    up = q_one('tower_unraid_up{target="192.168.10.10"}')
    arr_pct = q_one('tower_unraid_array_used_percent{target="192.168.10.10"}')
    parity_ok = q_one('tower_unraid_parity_valid{target="192.168.10.10"}')

    unraid_html = []
    unraid_html.append("<div class='card'>")
    unraid_html.append("<div class='v'>Unraid status (Tower 192.168.10.10)</div>")
    unraid_html.append(f"<div class='small'>Collector up: {h(int(up) if up is not None else 'N/A')}</div>")
    unraid_html.append(f"<div class='small'>Parity valid: {h(int(parity_ok) if parity_ok is not None else 'N/A')}</div>")
    unraid_html.append(f"<div class='small'>Array used %: {h(f'{arr_pct:.1f}' if arr_pct is not None else 'N/A')}</div>")
    unraid_html.append("<!-- UNRAID_DETAILS_PLACEHOLDER -->")
    unraid_html.append("</div>")
    unraid_block = "".join(unraid_html)

# Inject blocks before </body> (safe append without depending on base HTML structure)
with open(out, "r", encoding="utf-8") as f:
    page = f.read()

ins = docker_block + unraid_block
if "</body>" in page:
    page = page.replace("</body>", ins + "</body>", 1)
else:
    page = page + ins

with open(out, "w", encoding="utf-8") as f:
    f.write(page)

print("Patched:", out)
PY
