#!/usr/bin/env bash
set -euo pipefail

F="/opt/monitoring/bin/prom_tower_dashboard_html.base.sh"
TS="$(date +%F_%H%M%S)"
BAK="${F}.bak.${TS}"

sudo cp -a "$F" "$BAK"

python3 - <<'PY'
import re
from pathlib import Path

p = Path("/opt/monitoring/bin/prom_tower_dashboard_html.base.sh")
s = p.read_text(encoding="utf-8", errors="ignore")

MARK = "UNRAID_PROMFILE_RENDER_V1"
if MARK in s:
    print("NO CHANGE: already patched:", p)
    raise SystemExit(0)

pattern = re.compile(
    r'^(?P<i>\s*)print\(\s*"\(More parity/array/cache/device fields will appear once tower_unraid\.prom parsing is fixed\.\)"\s*\)\s*$',
    re.M
)

def repl(m):
    i = m.group("i")
    return f"""{i}# {MARK}
{i}# Work-around: render cache/system_cache/device details from local prom file
{i}try:
{i}    import re as _re
{i}    _tgt = instance.split(":")[0]
{i}    _prom_path = "/opt/monitoring/textfile_collector/tower_unraid.prom"
{i}    _metrics = {{}}
{i}    _temps = {{}}
{i}    _utils = {{}}
{i}    _devinfo = []
{i}    with open(_prom_path, "r", encoding="utf-8", errors="ignore") as _fh:
{i}        for _line in _fh:
{i}            if _line.startswith("#") or "target=" not in _line:
{i}                continue
{i}            if f'target="{{_tgt}}"' not in _line:
{i}                continue
{i}            _m = _re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\\{{([^}}]*)\\}}\\s+(.+)$', _line.strip())
{i}            if not _m:
{i}                continue
{i}            _name, _labels, _val = _m.group(1), _m.group(2), _m.group(3)
{i}            _lbl = dict(_re.findall(r'(\\w+)="([^"]*)"', _labels))
{i}            try:
{i}                _fv = float(_val)
{i}            except Exception:
{i}                continue
{i}            if _name in (
{i}                "tower_unraid_array_size_bytes","tower_unraid_array_used_bytes","tower_unraid_array_used_percent",
{i}                "tower_unraid_cache_size_bytes","tower_unraid_cache_used_bytes","tower_unraid_cache_used_percent",
{i}                "tower_unraid_system_cache_size_bytes","tower_unraid_system_cache_used_bytes","tower_unraid_system_cache_used_percent",
{i}            ):
{i}                _metrics[_name] = _fv
{i}            elif _name == "tower_unraid_device_temp_celsius":
{i}                _temps[_lbl.get("device","?")] = _fv
{i}            elif _name == "tower_unraid_device_utilization_percent":
{i}                _utils[_lbl.get("device","?")] = _fv
{i}            elif _name == "tower_unraid_device_info":
{i}                _devinfo.append((_lbl.get("device","?"), _lbl.get("status","?"), _lbl.get("smart","?"), _lbl.get("type","?")))
{i}
{i}    def _fmt_bytes(b):
{i}        if b is None:
{i}            return "—"
{i}        x = float(b)
{i}        for u in ("B","KB","MB","GB","TB","PB"):
{i}            if x < 1024.0:
{i}                return f"{{x:.2f}} {{u}}"
{i}            x /= 1024.0
{i}        return f"{{x:.2f}} EB"
{i}
{i}    if _metrics:
{i}        print(f"Cache used %: {{_metrics.get('tower_unraid_cache_used_percent',0):.1f}}  ({{_fmt_bytes(_metrics.get('tower_unraid_cache_used_bytes'))}} / {{_fmt_bytes(_metrics.get('tower_unraid_cache_size_bytes'))}})")
{i}        print(f"System cache used %: {{_metrics.get('tower_unraid_system_cache_used_percent',0):.1f}}  ({{_fmt_bytes(_metrics.get('tower_unraid_system_cache_used_bytes'))}} / {{_fmt_bytes(_metrics.get('tower_unraid_system_cache_size_bytes'))}})")
{i}
{i}    if _devinfo:
{i}        print("Device\\tType\\tStatus\\tTemp(C)\\tSMART\\tUtil(%)")
{i}        for d, st, sm, ty in sorted(_devinfo, key=lambda x: x[0]):
{i}            t = _temps.get(d)
{i}            u = _utils.get(d)
{i}            t_s = f"{{t:.0f}}" if t is not None else "—"
{i}            u_s = f"{{u:.1f}}" if u is not None else "—"
{i}            print(f"{{d}}\\t{{ty}}\\t{{st}}\\t{{t_s}}\\t{{sm}}\\t{{u_s}}")
{i}except Exception:
{i}    pass"""

ns, n = pattern.subn(repl, s, count=1)
if n == 0:
    print("ERROR: placeholder line not found to replace.")
    print("TIP: search for the placeholder text in:", p)
    raise SystemExit(2)

p.write_text(ns, encoding="utf-8")
print("OK patched:", p)
PY
