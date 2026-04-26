#!/usr/bin/env bash
# Create merged Security Operations Center dashboard
# Combines Alert Command Center (Prometheus) + Wazuh Security Events (OpenSearch)
set -euo pipefail

GRAFANA="http://127.0.0.1:3000"
AUTH="Authorization: Basic $(echo -n 'admin:admin' | base64)"
DS_PROM="afiwke54zcjcwe"
DS_WAZUH="ffk7w5f7pkv7kd"

echo "Building Security Operations Center dashboard..."

python3 << PYEOF
import json, base64, urllib.request, sys

GRAFANA = "http://127.0.0.1:3000"
AUTH = "Basic " + base64.b64encode(b"admin:admin").decode()
DS_PROM  = "afiwke54zcjcwe"
DS_WAZUH = "ffk7w5f7pkv7kd"

def get_dash(uid):
    req = urllib.request.Request(f"{GRAFANA}/api/dashboards/uid/{uid}",
                                 headers={"Authorization": AUTH})
    return json.loads(urllib.request.urlopen(req).read())["dashboard"]

acc = get_dash("alert-command-center")
wse = get_dash("wazuh-security-events")

def find(panels, pid):
    return next(p for p in panels if p["id"] == pid)

def place(panel, new_id, x, y, w, h):
    p = json.loads(json.dumps(panel))   # deep copy
    p["id"] = new_id
    p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
    return p

# ── Row helper ──────────────────────────────────────────────────────────────
def row(new_id, title, y, collapsed=False):
    return {
        "id": new_id, "type": "row", "title": title,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "collapsed": collapsed, "panels": []
    }

panels = []
nid = 100   # start IDs fresh to avoid collisions

# ═══════════════════════════════════════════════════════════════════════════
# ROW A — Prometheus Alert Status
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Prometheus Alert Status", y=0)); nid+=1

# 6 stat cards from ACC, row 0
acc_stats = [
    (1, "Critical Alerts",           0,  1, 4, 4),
    (2, "Warning Alerts",            4,  1, 4, 4),
    (3, "Info Alerts",               8,  1, 4, 4),
    (4, "Total Firing",             12,  1, 4, 4),
    (5, "Pending (not yet firing)", 16,  1, 4, 4),
    (6, "Prometheus Targets Down",  20,  1, 4, 4),
]
for (pid, _, x, y, w, h) in acc_stats:
    panels.append(place(find(acc["panels"], pid), nid, x, y, w, h)); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW B — Wazuh SIEM Stats
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Wazuh SIEM Stats", y=5)); nid+=1

wse_stats = [
    (1, "Total Events (24h)",       0,  6, 4, 3),
    (2, "Critical (Level ≥ 12)",    4,  6, 4, 3),
    (3, "High (Level 7-11)",        8,  6, 4, 3),
    (4, "SSH Auth Failures (24h)", 12,  6, 4, 3),
    (5, "Sudo / Root Events (24h)",16,  6, 4, 3),
    (6, "Unique Agents Reporting", 20,  6, 4, 3),
]
for (pid, _, x, y, w, h) in wse_stats:
    panels.append(place(find(wse["panels"], pid), nid, x, y, w, h)); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW C — Timelines
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Timelines (24h)", y=9)); nid+=1

# Prometheus: Alert History (w=12, left)
p = place(find(acc["panels"], 10), nid, 0, 10, 12, 8)
p["title"] = "Prometheus — Firing Alerts by Severity"
panels.append(p); nid+=1

# Wazuh: Alert Volume (w=12, right)
p = place(find(wse["panels"], 10), nid, 12, 10, 12, 8)
p["title"] = "Wazuh SIEM — Events by Severity"
panels.append(p); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW D — Active Alerts (Prometheus firing table — most important, full width)
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Active Prometheus Alerts", y=18)); nid+=1

p = place(find(acc["panels"], 20), nid, 0, 19, 24, 12)
panels.append(p); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW E — Wazuh Live Alerts
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Wazuh — Live High/Critical Events", y=31)); nid+=1

p = place(find(wse["panels"], 30), nid, 0, 32, 24, 10)
panels.append(p); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW F — Analysis: Top Rules + SSH Failures
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Attack Analysis", y=42)); nid+=1

p = place(find(wse["panels"], 20), nid, 0, 43, 12, 8)
panels.append(p); nid+=1

p = place(find(wse["panels"], 21), nid, 12, 43, 12, 8)
panels.append(p); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW G — Sudo/Root Escalations
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Privilege Escalations", y=51)); nid+=1

p = place(find(wse["panels"], 40), nid, 0, 52, 24, 8)
panels.append(p); nid+=1

# ═══════════════════════════════════════════════════════════════════════════
# ROW H — Infrastructure: Pending + Targets Down + Categories + Agents + Trend
# ═══════════════════════════════════════════════════════════════════════════
panels.append(row(nid, "Infrastructure & Trends", y=60)); nid+=1

p = place(find(acc["panels"], 30), nid,  0, 61, 12, 8)
panels.append(p); nid+=1

p = place(find(acc["panels"], 31), nid, 12, 61, 12, 8)
panels.append(p); nid+=1

# Category donut + Agent pie + 7-day trend
p = place(find(acc["panels"], 40), nid,  0, 69, 8, 8)
panels.append(p); nid+=1

p = place(find(wse["panels"], 11), nid,  8, 69, 8, 8)
p["title"] = "Wazuh Events by Agent"
panels.append(p); nid+=1

p = place(find(acc["panels"], 41), nid, 16, 69, 8, 8)
panels.append(p); nid+=1

# ── Build final dashboard ──────────────────────────────────────────────────
dashboard = {
    "uid":           "security-ops-center",
    "title":         "Security Operations Center",
    "tags":          ["soc", "wazuh", "prometheus", "security"],
    "timezone":      "browser",
    "refresh":       "60s",
    "time":          {"from": "now-24h", "to": "now"},
    "schemaVersion": 36,
    "panels":        panels,
    "links": [
        {
            "title": "Alert Command Center",
            "url":   "/d/alert-command-center",
            "type":  "link", "icon": "external link", "targetBlank": False
        },
        {
            "title": "Employee Reconcile",
            "url":   "/d/employee-reconcile",
            "type":  "link", "icon": "external link", "targetBlank": False
        }
    ]
}

payload = json.dumps({"overwrite": True, "folderId": 0, "dashboard": dashboard})

req = urllib.request.Request(
    f"{GRAFANA}/api/dashboards/db",
    data=payload.encode(),
    headers={"Content-Type": "application/json", "Authorization": AUTH},
    method="POST"
)
resp = json.loads(urllib.request.urlopen(req).read())
print(json.dumps(resp, indent=2))
PYEOF

echo ""
echo "Exporting portable JSON..."
python3 << 'EXPORTEOF'
import json, base64, urllib.request

GRAFANA = "http://127.0.0.1:3000"
AUTH = "Basic " + base64.b64encode(b"admin:admin").decode()

req = urllib.request.Request(
    f"{GRAFANA}/api/dashboards/uid/security-ops-center",
    headers={"Authorization": AUTH}
)
data = json.loads(urllib.request.urlopen(req).read())
dash = data["dashboard"]

for k in ("id", "version"):
    dash.pop(k, None)

dash_str = json.dumps(dash)
dash_str = dash_str.replace("afiwke54zcjcwe", "${DS_PROMETHEUS}")
dash_str = dash_str.replace("ffk7w5f7pkv7kd", "${DS_WAZUH_INDEXER}")
dash = json.loads(dash_str)

portable = {
    "__inputs": [
        {
            "name": "DS_PROMETHEUS", "label": "Prometheus",
            "type": "datasource", "pluginId": "prometheus"
        },
        {
            "name": "DS_WAZUH_INDEXER", "label": "Wazuh Indexer",
            "type": "datasource", "pluginId": "grafana-opensearch-datasource"
        }
    ],
    "__requires": [
        {"type": "grafana",    "id": "grafana",                         "name": "Grafana",    "version": "10.0.0"},
        {"type": "datasource", "id": "prometheus",                      "name": "Prometheus", "version": "1.0.0"},
        {"type": "datasource", "id": "grafana-opensearch-datasource",   "name": "OpenSearch", "version": "1.0.0"},
        {"type": "panel",      "id": "stat",       "name": "Stat",       "version": ""},
        {"type": "panel",      "id": "timeseries", "name": "Time series","version": ""},
        {"type": "panel",      "id": "piechart",   "name": "Pie chart",  "version": ""},
        {"type": "panel",      "id": "table",      "name": "Table",      "version": ""}
    ]
}
portable.update(dash)

out = "/opt/monitoring/dashboards/security-ops-center.json"
with open(out, "w") as f:
    json.dump(portable, f, indent=2)

panel_count = len(dash["panels"])
print(f"Exported: {out}")
print(f"Panels:   {panel_count}")
EXPORTEOF

echo ""
echo "URL: http://192.168.10.20:3000/d/security-ops-center"
