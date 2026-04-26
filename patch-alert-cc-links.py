#!/usr/bin/env python3
"""
Add clickable data links to the Alert Command Center dashboard:
- Alert name cell → Grafana Explore (shows the full metric + labels)
- Alert name cell → Prometheus /alerts page
- Alert name cell → relevant Grafana dashboard (infra/gworkspace/network/containers)
- Instance cell → Fleet Overview filtered to that host
"""
import json, urllib.request, urllib.parse, base64, sys

GRAFANA = "http://127.0.0.1:3000"
AUTH = base64.b64encode(b"admin:admin").decode()
HEADERS = {"Authorization": f"Basic {AUTH}", "Content-Type": "application/json"}

def gget(path):
    req = urllib.request.Request(f"{GRAFANA}{path}", headers=HEADERS)
    return json.loads(urllib.request.urlopen(req).read())

def gpost(path, body):
    req = urllib.request.Request(f"{GRAFANA}{path}", data=json.dumps(body).encode(), headers=HEADERS, method="POST")
    return json.loads(urllib.request.urlopen(req).read())

# Fetch current dashboard
data = gget("/api/dashboards/uid/alert-command-center")
dash = data["dashboard"]
folder_id = data.get("meta", {}).get("folderId", 0)

# --- Data links for the Alert name cell ---
# Grafana Explore link: shows ALERTS{alertname="<value>"} in Explore
# ${__data.fields.Alert} is substituted by Grafana at click time
explore_query = 'ALERTS{alertname="${__data.fields.Alert}",alertstate="firing"}'
explore_url = (
    '/explore?orgId=1&left='
    + urllib.parse.quote(json.dumps({
        "datasource": "Prometheus",
        "queries": [{"expr": explore_query, "refId": "A", "instant": True}],
        "range": {"from": "now-1h", "to": "now"}
    }), safe='')
)

alert_links = [
    {
        "title": "Explore metric in Grafana",
        "url": explore_url,
        "targetBlank": True
    },
    {
        "title": "Prometheus /alerts page",
        "url": "http://localhost:9090/alerts",
        "targetBlank": True
    },
    # Category-based dashboard shortcuts — all shown, pick the relevant one
    {
        "title": "→ Fleet Overview (infra/host alerts)",
        "url": "/d/fleet-overview/fleet-overview",
        "targetBlank": False
    },
    {
        "title": "→ Google Workspace (GWorkspace alerts)",
        "url": "/d/google-workspace/google-workspace",
        "targetBlank": False
    },
    {
        "title": "→ Network Inventory (network/ARP alerts)",
        "url": "/d/network-inventory/network-inventory",
        "targetBlank": False
    },
    {
        "title": "→ Docker Containers (container alerts)",
        "url": "/d/docker-containers/docker-containers",
        "targetBlank": False
    },
]

# --- Data links for the Instance cell → Fleet Overview ---
instance_links = [
    {
        "title": "Fleet Overview for this host",
        "url": "/d/fleet-overview/fleet-overview?var-instance=${__data.fields.Instance}",
        "targetBlank": False
    }
]

# --- Patch panel id=20 (All Firing Alerts table) ---
for panel in dash["panels"]:
    if panel["id"] == 20:
        overrides = panel["fieldConfig"].get("overrides", [])

        # Add/replace Alert field override with links
        alert_override_found = False
        for ov in overrides:
            if ov["matcher"].get("options") == "Alert":
                # Append links property if not present
                props = ov["properties"]
                props = [p for p in props if p["id"] != "links"]  # remove old links
                props.append({"id": "links", "value": alert_links})
                ov["properties"] = props
                alert_override_found = True
                break

        if not alert_override_found:
            overrides.append({
                "matcher": {"id": "byName", "options": "Alert"},
                "properties": [
                    {"id": "custom.width", "value": 280},
                    {"id": "links", "value": alert_links}
                ]
            })

        # Add Instance field override with links
        instance_override_found = False
        for ov in overrides:
            if ov["matcher"].get("options") == "Instance":
                props = ov["properties"]
                props = [p for p in props if p["id"] != "links"]
                props.append({"id": "links", "value": instance_links})
                ov["properties"] = props
                instance_override_found = True
                break

        if not instance_override_found:
            overrides.append({
                "matcher": {"id": "byName", "options": "Instance"},
                "properties": [
                    {"id": "custom.width", "value": 200},
                    {"id": "links", "value": instance_links}
                ]
            })

        panel["fieldConfig"]["overrides"] = overrides
        print(f"Patched panel id=20: {len(alert_links)} alert links, {len(instance_links)} instance links")
        break

# Push back to Grafana
resp = gpost("/api/dashboards/db", {"dashboard": dash, "folderId": folder_id, "overwrite": True})
if resp.get("status") == "success":
    print(f"Dashboard updated OK — {resp['url']}")
else:
    print(f"ERROR: {resp}")
    sys.exit(1)

# Re-export portable JSON
exported = gget("/api/dashboards/uid/alert-command-center")
clean = exported["dashboard"]
clean.pop("id", None)
clean.pop("version", None)

envelope = {
    "__inputs": [
        {
            "name": "DS_PROMETHEUS",
            "label": "Prometheus",
            "description": "Prometheus datasource",
            "type": "datasource",
            "pluginId": "prometheus",
            "pluginName": "Prometheus"
        }
    ],
    "__requires": [
        {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "9.0.0"},
        {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
        {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
        {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
        {"type": "panel", "id": "table", "name": "Table", "version": ""},
        {"type": "panel", "id": "piechart", "name": "Pie chart", "version": ""}
    ]
}
envelope.update(clean)

raw = json.dumps(envelope, indent=2).replace('"uid": "afiwke54zcjcwe"', '"uid": "${DS_PROMETHEUS}"')
with open("/opt/monitoring/dashboards/alert-command-center.json", "w") as f:
    f.write(raw)
print("Portable JSON re-exported to /opt/monitoring/dashboards/alert-command-center.json")
