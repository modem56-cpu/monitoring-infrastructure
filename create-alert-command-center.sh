#!/usr/bin/env bash
# Create Alert Command Center dashboard in Grafana
# Pure Prometheus queries — no new infrastructure needed
set -euo pipefail

GRAFANA="http://admin:admin@127.0.0.1:3000"
DS_UID="afiwke54zcjcwe"

DASHBOARD=$(cat << 'ENDJSON'
{
  "dashboard": {
    "uid": "alert-command-center",
    "title": "Alert Command Center",
    "tags": ["alerts", "overview"],
    "timezone": "browser",
    "refresh": "30s",
    "schemaVersion": 38,
    "panels": [

      {
        "id": 1,
        "type": "stat",
        "title": "Critical Alerts",
        "gridPos": { "x": 0, "y": 0, "w": 4, "h": 4 },
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "textMode": "auto",
          "reduceOptions": { "calcs": ["lastNotNull"] }
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "green", "value": null },
                { "color": "red", "value": 1 }
              ]
            },
            "mappings": [{ "type": "value", "options": { "0": { "text": "0", "color": "green" } } }]
          }
        },
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "count(ALERTS{alertstate=\"firing\",severity=\"critical\"}) or vector(0)",
          "legendFormat": "Critical",
          "instant": true
        }]
      },

      {
        "id": 2,
        "type": "stat",
        "title": "Warning Alerts",
        "gridPos": { "x": 4, "y": 0, "w": 4, "h": 4 },
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "textMode": "auto",
          "reduceOptions": { "calcs": ["lastNotNull"] }
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "green", "value": null },
                { "color": "yellow", "value": 1 }
              ]
            }
          }
        },
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "count(ALERTS{alertstate=\"firing\",severity=\"warning\"}) or vector(0)",
          "legendFormat": "Warning",
          "instant": true
        }]
      },

      {
        "id": 3,
        "type": "stat",
        "title": "Info Alerts",
        "gridPos": { "x": 8, "y": 0, "w": 4, "h": 4 },
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "textMode": "auto",
          "reduceOptions": { "calcs": ["lastNotNull"] }
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "green", "value": null },
                { "color": "blue", "value": 1 }
              ]
            }
          }
        },
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "count(ALERTS{alertstate=\"firing\",severity=\"info\"}) or vector(0)",
          "legendFormat": "Info",
          "instant": true
        }]
      },

      {
        "id": 4,
        "type": "stat",
        "title": "Total Firing",
        "gridPos": { "x": 12, "y": 0, "w": 4, "h": 4 },
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "textMode": "auto",
          "reduceOptions": { "calcs": ["lastNotNull"] }
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "green", "value": null },
                { "color": "orange", "value": 1 },
                { "color": "red", "value": 5 }
              ]
            }
          }
        },
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "count(ALERTS{alertstate=\"firing\"}) or vector(0)",
          "legendFormat": "Total",
          "instant": true
        }]
      },

      {
        "id": 5,
        "type": "stat",
        "title": "Pending (not yet firing)",
        "gridPos": { "x": 16, "y": 0, "w": 4, "h": 4 },
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "textMode": "auto",
          "reduceOptions": { "calcs": ["lastNotNull"] }
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "green", "value": null },
                { "color": "yellow", "value": 1 }
              ]
            }
          }
        },
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "count(ALERTS{alertstate=\"pending\"}) or vector(0)",
          "legendFormat": "Pending",
          "instant": true
        }]
      },

      {
        "id": 6,
        "type": "stat",
        "title": "Prometheus Targets Down",
        "gridPos": { "x": 20, "y": 0, "w": 4, "h": 4 },
        "options": {
          "colorMode": "background",
          "graphMode": "none",
          "textMode": "auto",
          "reduceOptions": { "calcs": ["lastNotNull"] }
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                { "color": "green", "value": null },
                { "color": "red", "value": 1 }
              ]
            }
          }
        },
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "count(up == 0) or vector(0)",
          "legendFormat": "Down",
          "instant": true
        }]
      },

      {
        "id": 10,
        "type": "timeseries",
        "title": "Alert History — Firing Count by Severity (24h)",
        "gridPos": { "x": 0, "y": 4, "w": 24, "h": 7 },
        "options": {
          "tooltip": { "mode": "multi" },
          "legend": { "displayMode": "list", "placement": "bottom" }
        },
        "fieldConfig": {
          "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 15 } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "critical" }, "properties": [{ "id": "color", "value": { "fixedColor": "red", "mode": "fixed" } }] },
            { "matcher": { "id": "byName", "options": "warning" }, "properties": [{ "id": "color", "value": { "fixedColor": "yellow", "mode": "fixed" } }] },
            { "matcher": { "id": "byName", "options": "info" }, "properties": [{ "id": "color", "value": { "fixedColor": "blue", "mode": "fixed" } }] }
          ]
        },
        "targets": [
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",severity=\"critical\"}) or vector(0)",
            "legendFormat": "critical"
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",severity=\"warning\"}) or vector(0)",
            "legendFormat": "warning"
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",severity=\"info\"}) or vector(0)",
            "legendFormat": "info"
          }
        ]
      },

      {
        "id": 20,
        "type": "table",
        "title": "All Firing Alerts",
        "gridPos": { "x": 0, "y": 11, "w": 24, "h": 12 },
        "options": {
          "sortBy": [{ "displayName": "Severity", "desc": false }],
          "footer": { "show": false }
        },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            {
              "matcher": { "id": "byName", "options": "Severity" },
              "properties": [
                { "id": "custom.width", "value": 100 },
                {
                  "id": "mappings",
                  "value": [
                    { "type": "value", "options": { "critical": { "color": "red", "index": 0 } } },
                    { "type": "value", "options": { "warning": { "color": "yellow", "index": 1 } } },
                    { "type": "value", "options": { "info": { "color": "blue", "index": 2 } } }
                  ]
                },
                { "id": "custom.displayMode", "value": "color-background" }
              ]
            },
            { "matcher": { "id": "byName", "options": "Alert" }, "properties": [{ "id": "custom.width", "value": 280 }] },
            { "matcher": { "id": "byName", "options": "Instance" }, "properties": [{ "id": "custom.width", "value": 200 }] },
            { "matcher": { "id": "byName", "options": "Value" }, "properties": [{ "id": "custom.width", "value": 100 }] },
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.hidden", "value": true }] }
          ]
        },
        "transformations": [
          { "id": "labelsToFields", "options": { "mode": "columns" } },
          {
            "id": "organize",
            "options": {
              "renameByName": {
                "alertname": "Alert",
                "severity": "Severity",
                "instance": "Instance",
                "alias": "Host",
                "job": "Job",
                "alertstate": "State",
                "Value": "Value"
              },
              "indexByName": {
                "Severity": 0,
                "Alert": 1,
                "Host": 2,
                "Instance": 3,
                "Job": 4,
                "State": 5,
                "Value": 6
              },
              "excludeByName": { "Time": true, "__name__": true }
            }
          }
        ],
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "ALERTS{alertstate=\"firing\"}",
          "legendFormat": "",
          "instant": true,
          "format": "table"
        }]
      },

      {
        "id": 30,
        "type": "table",
        "title": "Pending Alerts (evaluating — not yet firing)",
        "gridPos": { "x": 0, "y": 23, "w": 12, "h": 8 },
        "options": { "footer": { "show": false } },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Alert" }, "properties": [{ "id": "custom.width", "value": 260 }] },
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.hidden", "value": true }] }
          ]
        },
        "transformations": [
          { "id": "labelsToFields", "options": { "mode": "columns" } },
          {
            "id": "organize",
            "options": {
              "renameByName": { "alertname": "Alert", "severity": "Severity", "instance": "Instance", "alias": "Host" },
              "excludeByName": { "Time": true, "__name__": true, "alertstate": true }
            }
          }
        ],
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "ALERTS{alertstate=\"pending\"}",
          "legendFormat": "",
          "instant": true,
          "format": "table"
        }]
      },

      {
        "id": 31,
        "type": "table",
        "title": "Prometheus Targets Down",
        "gridPos": { "x": 12, "y": 23, "w": 12, "h": 8 },
        "options": { "footer": { "show": false } },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Instance" }, "properties": [{ "id": "custom.width", "value": 220 }] },
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.hidden", "value": true }] }
          ]
        },
        "transformations": [
          { "id": "labelsToFields", "options": { "mode": "columns" } },
          {
            "id": "organize",
            "options": {
              "renameByName": { "instance": "Instance", "job": "Job", "alias": "Host" },
              "excludeByName": { "Time": true, "__name__": true, "Value": true }
            }
          }
        ],
        "targets": [{
          "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "up == 0",
          "legendFormat": "",
          "instant": true,
          "format": "table"
        }]
      },

      {
        "id": 40,
        "type": "piechart",
        "title": "Alerts by Category",
        "gridPos": { "x": 0, "y": 31, "w": 8, "h": 8 },
        "options": {
          "pieType": "donut",
          "legend": { "displayMode": "table", "placement": "right", "values": ["value"] }
        },
        "targets": [
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",alertname=~\"Node.*|VPS.*|Windows.*\"}) or vector(0)",
            "legendFormat": "Infrastructure",
            "instant": true
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",alertname=~\"GWorkspace.*\"}) or vector(0)",
            "legendFormat": "Google Workspace",
            "instant": true
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",alertname=~\"Container.*|Docker.*\"}) or vector(0)",
            "legendFormat": "Containers",
            "instant": true
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",alertname=~\"Network.*|ARP.*|NewDevice.*\"}) or vector(0)",
            "legendFormat": "Network",
            "instant": true
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",alertname=~\"Akvorado.*\"}) or vector(0)",
            "legendFormat": "Akvorado",
            "instant": true
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\",alertname=~\"Blackbox.*|SSL.*\"}) or vector(0)",
            "legendFormat": "Blackbox/SSL",
            "instant": true
          }
        ]
      },

      {
        "id": 41,
        "type": "timeseries",
        "title": "Alert State Changes (last 7 days)",
        "gridPos": { "x": 8, "y": 31, "w": 16, "h": 8 },
        "options": {
          "tooltip": { "mode": "multi" },
          "legend": { "displayMode": "list", "placement": "bottom" }
        },
        "fieldConfig": {
          "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 10 } }
        },
        "targets": [
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"firing\"}) or vector(0)",
            "legendFormat": "firing"
          },
          {
            "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "count(ALERTS{alertstate=\"pending\"}) or vector(0)",
            "legendFormat": "pending"
          }
        ]
      }

    ],
    "time": { "from": "now-24h", "to": "now" },
    "timepicker": {},
    "templating": { "list": [] },
    "annotations": { "list": [] },
    "links": [
      { "title": "Fleet Overview", "url": "/d/fleet-overview", "type": "link", "icon": "external link", "targetBlank": false },
      { "title": "Google Workspace", "url": "/d/google-workspace", "type": "link", "icon": "external link", "targetBlank": false },
      { "title": "Network Inventory", "url": "/d/network-inventory", "type": "link", "icon": "external link", "targetBlank": false }
    ]
  },
  "folderId": 0,
  "overwrite": true
}
ENDJSON
)

echo "Creating Alert Command Center dashboard..."
RESULT=$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "$DASHBOARD" \
  http://admin:admin@127.0.0.1:3000/api/dashboards/db)

echo "$RESULT" | python3 -c "
import sys, json
r = json.load(sys.stdin)
if r.get('status') == 'success':
    print('Dashboard created OK')
    print('URL:', r.get('url'))
    print('UID:', r.get('uid'))
else:
    print('ERROR:', r)
    sys.exit(1)
"
