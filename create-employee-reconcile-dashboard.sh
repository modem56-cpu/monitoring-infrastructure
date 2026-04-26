#!/usr/bin/env bash
# Create Employee ↔ GWorkspace Reconciliation dashboard in Grafana
set -euo pipefail

GRAFANA="http://admin:admin@127.0.0.1:3000"

DASHBOARD=$(cat << 'ENDJSON'
{
  "dashboard": {
    "uid": "employee-reconcile",
    "title": "Employee ↔ GWorkspace Reconciliation",
    "tags": ["identity", "google-workspace", "security", "hr"],
    "timezone": "browser",
    "refresh": "5m",
    "schemaVersion": 38,
    "panels": [

      {
        "id": 1, "type": "stat", "title": "Orphaned GW Accounts",
        "description": "GW users with NO employee record — offboarding risk",
        "gridPos": { "x": 0, "y": 0, "w": 4, "h": 4 },
        "options": { "colorMode": "background", "graphMode": "none", "reduceOptions": { "calcs": ["lastNotNull"] } },
        "fieldConfig": { "defaults": { "thresholds": { "mode": "absolute", "steps": [
          { "color": "green", "value": null }, { "color": "red", "value": 1 }
        ] } } },
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_orphaned_accounts or vector(0)", "instant": true, "legendFormat": "Orphaned" }]
      },

      {
        "id": 2, "type": "stat", "title": "Unregistered Admins",
        "description": "GW admin accounts with no employee record — unauthorized admin risk",
        "gridPos": { "x": 4, "y": 0, "w": 4, "h": 4 },
        "options": { "colorMode": "background", "graphMode": "none", "reduceOptions": { "calcs": ["lastNotNull"] } },
        "fieldConfig": { "defaults": { "thresholds": { "mode": "absolute", "steps": [
          { "color": "green", "value": null }, { "color": "red", "value": 1 }
        ] } } },
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_admin_unregistered or vector(0)", "instant": true, "legendFormat": "Admin" }]
      },

      {
        "id": 3, "type": "stat", "title": "Suspended — Active Employee",
        "description": "Active employees whose GW account is suspended",
        "gridPos": { "x": 8, "y": 0, "w": 4, "h": 4 },
        "options": { "colorMode": "background", "graphMode": "none", "reduceOptions": { "calcs": ["lastNotNull"] } },
        "fieldConfig": { "defaults": { "thresholds": { "mode": "absolute", "steps": [
          { "color": "green", "value": null }, { "color": "yellow", "value": 1 }
        ] } } },
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_suspended_active_employees or vector(0)", "instant": true, "legendFormat": "Suspended" }]
      },

      {
        "id": 4, "type": "stat", "title": "Missing GW Accounts",
        "description": "Employees in roster with no Google Workspace account",
        "gridPos": { "x": 12, "y": 0, "w": 4, "h": 4 },
        "options": { "colorMode": "background", "graphMode": "none", "reduceOptions": { "calcs": ["lastNotNull"] } },
        "fieldConfig": { "defaults": { "thresholds": { "mode": "absolute", "steps": [
          { "color": "green", "value": null }, { "color": "yellow", "value": 1 }
        ] } } },
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_missing_gw_accounts or vector(0)", "instant": true, "legendFormat": "Missing" }]
      },

      {
        "id": 5, "type": "stat", "title": "Employees in Roster",
        "gridPos": { "x": 16, "y": 0, "w": 4, "h": 4 },
        "options": { "colorMode": "value", "graphMode": "none", "reduceOptions": { "calcs": ["lastNotNull"] } },
        "fieldConfig": { "defaults": { "thresholds": { "mode": "absolute", "steps": [{ "color": "blue", "value": null }] } } },
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_active_employees or vector(0)", "instant": true, "legendFormat": "Employees" }]
      },

      {
        "id": 6, "type": "stat", "title": "GW Active Users",
        "gridPos": { "x": 20, "y": 0, "w": 4, "h": 4 },
        "options": { "colorMode": "value", "graphMode": "none", "reduceOptions": { "calcs": ["lastNotNull"] } },
        "fieldConfig": { "defaults": { "thresholds": { "mode": "absolute", "steps": [{ "color": "blue", "value": null }] } } },
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_gw_active_total or vector(0)", "instant": true, "legendFormat": "GW Users" }]
      },

      {
        "id": 10, "type": "timeseries",
        "title": "Account Status Trend (7 days)",
        "description": "Track orphaned accounts and coverage drift over time",
        "gridPos": { "x": 0, "y": 4, "w": 24, "h": 7 },
        "options": { "tooltip": { "mode": "multi" }, "legend": { "displayMode": "list", "placement": "bottom" } },
        "fieldConfig": { "defaults": { "custom": { "lineWidth": 2, "fillOpacity": 10 } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "orphaned" }, "properties": [{ "id": "color", "value": { "fixedColor": "red", "mode": "fixed" } }] },
            { "matcher": { "id": "byName", "options": "admin_unregistered" }, "properties": [{ "id": "color", "value": { "fixedColor": "dark-red", "mode": "fixed" } }] },
            { "matcher": { "id": "byName", "options": "suspended_active" }, "properties": [{ "id": "color", "value": { "fixedColor": "yellow", "mode": "fixed" } }] }
          ]
        },
        "targets": [
          { "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "employee_reconcile_orphaned_accounts", "legendFormat": "orphaned" },
          { "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "employee_reconcile_admin_unregistered", "legendFormat": "admin_unregistered" },
          { "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "employee_reconcile_suspended_active_employees", "legendFormat": "suspended_active" },
          { "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
            "expr": "employee_reconcile_missing_gw_accounts", "legendFormat": "missing_gw" }
        ]
      },

      {
        "id": 20, "type": "table",
        "title": "Orphaned GW Accounts — No Employee Record",
        "description": "These GW users are NOT in the employee roster. Possible offboarded employees. Verify and disable if no longer active.",
        "gridPos": { "x": 0, "y": 11, "w": 12, "h": 10 },
        "options": { "footer": { "show": false } },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "email" }, "properties": [{ "id": "custom.width", "value": 250 }] },
            { "matcher": { "id": "byName", "options": "is_admin" }, "properties": [
              { "id": "custom.width", "value": 80 },
              { "id": "custom.displayMode", "value": "color-background" },
              { "id": "mappings", "value": [
                { "type": "value", "options": { "true":  { "text": "ADMIN", "color": "red",   "index": 0 } } },
                { "type": "value", "options": { "false": { "text": "user",  "color": "green", "index": 1 } } }
              ] }
            ] },
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.hidden", "value": true }] },
            { "matcher": { "id": "byName", "options": "Value" }, "properties": [{ "id": "custom.hidden", "value": true }] }
          ]
        },
        "transformations": [
          { "id": "labelsToFields", "options": { "mode": "columns" } },
          { "id": "organize", "options": {
            "excludeByName": { "Time": true, "Value": true, "__name__": true },
            "renameByName": { "email": "Email", "name": "Name", "is_admin": "Admin?" }
          } }
        ],
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_orphan_info", "format": "table", "instant": true, "legendFormat": "" }]
      },

      {
        "id": 21, "type": "table",
        "title": "Employees Missing GW Account",
        "description": "In the employee roster but no Google Workspace account found. Possible provisioning gap.",
        "gridPos": { "x": 12, "y": 11, "w": 12, "h": 10 },
        "options": { "footer": { "show": false } },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "email" }, "properties": [{ "id": "custom.width", "value": 250 }] },
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.hidden", "value": true }] },
            { "matcher": { "id": "byName", "options": "Value" }, "properties": [{ "id": "custom.hidden", "value": true }] }
          ]
        },
        "transformations": [
          { "id": "labelsToFields", "options": { "mode": "columns" } },
          { "id": "organize", "options": {
            "excludeByName": { "Time": true, "Value": true, "__name__": true },
            "renameByName": { "email": "Email", "name": "Name", "department": "Department" }
          } }
        ],
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "employee_reconcile_missing_info", "format": "table", "instant": true, "legendFormat": "" }]
      },

      {
        "id": 30, "type": "table",
        "title": "Firing Alerts — Identity & Employee",
        "description": "All employee reconciliation alerts currently firing in Prometheus",
        "gridPos": { "x": 0, "y": 21, "w": 24, "h": 8 },
        "options": { "footer": { "show": false },
          "sortBy": [{ "displayName": "Severity", "desc": false }]
        },
        "fieldConfig": {
          "defaults": { "custom": { "align": "left" } },
          "overrides": [
            { "matcher": { "id": "byName", "options": "Severity" }, "properties": [
              { "id": "custom.width", "value": 100 },
              { "id": "custom.displayMode", "value": "color-background" },
              { "id": "mappings", "value": [
                { "type": "value", "options": { "critical": { "color": "red",    "index": 0 } } },
                { "type": "value", "options": { "warning":  { "color": "yellow", "index": 1 } } },
                { "type": "value", "options": { "info":     { "color": "blue",   "index": 2 } } }
              ] }
            ] },
            { "matcher": { "id": "byName", "options": "Alert" }, "properties": [
              { "id": "custom.width", "value": 280 },
              { "id": "links", "value": [
                { "title": "→ Alert Command Center", "url": "/d/alert-command-center/alert-command-center", "targetBlank": false }
              ] }
            ] },
            { "matcher": { "id": "byName", "options": "Time" }, "properties": [{ "id": "custom.hidden", "value": true }] }
          ]
        },
        "transformations": [
          { "id": "labelsToFields", "options": { "mode": "columns" } },
          { "id": "organize", "options": {
            "excludeByName": { "Time": true, "__name__": true, "instance": true, "job": true },
            "renameByName": { "alertname": "Alert", "severity": "Severity", "alertstate": "State" }
          } }
        ],
        "targets": [{ "datasource": { "type": "prometheus", "uid": "afiwke54zcjcwe" },
          "expr": "ALERTS{alertstate=\"firing\",alertname=~\"Employee.*\"}",
          "format": "table", "instant": true, "legendFormat": "" }]
      }

    ],
    "time": { "from": "now-7d", "to": "now" },
    "timepicker": {},
    "templating": { "list": [] },
    "annotations": { "list": [] },
    "links": [
      { "title": "Alert Command Center", "url": "/d/alert-command-center", "type": "link", "icon": "external link", "targetBlank": false },
      { "title": "Google Workspace", "url": "/d/google-workspace", "type": "link", "icon": "external link", "targetBlank": false }
    ]
  },
  "folderId": 0,
  "overwrite": true
}
ENDJSON
)

echo "Creating Employee ↔ GWorkspace Reconciliation dashboard..."
RESULT=$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -d "$DASHBOARD" \
  http://admin:admin@127.0.0.1:3000/api/dashboards/db)

echo "$RESULT" | python3 -c "
import sys, json
r = json.load(sys.stdin)
if r.get('status') == 'success':
    print('Dashboard created: ' + r.get('url',''))
else:
    print('ERROR:', r)
    sys.exit(1)
"

# Export portable JSON
curl -sf http://admin:admin@127.0.0.1:3000/api/dashboards/uid/employee-reconcile | python3 - << 'PYEXPORT'
import sys, json
d = json.load(sys.stdin)
clean = d["dashboard"]
clean.pop("id", None)
clean.pop("version", None)
envelope = {
    "__inputs": [{"name": "DS_PROMETHEUS", "label": "Prometheus", "type": "datasource", "pluginId": "prometheus", "pluginName": "Prometheus"}],
    "__requires": [
        {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "9.0.0"},
        {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
        {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
        {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
        {"type": "panel", "id": "table", "name": "Table", "version": ""}
    ]
}
envelope.update(clean)
raw = json.dumps(envelope, indent=2).replace('"uid": "afiwke54zcjcwe"', '"uid": "${DS_PROMETHEUS}"')
with open("/opt/monitoring/dashboards/employee-reconcile.json", "w") as f:
    f.write(raw)
print("Exported: /opt/monitoring/dashboards/employee-reconcile.json")
PYEXPORT
