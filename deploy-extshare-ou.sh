#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  Deploy External Sharing OU Monitoring"
echo "  Wazuh + Prometheus + Grafana (GWS + Fleet)"
echo "============================================"

# ──────────────────────────────────────────────
# 1. Update collector
# ──────────────────────────────────────────────
echo ""
echo "=== Step 1: Update Google Workspace collector ==="
cp /opt/monitoring/gworkspace-collector-v2.py /opt/monitoring/bin/gworkspace-collector.py
chmod +x /opt/monitoring/bin/gworkspace-collector.py
echo "  Collector updated with ExtShare OU check (Section 5)"

# ──────────────────────────────────────────────
# 2. Wazuh rule 100509 — extshare_unassigned
# ──────────────────────────────────────────────
echo ""
echo "=== Step 2: Update Wazuh Google Workspace rules ==="
cat > /var/ossec/etc/rules/google_workspace.xml << 'XML'
<group name="google_workspace,">

  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^google_workspace$</field>
    <description>Google Workspace: $(alertname)</description>
    <group>google_workspace,</group>
  </rule>

  <rule id="100501" level="10">
    <if_sid>100500</if_sid>
    <match>login_failure</match>
    <description>Google Workspace: Login failure — $(summary)</description>
    <group>google_workspace,authentication_failed,</group>
  </rule>

  <rule id="100502" level="12">
    <if_sid>100500</if_sid>
    <match>suspicious_login</match>
    <description>CRITICAL: Google Workspace suspicious login — $(summary)</description>
    <group>google_workspace,authentication,suspicious,</group>
  </rule>

  <rule id="100503" level="12">
    <if_sid>100500</if_sid>
    <match>account_disabled_password_leak</match>
    <description>CRITICAL: Google Workspace password leak — $(summary)</description>
    <group>google_workspace,credential_leak,</group>
  </rule>

  <rule id="100504" level="5">
    <if_sid>100500</if_sid>
    <match>admin_action</match>
    <description>Google Workspace admin action — $(summary)</description>
    <group>google_workspace,admin,audit,</group>
  </rule>

  <rule id="100505" level="7">
    <if_sid>100500</if_sid>
    <match>external_share</match>
    <description>Google Workspace: External file sharing — $(summary)</description>
    <group>google_workspace,data_loss,</group>
  </rule>

  <rule id="100506" level="7">
    <if_sid>100500</if_sid>
    <match>over_quota</match>
    <description>Google Workspace: User over 50GB storage quota — $(summary)</description>
    <group>google_workspace,storage,compliance,</group>
  </rule>

  <rule id="100507" level="10">
    <if_sid>100500</if_sid>
    <match>security_</match>
    <description>Google Workspace Security Alert — $(summary)</description>
    <group>google_workspace,security_alert,</group>
  </rule>

  <rule id="100508" level="6">
    <if_sid>100500</if_sid>
    <match>quota_summary</match>
    <description>Google Workspace: Storage quota violation summary — $(summary)</description>
    <group>google_workspace,storage,compliance,</group>
  </rule>

  <rule id="100509" level="7">
    <if_sid>100500</if_sid>
    <match>extshare_unrestricted</match>
    <description>Google Workspace: Users NOT in DEFAULT-BLOCKED OU — can still share externally — $(summary)</description>
    <group>google_workspace,data_loss,compliance,</group>
  </rule>

  <rule id="100510" level="5">
    <if_sid>100500</if_sid>
    <match>extshare_exception_present</match>
    <description>Google Workspace: Users in SHARED-DRIVES-EXTERNAL OU (authorized external sharing) — $(summary)</description>
    <group>google_workspace,data_loss,audit,</group>
  </rule>

</group>
XML
chown wazuh:wazuh /var/ossec/etc/rules/google_workspace.xml
echo "  Rules 100509 (unrestricted) + 100510 (exception OU tracking) updated"

# ──────────────────────────────────────────────
# 3. Prometheus alert rule
# ──────────────────────────────────────────────
echo ""
echo "=== Step 3: Create Prometheus alert rule ==="
cat > /opt/monitoring/rules/gworkspace.rules.yml << 'YML'
groups:
- name: google_workspace
  rules:

  - alert: GWorkspace_ExtShare_Unrestricted
    expr: gworkspace_extshare_unrestricted_users > 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "{{ $value }} active users NOT in DEFAULT-BLOCKED OU — can still share externally"

  - alert: GWorkspace_ExtShare_ExceptionOU_Present
    expr: gworkspace_extshare_exception_users > 0
    for: 4h
    labels:
      severity: info
    annotations:
      summary: "{{ $value }} user(s) in SHARED-DRIVES-EXTERNAL OU for over 4h — review if still needed"

  - alert: GWorkspace_CollectorDown
    expr: gworkspace_collector_up == 0
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: "Google Workspace collector is failing"

  - alert: GWorkspace_OverQuota
    expr: gworkspace_drive_users_over_quota > 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "{{ $value }} non-exempt users over 50GB storage quota"
YML
echo "  Created /opt/monitoring/rules/gworkspace.rules.yml"

# Reload Prometheus rules
curl -s -X POST http://localhost:9090/-/reload 2>/dev/null && echo "  Prometheus rules reloaded" || echo "  WARNING: Could not reload Prometheus (may need container restart)"

# ──────────────────────────────────────────────
# 4. Grafana — Google Workspace dashboard
# ──────────────────────────────────────────────
echo ""
echo "=== Step 4: Update Grafana — Google Workspace dashboard ==="

GF_AUTH="admin:admin"
GF_URL="http://localhost:3000"

python3 << 'PYTHON'
import json, urllib.request, sys, base64

GF_URL = "http://localhost:3000"
GF_AUTH = "admin:admin"

def gf_request(path, data=None):
    req = urllib.request.Request(f"{GF_URL}{path}")
    req.add_header("Authorization", "Basic " + base64.b64encode(GF_AUTH.encode()).decode())
    req.add_header("Content-Type", "application/json")
    body = json.dumps(data).encode() if data else None
    return json.loads(urllib.request.urlopen(req, body).read())

# Titles managed by this deploy — will be removed & re-added to pick up metric renames
MANAGED_TITLES_GW = {
    # Legacy titles (purged on each run)
    "ExtShare Unassigned", "ExtShare Assigned",
    "OU Lockdown Coverage",
    "Users NOT in External Sharing OU (can still share externally)",
    "External Sharing OU Rollout Progress",
    "ExtShare Delegate (Authorized)", "ExtShare Unauthorized",
    "Users in SHARED-DRIVES-EXTERNAL OU — Authorized Delegates",
    "UNAUTHORIZED Users in SHARED-DRIVES-EXTERNAL OU",
    "Users NOT in DEFAULT-BLOCKED OU (can share externally)",
    "Users in SHARED-DRIVES-EXTERNAL OU (exception — should be temporary)",
    # Current titles
    "ExtShare Unrestricted", "ExtShare Blocked (Compliant)", "ExtShare Exception",
    "External Sharing Compliance",
    "Users NOT in Restrictive Group (can share externally)",
    "Users in SHARED-DRIVES-EXTERNAL OU (authorized exception)",
    "External Sharing Audit Over Time",
}
MANAGED_TITLES_FLEET = {"NoOU", "Unrestricted"}

# ── Google Workspace dashboard ──
gw = gf_request("/api/dashboards/uid/google-workspace")
dash = gw["dashboard"]
# Remove managed panels to refresh with new metric names
dash["panels"] = [p for p in dash["panels"] if p.get("title") not in MANAGED_TITLES_GW]
panels = dash["panels"]

if True:  # always re-add with current schema
    # Find max y to append at bottom
    max_y = 0
    for p in panels:
        gp = p.get("gridPos", {})
        bottom = gp.get("y", 0) + gp.get("h", 0)
        if bottom > max_y:
            max_y = bottom

    next_id = (max((p.get("id",0) for p in panels), default=100)) + 1
    new_y = max((gp.get("y",0) + gp.get("h",0) for p in panels for gp in [p.get("gridPos",{})]), default=0)

    # Stat — unrestricted count (RISK)
    panels.append({
        "id": next_id, "type": "stat", "title": "ExtShare Unrestricted",
        "gridPos": {"h": 4, "w": 3, "x": 0, "y": new_y},
        "fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
            {"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 10}]}}},
        "options": {"colorMode": "background", "graphMode": "none", "reduceOptions": {"calcs": ["lastNotNull"]}},
        "targets": [{"expr": "gworkspace_extshare_unrestricted_users", "legendFormat": "Unrestricted"}]
    })

    # Stat — blocked/compliant count (GOOD)
    panels.append({
        "id": next_id + 1, "type": "stat", "title": "ExtShare Blocked (Compliant)",
        "gridPos": {"h": 4, "w": 3, "x": 3, "y": new_y},
        "fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
            {"color": "red", "value": None}, {"color": "orange", "value": 10}, {"color": "green", "value": 30}]}}},
        "options": {"colorMode": "background", "graphMode": "none", "reduceOptions": {"calcs": ["lastNotNull"]}},
        "targets": [{"expr": "gworkspace_extshare_blocked_users", "legendFormat": "Blocked"}]
    })

    # Stat — users in SHARED-DRIVES-EXTERNAL OU (authorized external sharing)
    panels.append({
        "id": next_id + 2, "type": "stat", "title": "ExtShare Exception",
        "gridPos": {"h": 4, "w": 3, "x": 6, "y": new_y},
        "fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
            {"color": "green", "value": None}, {"color": "yellow", "value": 1}, {"color": "orange", "value": 10}]}}},
        "options": {"colorMode": "background", "graphMode": "none", "reduceOptions": {"calcs": ["lastNotNull"]}},
        "targets": [{"expr": "gworkspace_extshare_exception_users", "legendFormat": "Exception"}]
    })

    # Gauge — compliance percentage
    panels.append({
        "id": next_id + 3, "type": "gauge", "title": "External Sharing Compliance",
        "gridPos": {"h": 4, "w": 3, "x": 9, "y": new_y},
        "fieldConfig": {"defaults": {"max": 100, "min": 0, "unit": "percent",
            "thresholds": {"mode": "absolute", "steps": [
                {"color": "red", "value": None}, {"color": "orange", "value": 75},
                {"color": "yellow", "value": 90}, {"color": "green", "value": 98}]}}},
        "options": {},
        "targets": [{"expr": "gworkspace_extshare_blocked_users / (gworkspace_extshare_blocked_users + gworkspace_extshare_unrestricted_users + gworkspace_extshare_exception_users) * 100",
                     "legendFormat": "Compliance %"}]
    })

    # Table — unrestricted users (who can still share externally)
    panels.append({
        "id": next_id + 4, "type": "table",
        "title": "Users NOT in Restrictive Group (can share externally)",
        "gridPos": {"h": 10, "w": 12, "x": 12, "y": new_y},
        "targets": [{"expr": "gworkspace_extshare_user_category{category=\"unrestricted\"}",
                     "format": "table", "instant": True, "legendFormat": ""}],
        "transformations": [{"id": "organize", "options": {
            "excludeByName": {"Time": True, "__name__": True, "instance": True, "job": True, "Value": True, "category": True},
            "renameByName": {"user": "User Email", "ou": "Org Unit"}}}]
    })

    # Table — users in SHARED-DRIVES-EXTERNAL OU (authorized exception)
    panels.append({
        "id": next_id + 5, "type": "table",
        "title": "Users in SHARED-DRIVES-EXTERNAL OU (authorized exception)",
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": new_y + 10},
        "targets": [{"expr": "gworkspace_extshare_user_category{category=\"exception\"}",
                     "format": "table", "instant": True, "legendFormat": ""}],
        "transformations": [{"id": "organize", "options": {
            "excludeByName": {"Time": True, "__name__": True, "instance": True, "job": True, "Value": True, "category": True},
            "renameByName": {"user": "User Email", "ou": "Org Unit"}}}]
    })

    # Timeseries — audit category trend over time
    panels.append({
        "id": next_id + 6, "type": "timeseries",
        "title": "External Sharing Audit Over Time",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": new_y + 4},
        "fieldConfig": {"defaults": {"custom": {"fillOpacity": 20, "lineWidth": 2, "stacking": {"mode": "none"}}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "Blocked (Compliant)"}, "properties": [{"id": "color", "value": {"fixedColor": "green", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "Unrestricted (Risk)"}, "properties": [{"id": "color", "value": {"fixedColor": "red", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "Exception (Authorized)"}, "properties": [{"id": "color", "value": {"fixedColor": "yellow", "mode": "fixed"}}]}]},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
        "targets": [
            {"expr": "gworkspace_extshare_blocked_users", "legendFormat": "Blocked (Compliant)"},
            {"expr": "gworkspace_extshare_unrestricted_users", "legendFormat": "Unrestricted (Risk)"},
            {"expr": "gworkspace_extshare_exception_users", "legendFormat": "Exception (Authorized)"}]
    })

    dash["version"] = dash.get("version", 0) + 1
    gf_request("/api/dashboards/db", {
        "dashboard": dash,
        "folderUid": gw.get("meta", {}).get("folderUid", ""),
        "overwrite": True
    })
    print("  Google Workspace dashboard: refreshed 7 ExtShare audit panels (group-based enforcement)")
else:
    print("  Google Workspace dashboard: unchanged")

# ── Fleet Overview dashboard ──
fleet = gf_request("/api/dashboards/uid/fleet-overview")
fdash = fleet["dashboard"]
# Strip managed panels to refresh
fdash["panels"] = [p for p in fdash["panels"] if p.get("title") not in MANAGED_TITLES_FLEET]
fpanels = fdash["panels"]

next_fid = (max((p.get("id",0) for p in fpanels), default=100)) + 1

# Find the >50GB panel to place our new stat next to it
gt50_panel = next((p for p in fpanels if p.get("id") == 12), None)
if gt50_panel:
    gp = gt50_panel["gridPos"]
    new_x = gp["x"] + gp["w"]
    if new_x > 22:
        new_x = gp["x"]
    new_fleet_y = gp["y"]
else:
    new_x, new_fleet_y = 22, 0

# Compact stat — users who can still share externally (unrestricted)
fpanels.append({
    "id": next_fid, "type": "stat", "title": "Unrestricted",
    "gridPos": {"h": 2, "w": 2, "x": new_x, "y": new_fleet_y},
    "fieldConfig": {"defaults": {"thresholds": {"mode": "absolute", "steps": [
        {"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 10}]}}},
    "options": {"colorMode": "background", "graphMode": "none", "justifyMode": "center",
                "reduceOptions": {"calcs": ["lastNotNull"]}, "textMode": "value"},
    "targets": [{"expr": "gworkspace_extshare_unrestricted_users", "legendFormat": ""}]
})

fdash["version"] = fdash.get("version", 0) + 1
gf_request("/api/dashboards/db", {
    "dashboard": fdash,
    "folderUid": fleet.get("meta", {}).get("folderUid", ""),
    "overwrite": True
})
print("  Fleet Overview dashboard: refreshed Unrestricted stat panel")
PYTHON

# ──────────────────────────────────────────────
# 5. Update restore script reference
# ──────────────────────────────────────────────
echo ""
echo "=== Step 5: Restart Wazuh Manager ==="
systemctl restart wazuh-manager
echo "  Wazuh restarted"

# ──────────────────────────────────────────────
# 6. Test run
# ──────────────────────────────────────────────
echo ""
echo "=== Step 6: Test collector run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "============================================"
echo "  Deployed: External Sharing Audit (group-based enforcement)"
echo "    Restrictive groups: hrou, itdevou, marketingou, trainingou @yokly.gives"
echo "    Exception OU:       /Yokly/SHARED-DRIVES-EXTERNAL"
echo "    Collector: Section 5 — BLOCKED / EXCEPTION / UNRESTRICTED"
echo "    Wazuh:     100509 unrestricted (L7), 100510 exception_present (L5)"
echo "    Prometheus: 3 alerts — Unrestricted, ExceptionOU_Present (4h info), CollectorDown"
echo "    Grafana GWS:   7 panels (3 stats, gauge, 2 tables, timeseries)"
echo "    Grafana Fleet: Unrestricted stat panel"
echo "============================================"
