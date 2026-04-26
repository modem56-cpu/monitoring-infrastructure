#!/usr/bin/env bash
# Create Export Reports dashboard — structured alert report tables + JSON download links
set -euo pipefail

GRAFANA="http://127.0.0.1:3000"
AUTH="Authorization: Basic $(echo -n 'admin:admin' | base64)"
DS_PROM="afiwke54zcjcwe"
DS_WAZUH="ffk7yn7hg1k3ka"
REPORT_URL="http://192.168.10.20:8088/monitoring_report.json"

echo "Creating Export Reports dashboard..."

python3 << PYEOF
import json, base64, urllib.request

GRAFANA    = "http://127.0.0.1:3000"
AUTH       = "Basic " + base64.b64encode(b"admin:admin").decode()
DS_PROM    = "afiwke54zcjcwe"
DS_WAZUH   = "ffk7yn7hg1k3ka"
REPORT_URL = "http://192.168.10.20:8088/monitoring_report.json"

P  = lambda t,x,y,w,h: {"x":x,"y":y,"w":w,"h":h}   # gridPos shorthand

def row(rid, title, y):
    return {"id":rid,"type":"row","title":title,"collapsed":False,
            "gridPos":{"x":0,"y":y,"w":24,"h":1},"panels":[]}

# ── Text / HTML helpers ────────────────────────────────────────────────────
def text_panel(pid, title, content, x, y, w, h, mode="html"):
    return {
        "id": pid, "type": "text", "title": title,
        "gridPos": {"x":x,"y":y,"w":w,"h":h},
        "options": {"mode": mode, "content": content},
        "datasource": None
    }

# ── Prometheus stat ────────────────────────────────────────────────────────
def prom_stat(pid, title, expr, unit, color_steps, x, y, w, h):
    return {
        "id": pid, "type": "stat", "title": title,
        "gridPos": {"x":x,"y":y,"w":w,"h":h},
        "datasource": {"type":"prometheus","uid":DS_PROM},
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "color": {"mode":"thresholds"},
                "thresholds": {"mode":"absolute","steps": color_steps},
                "mappings": []
            }
        },
        "options": {"reduceOptions":{"calcs":["lastNotNull"]},"colorMode":"background","textMode":"auto"},
        "targets": [{"refId":"A","expr":expr,"instant":True,"datasource":{"type":"prometheus","uid":DS_PROM}}]
    }

# ── Prometheus table ───────────────────────────────────────────────────────
def prom_table(pid, title, targets, overrides, x, y, w, h, transforms=None):
    return {
        "id": pid, "type": "table", "title": title,
        "gridPos": {"x":x,"y":y,"w":w,"h":h},
        "datasource": {"type":"prometheus","uid":DS_PROM},
        "fieldConfig": {
            "defaults": {"custom":{"align":"left"}},
            "overrides": overrides
        },
        "options": {"frameIndex":0,"showHeader":True,"footer":{"show":False}},
        "targets": targets,
        "transformations": transforms or []
    }

# ── Wazuh (ES) table ───────────────────────────────────────────────────────
def wazuh_table(pid, title, query, metrics, buckets, overrides, x, y, w, h, transforms=None):
    return {
        "id": pid, "type": "table", "title": title,
        "gridPos": {"x":x,"y":y,"w":w,"h":h},
        "datasource": {"type":"elasticsearch","uid":DS_WAZUH},
        "fieldConfig": {
            "defaults": {"custom":{"align":"left"}},
            "overrides": overrides
        },
        "options": {"frameIndex":0,"showHeader":True,"footer":{"show":False},"sortBy":[{"displayName":"Count","desc":True}]},
        "targets": [{
            "refId":"A","query":query,"queryType":"lucene",
            "metrics":metrics,"bucketAggs":buckets,"timeField":"@timestamp"
        }],
        "transformations": transforms or []
    }

# ══════════════════════════════════════════════════════════════════════════
panels = []
nid = 1

# ── HEADER ─────────────────────────────────────────────────────────────────
panels.append(text_panel(nid,
    "Alert Report Export",
    """<div style="background:#1a1d2e;padding:16px 20px;border-radius:6px;border-left:4px solid #5794f2;">
<h2 style="margin:0 0 8px;color:#e0e0e0;">Yokly / Agapay &mdash; Alert Report</h2>
<p style="margin:0;color:#aaa;font-size:13px;">
All tables below are <strong>exportable as CSV</strong> — hover any table, click the ⋮ menu → <em>Download CSV</em>.<br>
Full machine-readable JSON report:
<a href="{url}" target="_blank" style="color:#5794f2;font-weight:bold;">monitoring_report.json ↗</a>
&nbsp;|&nbsp;
<a href="{url}" download="monitoring_report.json" style="color:#73bf69;font-weight:bold;">⬇ Download JSON</a>
</p>
</div>""".format(url=REPORT_URL),
    0, 0, 24, 3
)); nid+=1

# ── ROW A: PROMETHEUS FIRING ALERTS ────────────────────────────────────────
panels.append(row(nid, "Prometheus — Firing Alerts", y=3)); nid+=1

# Stat cards
panels.append(prom_stat(nid,"Total Firing",
    'count(ALERTS{alertstate="firing"}) or vector(0)', "short",
    [{"color":"green","value":None},{"color":"yellow","value":1},{"color":"red","value":5}],
    0,4,4,3)); nid+=1
panels.append(prom_stat(nid,"Critical",
    'count(ALERTS{alertstate="firing",severity="critical"}) or vector(0)', "short",
    [{"color":"green","value":None},{"color":"red","value":1}],
    4,4,4,3)); nid+=1
panels.append(prom_stat(nid,"Warning",
    'count(ALERTS{alertstate="firing",severity="warning"}) or vector(0)', "short",
    [{"color":"green","value":None},{"color":"yellow","value":1},{"color":"orange","value":5}],
    8,4,4,3)); nid+=1
panels.append(prom_stat(nid,"Targets Down",
    'count(up==0) or vector(0)', "short",
    [{"color":"green","value":None},{"color":"red","value":1}],
    12,4,4,3)); nid+=1
panels.append(prom_stat(nid,"Pending Alerts",
    'count(ALERTS{alertstate="pending"}) or vector(0)', "short",
    [{"color":"green","value":None},{"color":"yellow","value":1}],
    16,4,4,3)); nid+=1
panels.append(prom_stat(nid,"Alerting Rules",
    'count(ALERTS) or vector(0)', "short",
    [{"color":"blue","value":None}],
    20,4,4,3)); nid+=1

# Firing alerts full table — exportable
panels.append(prom_table(nid,
    "Firing Alerts — Full Report (exportable CSV / JSON)",
    [{
        "refId":"A",
        "expr":'ALERTS{alertstate="firing"}',
        "instant":True,
        "legendFormat":"",
        "datasource":{"type":"prometheus","uid":DS_PROM}
    }],
    [
        {"matcher":{"id":"byName","options":"alertname"},  "properties":[{"id":"custom.width","value":220}]},
        {"matcher":{"id":"byName","options":"severity"},   "properties":[
            {"id":"custom.width","value":100},
            {"id":"custom.displayMode","value":"color-background"},
            {"id":"thresholds","value":{"mode":"absolute","steps":[
                {"color":"blue","value":None},
                {"color":"yellow","value":None},
                {"color":"red","value":None}
            ]}},
            {"id":"mappings","value":[
                {"type":"value","options":{"critical":{"color":"red","index":0},
                                           "warning":{"color":"yellow","index":1},
                                           "info":{"color":"blue","index":2}}}
            ]}
        ]},
        {"matcher":{"id":"byName","options":"instance"}, "properties":[{"id":"custom.width","value":200}]},
        {"matcher":{"id":"byName","options":"Time"},     "properties":[{"id":"custom.width","value":180}]},
        {"matcher":{"id":"byName","options":"Value"},    "properties":[{"id":"custom.width","value":70}]}
    ],
    0,7,24,10,
    transforms=[
        {"id":"labelsToFields","options":{"mode":"columns"}},
        {"id":"organize","options":{
            "excludeByName":{"Time":False,"Value":False,"__name__":True,"job":True,"alertstate":True},
            "renameByName":{"alertname":"Alert","severity":"Severity","instance":"Instance","Time":"First Seen"}
        }}
    ]
)); nid+=1

# ── ROW B: PROMETHEUS TARGETS ─────────────────────────────────────────────
panels.append(row(nid, "Prometheus — Target Health", y=17)); nid+=1

panels.append(prom_table(nid,
    "All Scrape Targets — Status Report (exportable)",
    [{
        "refId":"A",
        "expr":'up',
        "instant":True,
        "legendFormat":"",
        "datasource":{"type":"prometheus","uid":DS_PROM}
    }],
    [
        {"matcher":{"id":"byName","options":"Value"},"properties":[
            {"id":"custom.width","value":90},
            {"id":"custom.displayMode","value":"color-background"},
            {"id":"mappings","value":[{"type":"value","options":{
                "0":{"text":"DOWN","color":"red","index":0},
                "1":{"text":"UP","color":"green","index":1}
            }}]}
        ]},
        {"matcher":{"id":"byName","options":"instance"},"properties":[{"id":"custom.width","value":220}]},
        {"matcher":{"id":"byName","options":"job"},     "properties":[{"id":"custom.width","value":180}]}
    ],
    0,18,24,8,
    transforms=[
        {"id":"labelsToFields","options":{"mode":"columns"}},
        {"id":"organize","options":{
            "excludeByName":{"Time":True,"__name__":True},
            "renameByName":{"Value":"Status","instance":"Instance","job":"Job"}
        }},
        {"id":"sortBy","options":{"fields":[{"displayName":"Status","desc":False}]}}
    ]
)); nid+=1

# ── ROW C: WAZUH — 24H SUMMARY ────────────────────────────────────────────
panels.append(row(nid, "Wazuh SIEM — 24h Alert Summary", y=26)); nid+=1

panels.append(wazuh_table(nid,
    "Alert Count by Severity Level (exportable)",
    "",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"rule.level",
      "settings":{"size":"15","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"rule.level"},"properties":[
            {"id":"custom.width","value":100},
            {"id":"displayName","value":"Level"},
            {"id":"custom.displayMode","value":"color-background"},
            {"id":"thresholds","value":{"mode":"absolute","steps":[
                {"color":"blue","value":None},
                {"color":"yellow","value":7},
                {"color":"orange","value":10},
                {"color":"red","value":12}
            ]}}
        ]},
        {"matcher":{"id":"byName","options":"Count"},"properties":[{"id":"custom.width","value":100}]}
    ],
    0,27,8,8,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","rule.level":"Level"}}}]
)); nid+=1

panels.append(wazuh_table(nid,
    "Alert Count by Agent (exportable)",
    "",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"agent.name",
      "settings":{"size":"20","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"agent.name"},"properties":[{"id":"custom.width","value":180},{"id":"displayName","value":"Agent"}]},
        {"matcher":{"id":"byName","options":"Count"},     "properties":[{"id":"custom.width","value":90}]}
    ],
    8,27,8,8,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","agent.name":"Agent"}}}]
)); nid+=1

panels.append(wazuh_table(nid,
    "Alert Count by Rule Description (Top 20, exportable)",
    "",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"rule.description",
      "settings":{"size":"20","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"rule.description"},"properties":[{"id":"displayName","value":"Rule"}]},
        {"matcher":{"id":"byName","options":"Count"},"properties":[{"id":"custom.width","value":90}]}
    ],
    16,27,8,8,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","rule.description":"Rule"}}}]
)); nid+=1

# ── ROW D: WAZUH CRITICAL & HIGH EVENTS ──────────────────────────────────
panels.append(row(nid, "Wazuh — Critical & High Events (Level ≥ 10)", y=35)); nid+=1

panels.append(wazuh_table(nid,
    "Critical Events — Level ≥ 10 (exportable CSV)",
    "rule.level:>=10",
    [{"type":"count","id":"1"},{"type":"max","id":"2","field":"rule.level"}],
    [
        {"type":"terms","id":"3","field":"rule.description",
         "settings":{"size":"50","order":"desc","orderBy":"1"}},
        {"type":"terms","id":"4","field":"agent.name",
         "settings":{"size":"10","order":"desc","orderBy":"_count","min_doc_count":"1"}}
    ],
    [
        {"matcher":{"id":"byName","options":"Count"},    "properties":[{"id":"custom.width","value":80}]},
        {"matcher":{"id":"byName","options":"Max Level"},"properties":[
            {"id":"custom.width","value":90},
            {"id":"custom.displayMode","value":"color-background"},
            {"id":"thresholds","value":{"mode":"absolute","steps":[
                {"color":"orange","value":None},{"color":"red","value":12}
            ]}}
        ]},
        {"matcher":{"id":"byName","options":"Agent"},    "properties":[{"id":"custom.width","value":150}]}
    ],
    0,36,24,9,
    transforms=[{"id":"organize","options":{"renameByName":{
        "1":"Count","2 max":"Max Level","rule.description":"Description","agent.name":"Agent"
    }}}]
)); nid+=1

# ── ROW E: SSH FAILURES ────────────────────────────────────────────────────
panels.append(row(nid, "Wazuh — Authentication Failures", y=45)); nid+=1

panels.append(wazuh_table(nid,
    "SSH Auth Failures by Source IP (exportable)",
    "rule.groups:authentication_failed AND data.srcip:*",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"data.srcip","settings":{"size":"50","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"data.srcip"},"properties":[{"id":"displayName","value":"Source IP"},{"id":"custom.width","value":160}]},
        {"matcher":{"id":"byName","options":"Count"},     "properties":[{"id":"custom.width","value":80}]}
    ],
    0,46,12,8,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","data.srcip":"Source IP"}}}]
)); nid+=1

panels.append(wazuh_table(nid,
    "SSH Auth Failures by Target User (exportable)",
    "rule.groups:authentication_failed",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"data.dstuser","settings":{"size":"30","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"data.dstuser"},"properties":[{"id":"displayName","value":"Target User"},{"id":"custom.width","value":160}]},
        {"matcher":{"id":"byName","options":"Count"},       "properties":[{"id":"custom.width","value":80}]}
    ],
    12,46,12,8,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","data.dstuser":"Target User"}}}]
)); nid+=1

# ── ROW F: PRIVILEGE ESCALATIONS ──────────────────────────────────────────
panels.append(row(nid, "Wazuh — Privilege Escalations", y=54)); nid+=1

panels.append(wazuh_table(nid,
    "Sudo / Root Events by Agent (exportable)",
    "rule.groups:sudo OR rule.description:*sudo* OR rule.description:*ROOT*",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"agent.name","settings":{"size":"20","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"agent.name"},"properties":[{"id":"displayName","value":"Agent"},{"id":"custom.width","value":160}]},
        {"matcher":{"id":"byName","options":"Count"},     "properties":[{"id":"custom.width","value":80}]}
    ],
    0,55,8,7,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","agent.name":"Agent"}}}]
)); nid+=1

panels.append(wazuh_table(nid,
    "Sudo / Root Events by Rule (exportable)",
    "rule.groups:sudo OR rule.description:*sudo* OR rule.description:*ROOT*",
    [{"type":"count","id":"1"}],
    [{"type":"terms","id":"2","field":"rule.description","settings":{"size":"20","order":"desc","orderBy":"1"}}],
    [
        {"matcher":{"id":"byName","options":"rule.description"},"properties":[{"id":"displayName","value":"Rule"}]},
        {"matcher":{"id":"byName","options":"Count"},           "properties":[{"id":"custom.width","value":80}]}
    ],
    8,55,16,7,
    transforms=[{"id":"organize","options":{"renameByName":{"1":"Count","rule.description":"Rule"}}}]
)); nid+=1

# ── ROW G: EMPLOYEE RECONCILIATION ────────────────────────────────────────
panels.append(row(nid, "Employee / Google Workspace Reconciliation", y=62)); nid+=1

def prom_stat_small(pid, title, expr, color_steps, x, y):
    return prom_stat(pid, title, expr, "short", color_steps, x, y, 6, 3)

panels.append(prom_stat_small(nid,"Active Employees (Roster)",
    'employee_reconcile_active_employees or vector(0)',
    [{"color":"green","value":None}], 0, 63)); nid+=1
panels.append(prom_stat_small(nid,"GW Active Users",
    'employee_reconcile_gw_active_total or vector(0)',
    [{"color":"green","value":None}], 6, 63)); nid+=1
panels.append(prom_stat_small(nid,"Orphaned GW Accounts",
    'employee_reconcile_orphaned_accounts or vector(0)',
    [{"color":"green","value":None},{"color":"yellow","value":1},{"color":"red","value":5}],
    12, 63)); nid+=1
panels.append(prom_stat_small(nid,"Missing from GW",
    'employee_reconcile_missing_accounts or vector(0)',
    [{"color":"green","value":None},{"color":"red","value":1}],
    18, 63)); nid+=1

panels.append(prom_table(nid,
    "Orphaned GW Accounts (in GW but not in roster) — exportable",
    [{
        "refId":"A",
        "expr":'employee_reconcile_orphan_info',
        "instant":True,
        "legendFormat":"",
        "datasource":{"type":"prometheus","uid":DS_PROM}
    }],
    [
        {"matcher":{"id":"byName","options":"email"},    "properties":[{"id":"custom.width","value":240}]},
        {"matcher":{"id":"byName","options":"name"},     "properties":[{"id":"custom.width","value":180}]},
        {"matcher":{"id":"byName","options":"is_admin"}, "properties":[
            {"id":"custom.width","value":90},
            {"id":"custom.displayMode","value":"color-background"},
            {"id":"mappings","value":[{"type":"value","options":{
                "true":{"text":"ADMIN","color":"red","index":0},
                "false":{"text":"user","color":"blue","index":1}
            }}]}
        ]},
        {"matcher":{"id":"byName","options":"Value"}, "properties":[{"id":"custom.width","value":70}]}
    ],
    0,66,14,8,
    transforms=[
        {"id":"labelsToFields","options":{"mode":"columns"}},
        {"id":"organize","options":{
            "excludeByName":{"Time":True,"__name__":True,"job":True,"instance":True},
            "renameByName":{"email":"Email","name":"Name","is_admin":"Admin","Value":"Score"}
        }}
    ]
)); nid+=1

panels.append(prom_table(nid,
    "Missing from GW (in roster but no GW account) — exportable",
    [{
        "refId":"A",
        "expr":'employee_reconcile_missing_info',
        "instant":True,
        "legendFormat":"",
        "datasource":{"type":"prometheus","uid":DS_PROM}
    }],
    [
        {"matcher":{"id":"byName","options":"email"},      "properties":[{"id":"custom.width","value":240}]},
        {"matcher":{"id":"byName","options":"name"},       "properties":[{"id":"custom.width","value":180}]},
        {"matcher":{"id":"byName","options":"department"}, "properties":[{"id":"custom.width","value":140}]}
    ],
    14,66,10,8,
    transforms=[
        {"id":"labelsToFields","options":{"mode":"columns"}},
        {"id":"organize","options":{
            "excludeByName":{"Time":True,"__name__":True,"job":True,"instance":True,"Value":True},
            "renameByName":{"email":"Email","name":"Name","department":"Department"}
        }}
    ]
)); nid+=1

# ── ROW H: FOOTER / DOWNLOAD ─────────────────────────────────────────────
panels.append(row(nid, "Download & Export", y=74)); nid+=1

panels.append(text_panel(nid,
    "JSON Report Download",
    """<div style="padding:12px 16px;background:#1a1d2e;border-radius:6px;font-family:monospace;">
<h3 style="color:#e0e0e0;margin:0 0 12px;">Export Options</h3>
<table style="width:100%;border-collapse:collapse;color:#ccc;font-size:13px;">
<tr style="border-bottom:1px solid #333;">
  <td style="padding:8px 12px;color:#aaa;">Full monitoring report (JSON)</td>
  <td style="padding:8px 12px;">
    <a href="{url}" target="_blank" style="color:#5794f2;">View ↗</a>&nbsp;&nbsp;
    <a href="{url}" download="monitoring_report_{ts}.json" style="color:#73bf69;">⬇ Download</a>
  </td>
</tr>
<tr style="border-bottom:1px solid #333;">
  <td style="padding:8px 12px;color:#aaa;">Grafana — any table panel</td>
  <td style="padding:8px 12px;">Hover panel → ⋮ menu → <strong>Download CSV</strong></td>
</tr>
<tr style="border-bottom:1px solid #333;">
  <td style="padding:8px 12px;color:#aaa;">Grafana — this dashboard (JSON)</td>
  <td style="padding:8px 12px;">Share → Export → Download JSON</td>
</tr>
<tr>
  <td style="padding:8px 12px;color:#aaa;">Security Ops Center</td>
  <td style="padding:8px 12px;"><a href="/d/security-ops-center" style="color:#5794f2;">Open Dashboard ↗</a></td>
</tr>
</table>
<p style="margin:12px 0 0;color:#666;font-size:11px;">
Report auto-regenerates every 5 minutes. All times are UTC. Organization: Yokly / Agapay.
</p>
</div>""".format(url=REPORT_URL, ts="$(date +%Y%m%d)"),
    0, 75, 24, 7
)); nid+=1

# ── Build & POST ───────────────────────────────────────────────────────────
dashboard = {
    "uid":           "export-reports",
    "title":         "Export Reports",
    "tags":          ["reports","export","alerts","security"],
    "timezone":      "browser",
    "refresh":       "5m",
    "time":          {"from":"now-24h","to":"now"},
    "schemaVersion": 36,
    "panels":        panels,
    "links": [
        {"title":"Security Operations Center","url":"/d/security-ops-center",
         "type":"link","icon":"external link","targetBlank":False},
        {"title":"Wazuh Security Events","url":"/d/wazuh-security-events",
         "type":"link","icon":"external link","targetBlank":False},
        {"title":"Download JSON Report","url":REPORT_URL,
         "type":"link","icon":"external link","targetBlank":True}
    ]
}

payload = json.dumps({"overwrite":True,"folderId":0,"dashboard":dashboard}).encode()
req = urllib.request.Request(
    f"{GRAFANA}/api/dashboards/db", data=payload,
    headers={"Content-Type":"application/json","Authorization":AUTH}, method="POST"
)
r = json.loads(urllib.request.urlopen(req).read())
print(json.dumps(r, indent=2))
PYEOF

echo ""
echo "Exporting portable JSON..."
python3 << 'EXPORTEOF'
import json, base64, urllib.request

GRAFANA = "http://127.0.0.1:3000"
AUTH = "Basic " + base64.b64encode(b"admin:admin").decode()

req = urllib.request.Request(
    f"{GRAFANA}/api/dashboards/uid/export-reports",
    headers={"Authorization": AUTH}
)
data = json.loads(urllib.request.urlopen(req).read())
dash = data["dashboard"]
for k in ("id", "version"):
    dash.pop(k, None)

dash_str = json.dumps(dash)
dash_str = dash_str.replace("afiwke54zcjcwe", "${DS_PROMETHEUS}")
dash_str = dash_str.replace("ffk7yn7hg1k3ka", "${DS_WAZUH_INDEXER}")
dash = json.loads(dash_str)

portable = {
    "__inputs": [
        {"name":"DS_PROMETHEUS","label":"Prometheus","type":"datasource","pluginId":"prometheus"},
        {"name":"DS_WAZUH_INDEXER","label":"Wazuh Indexer","type":"datasource","pluginId":"elasticsearch"}
    ],
    "__requires": [
        {"type":"grafana",    "id":"grafana",      "name":"Grafana",    "version":"10.0.0"},
        {"type":"datasource", "id":"prometheus",   "name":"Prometheus", "version":"1.0.0"},
        {"type":"datasource", "id":"elasticsearch","name":"Elasticsearch","version":"1.0.0"},
        {"type":"panel","id":"stat",      "name":"Stat",       "version":""},
        {"type":"panel","id":"table",     "name":"Table",      "version":""},
        {"type":"panel","id":"text",      "name":"Text",       "version":""}
    ]
}
portable.update(dash)

out = "/opt/monitoring/dashboards/export-reports.json"
with open(out, "w") as f:
    json.dump(portable, f, indent=2)

panels = [p for p in dash["panels"] if p["type"] != "row"]
print(f"Exported: {out}")
print(f"Content panels: {len(panels)}")
EXPORTEOF

echo ""
echo "Done."
echo "URL: http://192.168.10.20:3000/d/export-reports"
