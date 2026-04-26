#!/usr/bin/env python3
"""
Monitoring Platform JSON Report Generator
Exports all monitoring data as structured JSON for AI agent interpretation.

Usage:
  python3 /opt/monitoring/generate-report.py                    # stdout
  python3 /opt/monitoring/generate-report.py report.json        # file
"""
import json, urllib.parse, urllib.request, datetime, os, sys, ssl, base64

PROM = os.environ.get("PROM_URL", "http://127.0.0.1:9090")

def pq(query):
    url = f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": query})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read().decode("utf-8")).get("data", {}).get("result", [])
    except Exception:
        return []

def scalar(query):
    r = pq(query)
    if r:
        try: return float(r[0]["value"][1])
        except: pass
    return None

def labeled(query, label_key="instance"):
    results = {}
    for r in pq(query):
        key = r["metric"].get(label_key, "unknown")
        try: results[key] = round(float(r["value"][1]), 2)
        except: pass
    return results

now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

report = {
    "report_type": "monitoring_platform_summary",
    "generated_at": now,
    "organization": "Yokly / Agapay",
    "ai_instructions": "Analyze this monitoring report. Identify risks, anomalies, capacity issues, and security concerns. Provide actionable recommendations prioritized by severity.",
}

# === Node Status ===
nodes = {}
for r in pq('up{job=~"node_.*|windows_.*"}'):
    inst = r["metric"].get("instance", "")
    nodes[inst] = {"alias": r["metric"].get("alias", ""), "up": int(float(r["value"][1])), "job": r["metric"].get("job", "")}

vps_up = scalar('vps_ssh_up{target="31.170.165.94"}')
if vps_up is not None:
    nodes["31.170.165.94"] = {"alias": "movement-strategy", "up": int(vps_up), "job": "ssh_collector"}

udm_up = scalar('up{job="snmp_udm_pro"}')
if udm_up is not None:
    nodes["192.168.10.1"] = {"alias": "udm-pro", "up": int(udm_up), "job": "snmp"}

report["node_status"] = nodes

# === System Metrics ===
sys_m = {}
for inst, val in labeled('instance:cpu_busy_percent:avg5m').items():
    sys_m.setdefault(inst, {})["cpu_5m_avg_pct"] = val
for inst, val in labeled('sys_sample_cpu_busy_percent').items():
    sys_m.setdefault(inst, {})["cpu_current_pct"] = val
for inst, val in labeled('instance:memory_used_percent').items():
    sys_m.setdefault(inst, {})["memory_pct"] = val
for inst, val in labeled('instance:swap_used_percent').items():
    sys_m.setdefault(inst, {})["swap_pct"] = val
for inst, val in labeled('instance:rootfs_used_percent').items():
    sys_m.setdefault(inst, {})["disk_root_pct"] = val
for inst, val in labeled('sys_sample_rootfs_used_percent').items():
    sys_m.setdefault(inst, {})["disk_root_pct"] = val
for inst, val in labeled('instance:uptime_days').items():
    sys_m.setdefault(inst, {})["uptime_days"] = round(val, 1)

# VPS
vps_cpu = scalar('vps_cpu_busy_percent{target="31.170.165.94"}')
vps_mem_t = scalar('vps_mem_total_bytes{target="31.170.165.94"}')
vps_mem_a = scalar('vps_mem_avail_bytes{target="31.170.165.94"}')
vps_disk = scalar('vps_rootfs_used_percent{target="31.170.165.94"}')
if vps_cpu is not None:
    sys_m["movement-strategy"] = {
        "cpu_current_pct": round(vps_cpu, 1),
        "memory_pct": round(((vps_mem_t - vps_mem_a) / vps_mem_t * 100), 1) if vps_mem_t and vps_mem_a else None,
        "disk_root_pct": round(vps_disk, 1) if vps_disk else None,
    }

report["system_metrics"] = sys_m

# === Firing Alerts ===
alerts = []
for r in pq('ALERTS{alertstate="firing"}'):
    alerts.append({
        "alert": r["metric"].get("alertname", ""),
        "instance": r["metric"].get("instance", ""),
        "severity": r["metric"].get("severity", ""),
    })
report["alerts_firing"] = alerts
report["alerts_firing_count"] = len(alerts)

# === Docker ===
containers = {}
for r in pq('container_memory_usage_bytes{name!=""}'):
    name = r["metric"].get("name", "")
    containers.setdefault(name, {})["memory_mb"] = round(float(r["value"][1]) / 1024**2, 1)
for r in pq('rate(container_cpu_usage_seconds_total{name!=""}[5m]) * 100'):
    name = r["metric"].get("name", "")
    containers.setdefault(name, {})["cpu_pct"] = round(float(r["value"][1]), 2)

report["docker"] = {"running": len(containers), "containers": containers}

# === Top Processes (per node) ===
top_procs = {}
for r in pq('topk(15, sys_topproc_pcpu_percent or sys_topproc_cpu_percent)'):
    m = r["metric"]
    inst = m.get("instance", "")
    top_procs.setdefault(inst, []).append({
        "pid": m.get("pid", ""),
        "user": m.get("user", m.get("name", "")),
        "command": m.get("comm", m.get("cmd", "")),
        "cpu_pct": round(float(r["value"][1]), 1),
    })

rss_map = {}
for r in pq('sys_topproc_rss_kb'):
    m = r["metric"]
    key = (m.get("instance", ""), m.get("pid", ""), m.get("comm", m.get("cmd", "")))
    rss_map[key] = round(float(r["value"][1]) / 1024, 1)

mem_map = {}
for r in pq('sys_topproc_pmem_percent or sys_topproc_mem_percent'):
    m = r["metric"]
    key = (m.get("instance", ""), m.get("pid", ""), m.get("comm", m.get("cmd", "")))
    mem_map[key] = round(float(r["value"][1]), 1)

for inst, procs in top_procs.items():
    for p in procs:
        key = (inst, p["pid"], p["command"])
        p["rss_mb"] = rss_map.get(key)
        p["mem_pct"] = mem_map.get(key)

# VPS top processes
for r in pq('topk(10, vps_topproc_cpu_percent{target="31.170.165.94"})'):
    m = r["metric"]
    top_procs.setdefault("movement-strategy", []).append({
        "pid": m.get("pid", ""),
        "user": m.get("user", ""),
        "command": m.get("cmd", ""),
        "cpu_pct": round(float(r["value"][1]), 1),
    })

report["top_processes"] = top_procs

# === Network I/O (per node) ===
net_io = {}
for inst, val in labeled('instance:net_rx_bytes_rate:5m').items():
    net_io.setdefault(inst, {})["rx_bytes_sec"] = round(val, 1)
for inst, val in labeled('instance:net_tx_bytes_rate:5m').items():
    net_io.setdefault(inst, {})["tx_bytes_sec"] = round(val, 1)
for inst, val in labeled('instance:disk_io_read_bytes_rate:5m').items():
    net_io.setdefault(inst, {})["disk_read_bytes_sec"] = round(val, 1)
for inst, val in labeled('instance:disk_io_write_bytes_rate:5m').items():
    net_io.setdefault(inst, {})["disk_write_bytes_sec"] = round(val, 1)

# sys_sample network/disk
for r in pq('sys_sample_net_rx_bps or sys_sample_net_rx_bytes_per_sec'):
    inst = r["metric"].get("instance", "")
    net_io.setdefault(inst, {})["rx_bytes_sec"] = round(float(r["value"][1]), 1)
for r in pq('sys_sample_net_tx_bps or sys_sample_net_tx_bytes_per_sec'):
    inst = r["metric"].get("instance", "")
    net_io.setdefault(inst, {})["tx_bytes_sec"] = round(float(r["value"][1]), 1)

report["network_disk_io"] = net_io

# === Docker Container List ===
docker_list = []
for r in pq('tower_docker_list_up'):
    m = r["metric"]
    name = m.get("name", "")
    target = m.get("target", "")
    if name:
        docker_list.append({"name": name, "host": target, "running": int(float(r["value"][1]))})
report["docker"]["container_list"] = docker_list

# === API Health ===
apis = {}
for r in pq('probe_success{job="bb_api_health"}'):
    inst = r["metric"].get("instance", "")
    apis[inst] = {"up": int(float(r["value"][1]))}
for r in pq('probe_duration_seconds{job="bb_api_health"}'):
    inst = r["metric"].get("instance", "")
    apis.setdefault(inst, {})["response_sec"] = round(float(r["value"][1]), 3)
report["api_health"] = apis

# === UDM Pro Network ===
udm = {}
for r in pq('rate(ifHCInOctets{job="snmp_udm_pro",ifDescr=~"eth0|eth1|br0|br10|wgsrv1"}[5m]) * 8'):
    iface = r["metric"].get("ifDescr", "")
    udm.setdefault(iface, {})["rx_bps"] = round(float(r["value"][1]))
for r in pq('rate(ifHCOutOctets{job="snmp_udm_pro",ifDescr=~"eth0|eth1|br0|br10|wgsrv1"}[5m]) * 8'):
    iface = r["metric"].get("ifDescr", "")
    udm.setdefault(iface, {})["tx_bps"] = round(float(r["value"][1]))
report["udm_pro"] = {
    "uptime_days": round((scalar('sysUpTime{job="snmp_udm_pro"}') or 0) / 100 / 86400, 1),
    "interfaces": udm,
}

# === Akvorado ===
report["akvorado"] = {
    "inlet_up": int(scalar('up{job="akvorado_inlet"}') or 0),
    "outlet_up": int(scalar('up{job="akvorado_outlet"}') or 0),
    "orchestrator_up": int(scalar('up{job="akvorado_orchestrator"}') or 0),
    "flow_pps": round(scalar('rate(akvorado_inlet_flow_input_udp_packets_total[5m])') or 0, 2),
    "flow_bps": round(scalar('rate(akvorado_inlet_flow_input_udp_bytes_total[5m])') or 0),
    "kafka_lag": scalar('akvorado_outlet_kafka_consumergroup_lag_messages'),
}

# === Google Workspace ===
_gw_personal_bytes = scalar("gworkspace_org_storage_used_bytes") or 0
_gw_shared_bytes   = scalar("gworkspace_org_shared_drive_bytes") or 0
_gw_pool_bytes     = scalar("gworkspace_org_storage_total_bytes") or 0
_gw_used_bytes     = _gw_personal_bytes + _gw_shared_bytes  # shared drives count against org pool
_gw_avail_bytes    = max(0.0, _gw_pool_bytes - _gw_used_bytes)
_gw_used_pct       = round(_gw_used_bytes / _gw_pool_bytes * 100, 2) if _gw_pool_bytes else 0.0

gw = {
    "users_total": int(scalar("gworkspace_users_total") or 0),
    "users_active": int(scalar("gworkspace_users_active") or 0),
    "users_admin": int(scalar("gworkspace_users_admin") or 0),
    "storage": {
        "pool_tb": round(_gw_pool_bytes / 1024**4, 2),
        "used_tb": round(_gw_used_bytes / 1024**4, 2),
        "used_pct": _gw_used_pct,
        "available_tb": round(_gw_avail_bytes / 1024**4, 2),
        "personal_tb": round(_gw_personal_bytes / 1024**4, 2),
        "drive_tb": round((scalar("gworkspace_org_drive_bytes") or 0) / 1024**4, 2),
        "shared_drives_tb": round(_gw_shared_bytes / 1024**4, 2),
        "gmail_gb": round((scalar("gworkspace_org_gmail_bytes") or 0) / 1024**3, 1),
        "photos_gb": round((scalar("gworkspace_org_photos_bytes") or 0) / 1024**3, 1),
    },
    "quota_enforcement": {
        "quota_gb": 50,
        "non_exempt_over": int(scalar("gworkspace_drive_users_over_quota") or 0),
        "exempt_over": int(scalar("gworkspace_drive_users_exempt_over") or 0),
    },
    "security_alerts": int(scalar("gworkspace_security_alerts") or 0),
    "events_10min": {
        "login": int(scalar("gworkspace_login_events_total") or 0),
        "admin": int(scalar("gworkspace_admin_events_total") or 0),
        "drive": int(scalar("gworkspace_drive_events_total") or 0),
    },
}

top_users = []
for r in pq("topk(10, gworkspace_drive_usage_bytes)"):
    top_users.append({
        "user": r["metric"].get("user", ""),
        "gb": round(float(r["value"][1]) / 1024**3, 2),
        "exempt": r["metric"].get("exempt", "") == "true",
    })
gw["top_storage_users"] = top_users

top_shared = []
for r in pq("topk(10, gworkspace_shared_drive_size_bytes)"):
    top_shared.append({
        "drive": r["metric"].get("drive", ""),
        "sampled_gb": round(float(r["value"][1]) / 1024**3, 2),
    })
gw["top_shared_drives"] = top_shared

report["google_workspace"] = gw

# === SSH Sessions ===
sessions = []
for r in pq("tower_ssh_sessions_user_src > 0"):
    m = r["metric"]
    sessions.append({"target": m.get("target", ""), "user": m.get("user", ""), "src": m.get("src", ""), "count": int(float(r["value"][1]))})
report["ssh_sessions"] = sessions

# === Wazuh Agents (via Wazuh Indexer — API port 55000 not enabled) ===
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    wazuh_auth = "Basic " + base64.b64encode(b"kibanaserver:77RmIguYcnHPxjMJqG0EgeEsaIWLL3bE").decode()
    wazuh_body = json.dumps({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
        "aggs": {
            "agents": {
                "terms": {"field": "agent.name", "size": 50},
                "aggs": {
                    "agent_id":  {"terms": {"field": "agent.id",  "size": 1}},
                    "last_seen": {"max":  {"field": "@timestamp"}}
                }
            }
        }
    }).encode()
    req_w = urllib.request.Request(
        "https://172.18.0.1:9200/wazuh-alerts-4.x-*/_search",
        data=wazuh_body,
        headers={"Authorization": wazuh_auth, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req_w, context=ctx, timeout=10) as r:
        wd = json.loads(r.read().decode())
    agents_out = []
    for b in wd.get("aggregations", {}).get("agents", {}).get("buckets", []):
        agent_id_buckets = b.get("agent_id", {}).get("buckets", [])
        agents_out.append({
            "name":      b["key"],
            "id":        agent_id_buckets[0]["key"] if agent_id_buckets else "?",
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
            "status":    "active"
        })
    report["wazuh_agents"] = agents_out
except Exception as e:
    report["wazuh_agents"] = f"Error: {e}"

# === Grafana Dashboard Exports ===
# Embed portable dashboard JSONs so AI agents get full dashboard definitions
# alongside live metrics in one payload.
import glob as _glob
DASH_DIR = "/opt/monitoring/dashboards"
dashboards = {}
for path in sorted(_glob.glob(f"{DASH_DIR}/*.json")):
    name = os.path.basename(path).replace(".json", "")
    try:
        with open(path) as f:
            dashboards[name] = json.load(f)
    except Exception as e:
        dashboards[name] = {"error": str(e)}
report["grafana_dashboards"] = dashboards

# === Output ===
output = json.dumps(report, indent=2, default=str)

if len(sys.argv) > 1:
    out = sys.argv[1]
    with open(out, "w") as f:
        f.write(output)
    up = sum(1 for n in report["node_status"].values() if n.get("up") == 1)
    total = len(report["node_status"])
    print(f"Report: {out} ({len(output)} bytes)")
    print(f"Nodes: {up}/{total} up | Alerts: {len(alerts)} | Containers: {len(containers)} | GW users: {gw['users_active']}")
else:
    print(output)
