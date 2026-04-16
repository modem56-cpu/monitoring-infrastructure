#!/usr/bin/env bash
set -euo pipefail
#
# generate-report.sh — Export monitoring data as structured JSON
# for AI agent interpretation. Outputs to stdout or file.
#
# Usage: bash /opt/monitoring/generate-report.sh [output.json]
#

PROM="http://127.0.0.1:9090"
OUT="${1:-/opt/monitoring/reports/monitoring_report_$(date +%Y%m%d_%H%M%S).json}"

python3 << 'PYEOF'
import json, urllib.parse, urllib.request, datetime, os, sys

PROM = "http://127.0.0.1:9090"
OUT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OUT", "/dev/stdout")

def pq(query):
    url = f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": query})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("data", {}).get("result", [])
    except Exception:
        return []

def scalar(query):
    r = pq(query)
    if r:
        try: return float(r[0]["value"][1])
        except: pass
    return None

def scalar_str(query):
    r = pq(query)
    if r:
        try: return r[0]["value"][1]
        except: pass
    return None

def labeled(query, label_key="instance", value_fmt="float"):
    results = {}
    for r in pq(query):
        key = r["metric"].get(label_key, "unknown")
        try:
            v = float(r["value"][1])
            results[key] = round(v, 2) if value_fmt == "float" else int(v)
        except: pass
    return results

now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

report = {
    "report_type": "monitoring_platform_summary",
    "generated_at": now,
    "organization": "Yokly / Agapay",
    "report_source": "Prometheus + Wazuh + Google Workspace",

    # ============================================================
    "node_status": {},
    "infrastructure_health": {},
    "system_metrics": {},
    "alerts_firing": [],
    "docker_containers": {},
    "network": {},
    "google_workspace": {},
    "akvorado": {},
    "security": {},
}

# ============================================================
# Node Status
# ============================================================
nodes = {}
for r in pq('up{job=~"node_.*|windows_.*"}'):
    inst = r["metric"].get("instance", "")
    alias = r["metric"].get("alias", "")
    val = r["value"][1]
    nodes[inst] = {"alias": alias, "up": int(float(val)), "job": r["metric"].get("job", "")}

# VPS status
vps_up = scalar('vps_ssh_up{target="31.170.165.94"}')
if vps_up is not None:
    nodes["31.170.165.94 (VPN: 10.253.2.22)"] = {"alias": "movement-strategy", "up": int(vps_up), "job": "ssh_collector"}

# UDM Pro
udm_up = scalar('up{job="snmp_udm_pro"}')
if udm_up is not None:
    nodes["192.168.10.1"] = {"alias": "udm-pro", "up": int(udm_up), "job": "snmp_udm_pro"}

report["node_status"] = nodes

# ============================================================
# System Metrics
# ============================================================
sys_metrics = {}

# CPU
for inst, val in labeled('instance:cpu_busy_percent:avg5m').items():
    sys_metrics.setdefault(inst, {})["cpu_percent_5m_avg"] = val
for inst, val in labeled('sys_sample_cpu_busy_percent').items():
    sys_metrics.setdefault(inst, {})["cpu_percent_current"] = val

# Memory
for inst, val in labeled('instance:memory_used_percent').items():
    sys_metrics.setdefault(inst, {})["memory_used_percent"] = val

# Swap
for inst, val in labeled('instance:swap_used_percent').items():
    sys_metrics.setdefault(inst, {})["swap_used_percent"] = val

# Disk
for inst, val in labeled('instance:rootfs_used_percent').items():
    sys_metrics.setdefault(inst, {})["disk_root_used_percent"] = val
for inst, val in labeled('sys_sample_rootfs_used_percent').items():
    sys_metrics.setdefault(inst, {})["disk_root_used_percent"] = val

# Uptime
for inst, val in labeled('instance:uptime_days').items():
    sys_metrics.setdefault(inst, {})["uptime_days"] = round(val, 1)

# VPS metrics
vps_cpu = scalar('vps_cpu_busy_percent{target="31.170.165.94"}')
vps_mem_t = scalar('vps_mem_total_bytes{target="31.170.165.94"}')
vps_mem_a = scalar('vps_mem_avail_bytes{target="31.170.165.94"}')
vps_disk = scalar('vps_rootfs_used_percent{target="31.170.165.94"}')
if vps_cpu is not None:
    sys_metrics["movement-strategy"] = {
        "cpu_percent_current": round(vps_cpu, 1),
        "memory_used_percent": round(((vps_mem_t - vps_mem_a) / vps_mem_t * 100), 1) if vps_mem_t and vps_mem_a else None,
        "disk_root_used_percent": round(vps_disk, 1) if vps_disk else None,
    }

report["system_metrics"] = sys_metrics

# ============================================================
# Firing Alerts
# ============================================================
alerts = []
for r in pq('ALERTS{alertstate="firing"}'):
    alerts.append({
        "alertname": r["metric"].get("alertname", ""),
        "instance": r["metric"].get("instance", ""),
        "severity": r["metric"].get("severity", ""),
        "job": r["metric"].get("job", ""),
    })
report["alerts_firing"] = alerts

# ============================================================
# Docker Containers
# ============================================================
containers = {}
for r in pq('container_memory_usage_bytes{name!=""}'):
    name = r["metric"].get("name", "")
    mem_mb = round(float(r["value"][1]) / 1024 / 1024, 1)
    containers.setdefault(name, {})["memory_mb"] = mem_mb

for r in pq('rate(container_cpu_usage_seconds_total{name!=""}[5m]) * 100'):
    name = r["metric"].get("name", "")
    containers.setdefault(name, {})["cpu_percent"] = round(float(r["value"][1]), 2)

report["docker_containers"] = {
    "total_running": len(containers),
    "containers": containers,
}

# ============================================================
# API Health
# ============================================================
api_health = {}
for r in pq('probe_success{job="bb_api_health"}'):
    inst = r["metric"].get("instance", "")
    api_health[inst] = {"up": int(float(r["value"][1]))}
for r in pq('probe_duration_seconds{job="bb_api_health"}'):
    inst = r["metric"].get("instance", "")
    api_health.setdefault(inst, {})["response_time_seconds"] = round(float(r["value"][1]), 3)
report["infrastructure_health"]["api_endpoints"] = api_health

# Blackbox probes
probes = {}
for r in pq('probe_success{job=~"bb_.*"}'):
    inst = r["metric"].get("instance", "")
    job = r["metric"].get("job", "")
    probes[inst] = {"type": job, "up": int(float(r["value"][1]))}
report["infrastructure_health"]["blackbox_probes"] = probes

# ============================================================
# UDM Pro Network
# ============================================================
udm = {}
for r in pq('rate(ifHCInOctets{job="snmp_udm_pro",ifDescr=~"eth0|eth1|br0|br10|br5|wgsrv1"}[5m]) * 8'):
    iface = r["metric"].get("ifDescr", "")
    udm.setdefault(iface, {})["rx_bps"] = round(float(r["value"][1]), 0)
for r in pq('rate(ifHCOutOctets{job="snmp_udm_pro",ifDescr=~"eth0|eth1|br0|br10|br5|wgsrv1"}[5m]) * 8'):
    iface = r["metric"].get("ifDescr", "")
    udm.setdefault(iface, {})["tx_bps"] = round(float(r["value"][1]), 0)
udm_uptime = scalar('sysUpTime{job="snmp_udm_pro"} / 100 / 86400')
report["network"] = {
    "udm_pro_uptime_days": round(udm_uptime, 1) if udm_uptime else None,
    "interfaces": udm,
}

# ============================================================
# Akvorado
# ============================================================
report["akvorado"] = {
    "inlet_up": int(scalar('up{job="akvorado_inlet"}') or 0),
    "outlet_up": int(scalar('up{job="akvorado_outlet"}') or 0),
    "orchestrator_up": int(scalar('up{job="akvorado_orchestrator"}') or 0),
    "flow_packets_per_sec": round(scalar('rate(akvorado_inlet_flow_input_udp_packets_total[5m])') or 0, 2),
    "flow_bytes_per_sec": round(scalar('rate(akvorado_inlet_flow_input_udp_bytes_total[5m])') or 0, 0),
    "kafka_consumer_lag": scalar('akvorado_outlet_kafka_consumergroup_lag_messages'),
    "inlet_uptime_hours": round((scalar('akvorado_cmd_uptime_seconds{job="akvorado_inlet"}') or 0) / 3600, 1),
}

# ============================================================
# Google Workspace
# ============================================================
gw = {}
gw["users_total"] = int(scalar("gworkspace_users_total") or 0)
gw["users_active"] = int(scalar("gworkspace_users_active") or 0)
gw["users_admin"] = int(scalar("gworkspace_users_admin") or 0)
gw["users_suspended"] = int(scalar("gworkspace_users_suspended") or 0)

gw["storage"] = {
    "total_pool_tb": round((scalar("gworkspace_org_storage_total_bytes") or 0) / 1024**4, 2),
    "used_tb": round((scalar("gworkspace_org_storage_used_bytes") or 0) / 1024**4, 2),
    "used_percent": scalar("gworkspace_org_storage_used_percent"),
    "available_tb": round((scalar("gworkspace_org_storage_available_bytes") or 0) / 1024**4, 2),
    "breakdown": {
        "personal_drive_tb": round((scalar("gworkspace_org_drive_bytes") or 0) / 1024**4, 2),
        "shared_drives_tb": round((scalar("gworkspace_org_shared_drive_bytes") or 0) / 1024**4, 2),
        "gmail_gb": round((scalar("gworkspace_org_gmail_bytes") or 0) / 1024**3, 1),
        "photos_gb": round((scalar("gworkspace_org_photos_bytes") or 0) / 1024**3, 1),
    },
}

gw["storage_enforcement"] = {
    "quota_gb": 50,
    "users_over_quota_non_exempt": int(scalar("gworkspace_drive_users_over_quota") or 0),
    "users_over_quota_exempt": int(scalar("gworkspace_drive_users_exempt_over") or 0),
    "exempt_list": ["dan@agapay.gives", "calvin@yokly.gives", "it_dept@yokly.gives", "dm@yokly.gives", "tim@agapay.gives", "eddie@agapay.gives"],
}

# Top storage users
top_users = []
for r in pq("topk(10, gworkspace_drive_usage_bytes)"):
    user = r["metric"].get("user", "")
    exempt = r["metric"].get("exempt", "false")
    gb = round(float(r["value"][1]) / 1024**3, 2)
    top_users.append({"user": user, "usage_gb": gb, "exempt": exempt == "true"})
gw["top_storage_users"] = top_users

# Shared drives
shared = []
for r in pq("topk(10, gworkspace_shared_drive_size_bytes)"):
    name = r["metric"].get("drive", "")
    gb = round(float(r["value"][1]) / 1024**3, 2)
    shared.append({"drive": name, "sampled_size_gb": gb})
gw["top_shared_drives"] = shared

gw["security_alerts_last_hour"] = int(scalar("gworkspace_security_alerts") or 0)
gw["login_events_last_10min"] = int(scalar("gworkspace_login_events_total") or 0)
gw["admin_events_last_10min"] = int(scalar("gworkspace_admin_events_total") or 0)
gw["drive_events_last_10min"] = int(scalar("gworkspace_drive_events_total") or 0)

report["google_workspace"] = gw

# ============================================================
# SSH Sessions
# ============================================================
sessions = []
for r in pq("tower_ssh_sessions_user_src > 0"):
    m = r["metric"]
    sessions.append({
        "target": m.get("target", ""),
        "user": m.get("user", ""),
        "source_ip": m.get("src", ""),
        "count": int(float(r["value"][1])),
    })
report["security"]["active_ssh_sessions"] = sessions

# ============================================================
# Wazuh Agents
# ============================================================
try:
    wazuh_token_url = "https://localhost:55000/security/user/authenticate?raw=true"
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(wazuh_token_url, method="POST")
    req.add_header("Authorization", "Basic " + __import__("base64").b64encode(b"wazuh-wui:wazuh-wui").decode())
    with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
        token = r.read().decode().strip()

    agents_url = "https://localhost:55000/agents?select=id,name,ip,status&limit=20"
    req2 = urllib.request.Request(agents_url)
    req2.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req2, context=ctx, timeout=5) as r:
        agents_data = json.loads(r.read().decode())

    agents = []
    for a in agents_data.get("data", {}).get("affected_items", []):
        agents.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "status": a.get("status"),
        })
    report["security"]["wazuh_agents"] = agents
except Exception as e:
    report["security"]["wazuh_agents"] = f"Error: {e}"

# ============================================================
# Output
# ============================================================
output = json.dumps(report, indent=2, default=str)

out_path = os.environ.get("OUT", OUT)
if out_path == "/dev/stdout":
    print(output)
else:
    with open(out_path, "w") as f:
        f.write(output)
    print(f"Report saved to: {out_path}")
    print(f"Size: {len(output)} bytes")
    # Also print summary
    up_nodes = sum(1 for n in report["node_status"].values() if n.get("up") == 1)
    total_nodes = len(report["node_status"])
    print(f"Nodes: {up_nodes}/{total_nodes} up")
    print(f"Alerts firing: {len(report['alerts_firing'])}")
    print(f"Containers: {report['docker_containers']['total_running']}")
    print(f"Google Workspace: {report['google_workspace']['users_active']} active users, {report['google_workspace']['storage']['used_percent']}% storage used")
PYEOF
</SCRIPT>
chmod +x /opt/monitoring/generate-report.sh
