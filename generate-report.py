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
CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "http://247.16.14.11:8123/")

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

# === Akvorado Top Flows ===

def get_akvorado_top_flows(limit=30, window_hours=6):
    """
    Query ClickHouse for top traffic flows recorded by Akvorado.
    Uses flows_5m-bucketed aggregation of the raw flows table.
    Returns (list_of_flows, error_string_or_None).
    """
    query = """\
WITH flow_buckets AS (
    SELECT
        toStartOfFiveMinute(TimeReceived) AS bucket,
        replaceRegexpOne(toString(SrcAddr), '^::ffff:', '') AS src_addr,
        replaceRegexpOne(toString(DstAddr), '^::ffff:', '') AS dst_addr,
        SrcAS, DstAS, SrcPort, DstPort, PacketSizeBucket,
        InIfSpeed, OutIfSpeed, SrcCountry, DstCountry,
        SrcNetTenant, DstNetTenant, SrcNetName, DstNetName,
        SrcNetPrefix, DstNetPrefix,
        toUInt64(sum(toUInt64(Bytes) * SamplingRate) * 8) / 300 AS bps
    FROM default.flows
    WHERE TimeReceived >= now() - INTERVAL {wh} HOUR
    GROUP BY bucket, src_addr, dst_addr, SrcAS, DstAS, SrcPort, DstPort,
             PacketSizeBucket, InIfSpeed, OutIfSpeed, SrcCountry, DstCountry,
             SrcNetTenant, DstNetTenant, SrcNetName, DstNetName,
             SrcNetPrefix, DstNetPrefix
)
SELECT
    src_addr, dst_addr, SrcAS, DstAS, SrcPort, DstPort, PacketSizeBucket,
    InIfSpeed, OutIfSpeed, SrcCountry, DstCountry,
    SrcNetTenant, DstNetTenant, SrcNetName, DstNetName,
    SrcNetPrefix, DstNetPrefix,
    dictGetOrDefault('default.asns', 'name', toUInt64(SrcAS), '') AS src_as_name,
    dictGetOrDefault('default.asns', 'name', toUInt64(DstAS), '') AS dst_as_name,
    if(dictGetOrDefault('default.tcp', 'name', toUInt64(SrcPort), '') != '',
       dictGetOrDefault('default.tcp', 'name', toUInt64(SrcPort), ''),
       dictGetOrDefault('default.udp', 'name', toUInt64(SrcPort), '')) AS src_port_name,
    if(dictGetOrDefault('default.tcp', 'name', toUInt64(DstPort), '') != '',
       dictGetOrDefault('default.tcp', 'name', toUInt64(DstPort), ''),
       dictGetOrDefault('default.udp', 'name', toUInt64(DstPort), '')) AS dst_port_name,
    round(max(bps))              AS max_bps,
    round(avg(bps))              AS average_bps,
    round(quantile(0.95)(bps))  AS p95_bps,
    round(argMax(bps, bucket))   AS last_bps
FROM flow_buckets
GROUP BY src_addr, dst_addr, SrcAS, DstAS, SrcPort, DstPort, PacketSizeBucket,
         InIfSpeed, OutIfSpeed, SrcCountry, DstCountry,
         SrcNetTenant, DstNetTenant, SrcNetName, DstNetName,
         SrcNetPrefix, DstNetPrefix
ORDER BY max_bps DESC
LIMIT {lim}
FORMAT JSONEachRow""".format(wh=window_hours, lim=limit)

    try:
        req = urllib.request.Request(
            CLICKHOUSE_URL,
            data=query.encode("utf-8"),
            headers={"Content-Type": "text/plain"}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8")
    except Exception as e:
        return [], str(e)

    if raw.startswith("Code:"):
        return [], raw.strip()

    flows = []
    for rank, line in enumerate(raw.strip().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue

        # Strip null chars that ClickHouse returns for empty FixedString(2) country codes
        src_country = row.get("SrcCountry", "").replace("\x00", "")
        dst_country = row.get("DstCountry", "").replace("\x00", "")

        src_as_num  = row.get("SrcAS", 0)
        dst_as_num  = row.get("DstAS", 0)
        src_as_name = row.get("src_as_name", "")
        dst_as_name = row.get("dst_as_name", "")
        src_as_disp = f"{src_as_num} {src_as_name}".strip() if src_as_num else ""
        dst_as_disp = f"{dst_as_num} {dst_as_name}".strip() if dst_as_num else ""

        src_port_num  = row.get("SrcPort", 0)
        dst_port_num  = row.get("DstPort", 0)
        src_port_name = row.get("src_port_name", "")
        dst_port_name = row.get("dst_port_name", "")
        src_port_disp = f"{src_port_num}/{src_port_name}" if src_port_name else str(src_port_num)
        dst_port_disp = f"{dst_port_num}/{dst_port_name}" if dst_port_name else str(dst_port_num)

        max_bps  = int(row.get("max_bps",     0))
        avg_bps  = int(row.get("average_bps", 0))
        p95_bps  = int(row.get("p95_bps",     0))
        last_bps = int(row.get("last_bps",    0))

        flows.append({
            "rank":               rank,
            "src_as":             src_as_disp,
            "dst_addr":           row.get("dst_addr", ""),
            "dst_port":           dst_port_disp,
            "packet_size_bucket": row.get("PacketSizeBucket", ""),
            "src_port":           src_port_disp,
            "in_if_speed":        row.get("InIfSpeed", 0),
            "out_if_speed":       row.get("OutIfSpeed", 0),
            "src_country":        src_country,
            "dst_country":        dst_country,
            "dst_net_tenant":     row.get("DstNetTenant", ""),
            "src_net_tenant":     row.get("SrcNetTenant", ""),
            "src_net_name":       row.get("SrcNetName", ""),
            "dst_net_name":       row.get("DstNetName", ""),
            "src_addr":           row.get("src_addr", ""),
            "dst_as":             dst_as_disp,
            "src_net_prefix":     row.get("SrcNetPrefix", ""),
            "dst_net_prefix":     row.get("DstNetPrefix", ""),
            "max_bps":            max_bps,
            "last_bps":           last_bps,
            "average_bps":        avg_bps,
            "p95_bps":            p95_bps,
            "max_mbps":           round(max_bps  / 1_000_000, 2),
            "average_mbps":       round(avg_bps  / 1_000_000, 2),
            "p95_mbps":           round(p95_bps  / 1_000_000, 2),
        })

    return flows, None

_top_flows, _top_flows_err = get_akvorado_top_flows(limit=30, window_hours=6)

# === Akvorado ===
report["akvorado"] = {
    "inlet_up": int(scalar('up{job="akvorado_inlet"}') or 0),
    "outlet_up": int(scalar('up{job="akvorado_outlet"}') or 0),
    "orchestrator_up": int(scalar('up{job="akvorado_orchestrator"}') or 0),
    "flow_pps": round(scalar('rate(akvorado_inlet_flow_input_udp_packets_total[5m])') or 0, 2),
    "flow_bps": round(scalar('rate(akvorado_inlet_flow_input_udp_bytes_total[5m])') or 0),
    "kafka_lag": scalar('akvorado_outlet_kafka_consumergroup_lag_messages'),
    "top_flows_window": "6h",
    "top_flows_sort": "max_bps",
    "top_flows_count": len(_top_flows),
    "top_flows": _top_flows,
    **({"top_flows_error": _top_flows_err} if _top_flows_err else {}),
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

# Shared drive live summary from current Prometheus metrics
gw["shared_drive_summary"] = {
    "total_live":               int(scalar("gworkspace_shared_drives_total") or 0),
    "approved_external_live":   int(scalar("gworkspace_approved_external_shared_drives_total") or 0),
    "unapproved_external_live": int(scalar("gworkspace_unapproved_external_shared_drives_total") or 0),
    "deleted_detected":         int(scalar("gworkspace_deleted_shared_drives_total") or 0),
    "external_violations_live": int(scalar("gworkspace_unapproved_external_shared_drives_total") or 0),
}

# Deleted shared drives from state file (audit trail)
_sd_state_path = "/opt/monitoring/data/shared_drive_state.json"
deleted_drives_out = []
try:
    import os as _os
    if _os.path.exists(_sd_state_path):
        with open(_sd_state_path) as _sdp:
            _sd_state = json.load(_sdp)
        for _did, _di in _sd_state.get("drives", {}).items():
            if _di.get("status") == "deleted":
                if _di.get("had_external_members") and _di.get("was_approved"):
                    _prev_cat = "approved_external"
                elif _di.get("had_external_members"):
                    _prev_cat = "unapproved_external"
                else:
                    _prev_cat = "internal"
                deleted_drives_out.append({
                    "drive_id":              _did,
                    "drive_name":            _di.get("drive_name", ""),
                    "previous_category":     _prev_cat,
                    "had_external_members":  _di.get("had_external_members", False),
                    "was_approved":          _di.get("was_approved", False),
                    "removed_from_live_count": True,
                    "first_seen":            _di.get("first_seen", ""),
                    "last_seen":             _di.get("last_seen", ""),
                    "detected_at":           _di.get("deleted_at", ""),
                })
except Exception as _e:
    deleted_drives_out = [{"error": str(_e)}]
gw["deleted_shared_drives"] = deleted_drives_out

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

# === Wazuh Alert Summary — last 24h ===
try:
    wazuh_alert_body = json.dumps({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "by_level": {
                "terms": {"field": "rule.level", "size": 15, "order": {"_key": "desc"}}
            },
            "by_agent": {
                "terms": {"field": "agent.name", "size": 20, "order": {"_count": "desc"}}
            },
            "by_rule": {
                "terms": {"field": "rule.description", "size": 20, "order": {"_count": "desc"}}
            },
            "prometheus_bridge": {
                "filter": {"term": {"data.source": "prometheus"}},
                "aggs": {
                    "by_alertname": {
                        "terms": {"field": "data.alertname", "size": 20, "order": {"_count": "desc"}}
                    },
                    "by_severity": {
                        "terms": {"field": "data.severity", "size": 10}
                    }
                }
            }
        }
    }).encode()
    req_wa = urllib.request.Request(
        "https://172.18.0.1:9200/wazuh-alerts-4.x-*/_search",
        data=wazuh_alert_body,
        headers={"Authorization": wazuh_auth, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req_wa, context=ctx, timeout=10) as r:
        wda = json.loads(r.read().decode())
    aggs = wda.get("aggregations", {})
    prom_bridge = aggs.get("prometheus_bridge", {})
    report["wazuh_alerts_last_24h"] = {
        "by_level":  {str(b["key"]): b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
        "by_agent":  {b["key"]: b["doc_count"] for b in aggs.get("by_agent", {}).get("buckets", [])},
        "by_rule":   {b["key"]: b["doc_count"] for b in aggs.get("by_rule", {}).get("buckets", [])},
        "prometheus_bridge_by_alertname": {
            b["key"]: b["doc_count"]
            for b in prom_bridge.get("by_alertname", {}).get("buckets", [])
        },
        "prometheus_bridge_by_severity": {
            b["key"]: b["doc_count"]
            for b in prom_bridge.get("by_severity", {}).get("buckets", [])
        },
    }
except Exception as e:
    report["wazuh_alerts_last_24h"] = f"Error: {e}"

# ── Wazuh helper: run an Indexer aggregation query ─────────────────────────────
def _wazuh_query(body_dict, index="wazuh-alerts-4.x-*", timeout=15):
    """POST a search body to the Wazuh Indexer; return the parsed JSON or {}."""
    try:
        req = urllib.request.Request(
            f"https://172.18.0.1:9200/{index}/_search",
            data=json.dumps(body_dict).encode(),
            headers={"Authorization": wazuh_auth, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"_error": str(e)}

def _wazuh_count(body_dict, index="wazuh-alerts-4.x-*", timeout=10):
    try:
        req = urllib.request.Request(
            f"https://172.18.0.1:9200/{index}/_count",
            data=json.dumps(body_dict).encode(),
            headers={"Authorization": wazuh_auth, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return json.loads(r.read().decode()).get("count", 0)
    except Exception:
        return 0

_W24 = {"range": {"@timestamp": {"gte": "now-24h"}}}

# === Wazuh Agent Summary (enriched from wazuh-monitoring index) ===
try:
    # wazuh-monitoring-* stores flat docs (id, name, ip, status at root — not nested under agent.*)
    mon = _wazuh_query({
        "size": 100,
        "_source": ["id", "name", "ip", "status", "dateAdd", "timestamp",
                    "node_name", "group_config_status", "registerIP"]
    }, index="wazuh-monitoring-*")
    mon_by_id = {}
    for hit in mon.get("hits", {}).get("hits", []):
        s = hit["_source"]
        aid = s.get("id", "")
        if aid and aid not in mon_by_id:
            mon_by_id[aid] = s
    # Enrich agent list with IPs from the alerts index (more reliable than monitoring docs)
    ip_lookup_body = json.dumps({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "agents": {
                "terms": {"field": "agent.name", "size": 50},
                "aggs": {
                    "agent_id": {"terms": {"field": "agent.id", "size": 1}},
                    "agent_ip": {"terms": {"field": "agent.ip", "size": 1}},
                    "last_seen": {"max": {"field": "@timestamp"}}
                }
            }
        }
    }).encode()
    req_ip = urllib.request.Request(
        "https://172.18.0.1:9200/wazuh-alerts-4.x-*/_search",
        data=ip_lookup_body,
        headers={"Authorization": wazuh_auth, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req_ip, context=ctx, timeout=10) as r:
        ip_data = json.loads(r.read().decode())
    alerts_agents = {}
    for b in ip_data.get("aggregations", {}).get("agents", {}).get("buckets", []):
        aid_buckets = b.get("agent_id", {}).get("buckets", [])
        ip_buckets  = b.get("agent_ip", {}).get("buckets", [])
        if aid_buckets:
            alerts_agents[aid_buckets[0]["key"]] = {
                "name":      b["key"],
                "ip":        ip_buckets[0]["key"] if ip_buckets else "",
                "status":    "active",
                "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
            }
    # Base list from alert-derived agents; enrich with monitoring fields + alert IPs
    base_agents = report.get("wazuh_agents", [])
    agent_summary = []
    for ag in base_agents:
        aid = ag.get("id", "")
        m = mon_by_id.get(aid, {})
        a = alerts_agents.get(aid, {})
        agent_summary.append({
            "agent_id":          aid,
            "agent_name":        ag.get("name", m.get("name", "")),
            "ip":                a.get("ip") or m.get("ip", ""),
            "status":            a.get("status") or ag.get("status", ""),
            "registration_date": m.get("dateAdd", ""),
            "last_keep_alive":   a.get("last_seen") or ag.get("last_seen", ""),
            "node_name":         m.get("node_name", ""),
            "group":             m.get("group_config_status", ""),
        })
    # Include any monitoring-only or alerts-only agents not in wazuh_agents list
    alert_ids = {ag.get("id") for ag in base_agents}
    for aid, s in mon_by_id.items():
        if aid not in alert_ids:
            a = alerts_agents.get(aid, {})
            agent_summary.append({
                "agent_id":          aid,
                "agent_name":        s.get("name", ""),
                "ip":                a.get("ip") or s.get("ip", ""),
                "status":            a.get("status") or s.get("status", ""),
                "registration_date": s.get("dateAdd", ""),
                "last_keep_alive":   a.get("last_seen") or s.get("timestamp", ""),
                "node_name":         s.get("node_name", ""),
                "group":             s.get("group_config_status", ""),
            })
    report["wazuh_agent_summary"] = sorted(agent_summary, key=lambda x: x.get("agent_id", ""))
except Exception as e:
    report["wazuh_agent_summary"] = {"error": str(e), "fallback": report.get("wazuh_agents", [])}

# === Wazuh Threat Hunting — last 24h ===
try:
    th = _wazuh_query({
        "size": 0,
        "track_total_hits": True,
        "query": _W24,
        "aggs": {
            "total":         {"value_count": {"field": "rule.id"}},
            "level_12_plus": {"filter": {"range": {"rule.level": {"gte": 12}}}},
            "auth_success":  {"filter": {"terms": {"rule.groups": [
                "authentication_success", "pam", "sshd"
            ]}}},
            "auth_failure":  {"filter": {"terms": {"rule.groups": [
                "authentication_failure", "authentication_failed", "win_authentication_failed"
            ]}}},
            "top_alerts":    {"terms": {"field": "rule.description", "size": 15,
                                        "order": {"_count": "desc"}}},
            "top_groups":    {"terms": {"field": "rule.groups", "size": 20,
                                        "order": {"_count": "desc"}}},
            "by_level":      {"terms": {"field": "rule.level", "size": 15,
                                        "order": {"_key": "desc"}}},
            "by_agent":      {"terms": {"field": "agent.name", "size": 20,
                                        "order": {"_count": "desc"}}},
        }
    })
    if "_error" in th:
        raise Exception(th["_error"])
    a = th.get("aggregations", {})
    total_24h = th.get("hits", {}).get("total", {}).get("value", 0)
    report["wazuh_threat_hunting"] = {
        "window":               "24h",
        "total_alerts":         total_24h,
        "level_12_or_above":    a.get("level_12_plus", {}).get("doc_count", 0),
        "authentication_success": a.get("auth_success", {}).get("doc_count", 0),
        "authentication_failure": a.get("auth_failure", {}).get("doc_count", 0),
        "top_alerts": [
            {"description": b["key"], "count": b["doc_count"]}
            for b in a.get("top_alerts", {}).get("buckets", [])
        ],
        "top_rule_groups": [
            {"group": b["key"], "count": b["doc_count"]}
            for b in a.get("top_groups", {}).get("buckets", [])
        ],
        "alerts_by_level": [
            {"level": b["key"], "count": b["doc_count"]}
            for b in a.get("by_level", {}).get("buckets", [])
        ],
        "alerts_by_agent": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in a.get("by_agent", {}).get("buckets", [])
        ],
    }
except Exception as e:
    report["wazuh_threat_hunting"] = {"error": str(e), "window": "24h"}

# === Wazuh MITRE ATT&CK — last 24h ===
try:
    mi = _wazuh_query({
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"must": [_W24, {"exists": {"field": "rule.mitre.tactic"}}]}},
        "aggs": {
            "total":          {"value_count": {"field": "rule.id"}},
            "top_tactics":    {"terms": {"field": "rule.mitre.tactic",     "size": 20}},
            "top_techniques": {"terms": {"field": "rule.mitre.technique",  "size": 20}},
            "top_ids":        {"terms": {"field": "rule.mitre.id",         "size": 20}},
            "by_agent":       {"terms": {"field": "agent.name",            "size": 20}},
            "tactic_x_level": {
                "terms": {"field": "rule.mitre.tactic", "size": 10},
                "aggs": {"avg_level": {"avg": {"field": "rule.level"}}}
            },
        }
    })
    if "_error" in mi:
        raise Exception(mi["_error"])
    a = mi.get("aggregations", {})
    report["wazuh_mitre_attack"] = {
        "window":       "24h",
        "total_alerts_with_mitre": mi.get("hits", {}).get("total", {}).get("value", 0),
        "top_tactics": [
            {"tactic": b["key"], "count": b["doc_count"]}
            for b in a.get("top_tactics", {}).get("buckets", [])
        ],
        "top_techniques": [
            {"technique": b["key"], "count": b["doc_count"]}
            for b in a.get("top_techniques", {}).get("buckets", [])
        ],
        "top_mitre_ids": [
            {"id": b["key"], "count": b["doc_count"]}
            for b in a.get("top_ids", {}).get("buckets", [])
        ],
        "rule_level_by_tactic": [
            {"tactic": b["key"], "count": b["doc_count"],
             "avg_rule_level": round(b.get("avg_level", {}).get("value") or 0, 1)}
            for b in a.get("tactic_x_level", {}).get("buckets", [])
        ],
        "alerts_by_agent": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in a.get("by_agent", {}).get("buckets", [])
        ],
    }
except Exception as e:
    report["wazuh_mitre_attack"] = {"error": str(e), "window": "24h"}

# === Wazuh File Integrity Monitoring — last 24h ===
try:
    fim_q = {
        "size": 0,
        "query": {"bool": {"must": [
            _W24,
            {"terms": {"rule.groups": ["syscheck", "fim",
                                       "syscheck_entry_modified",
                                       "syscheck_entry_added",
                                       "syscheck_entry_deleted"]}}
        ]}},
        "aggs": {
            "by_action":  {"terms": {"field": "syscheck.event",  "size": 10}},
            "top_paths":  {"terms": {"field": "syscheck.path",   "size": 20,
                                     "order": {"_count": "desc"}}},
            "by_agent":   {"terms": {"field": "agent.name",      "size": 20}},
            "by_rule":    {"terms": {"field": "rule.description", "size": 10}},
        }
    }
    fim_data = _wazuh_query(fim_q)
    fim_recent = _wazuh_query({
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            _W24,
            {"terms": {"rule.groups": ["syscheck", "fim",
                                       "syscheck_entry_modified",
                                       "syscheck_entry_added",
                                       "syscheck_entry_deleted"]}}
        ]}},
        "_source": ["@timestamp", "agent.id", "agent.name",
                    "syscheck.path", "syscheck.event",
                    "rule.id", "rule.level", "rule.description"]
    })
    if "_error" in fim_data:
        raise Exception(fim_data["_error"])
    fa = fim_data.get("aggregations", {})
    actions = {b["key"]: b["doc_count"]
               for b in fa.get("by_action", {}).get("buckets", [])}
    recent_events = []
    for h in fim_recent.get("hits", {}).get("hits", []):
        s = h["_source"]
        sc = s.get("syscheck", {})
        ag = s.get("agent", {})
        ru = s.get("rule", {})
        recent_events.append({
            "timestamp":       s.get("@timestamp", ""),
            "agent_id":        ag.get("id", ""),
            "agent_name":      ag.get("name", ""),
            "path":            sc.get("path", ""),
            "action":          sc.get("event", ""),
            "rule_id":         ru.get("id", ""),
            "rule_level":      ru.get("level", 0),
            "rule_description": ru.get("description", ""),
        })
    report["wazuh_fim"] = {
        "window":       "24h",
        "total_events": fim_data.get("hits", {}).get("total", {}).get("value", 0),
        "actions": {
            "added":    actions.get("added",    0),
            "modified": actions.get("modified", 0),
            "deleted":  actions.get("deleted",  0),
        },
        "top_paths": [
            {"path": b["key"], "count": b["doc_count"]}
            for b in fa.get("top_paths", {}).get("buckets", [])
        ],
        "by_agent": [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in fa.get("by_agent", {}).get("buckets", [])
        ],
        "recent_events": recent_events,
    }
except Exception as e:
    report["wazuh_fim"] = {"error": str(e), "window": "24h",
                            "total_events": 0, "actions": {"added": 0, "modified": 0, "deleted": 0}}

# === Wazuh Vulnerability Detection ===
# wazuh-states-vulnerabilities-* is present but has 0 docs (scanning not yet active)
try:
    vuln_total = _wazuh_count({"query": {"match_all": {}}},
                               index="wazuh-states-vulnerabilities-*")
    if vuln_total and vuln_total > 0:
        vd = _wazuh_query({
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                "by_package":  {"terms": {"field": "vulnerability.package.name", "size": 20,
                                          "order": {"_count": "desc"}}},
                "by_agent":    {"terms": {"field": "agent.name", "size": 20}},
            }
        }, index="wazuh-states-vulnerabilities-*")
        va = vd.get("aggregations", {})
        sevs = {b["key"].lower(): b["doc_count"]
                for b in va.get("by_severity", {}).get("buckets", [])}
        report["wazuh_vulnerabilities"] = {
            "total":    vuln_total,
            "critical": sevs.get("critical", 0),
            "high":     sevs.get("high",     0),
            "medium":   sevs.get("medium",   0),
            "low":      sevs.get("low",      0),
            "top_packages": [
                {"package": b["key"], "count": b["doc_count"]}
                for b in va.get("by_package", {}).get("buckets", [])
            ],
            "by_agent": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in va.get("by_agent", {}).get("buckets", [])
            ],
        }
    else:
        report["wazuh_vulnerabilities"] = {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "top_packages": [], "by_agent": [],
            "note": "Vulnerability states index empty — scanning may not be configured"
        }
except Exception as e:
    report["wazuh_vulnerabilities"] = {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "top_packages": [], "by_agent": [], "error": str(e)
    }

# === Wazuh Security Configuration Assessment (SCA) ===
# SCA summary data is from wazuh-monitoring-* agent docs (agent.lastSCA fields)
# or from SCA alert events in the alerts index.
try:
    # Use 60d window to catch agents that scan infrequently; filter on summary events only
    # (type=summary are policy-level results; other types are per-check events)
    sca_d = _wazuh_query({
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": "now-60d"}}},
            {"terms": {"rule.groups": ["sca"]}},
            {"term":  {"data.sca.type": "summary"}}
        ]}},
        "_source": ["@timestamp", "agent.id", "agent.name",
                    "data.sca.policy", "data.sca.passed", "data.sca.failed",
                    "data.sca.invalid", "data.sca.score",
                    "data.sca.policy_id", "data.sca.description",
                    "rule.description"]
    })
    sca_hits = sca_d.get("hits", {}).get("hits", [])
    seen_agents = set()
    sca_summary = []
    for h in sca_hits:
        s = h["_source"]
        ag = s.get("agent", {})
        sca = s.get("data", {}).get("sca", {})
        aid = ag.get("id", "")
        policy_id = sca.get("policy_id", "") or sca.get("policy", "")
        key = f"{ag.get('name', aid)}:{policy_id}"
        if key in seen_agents:
            continue
        seen_agents.add(key)
        passed = int(sca.get("passed") or 0)
        failed = int(sca.get("failed") or 0)
        total  = passed + failed
        score  = round(passed / total * 100, 1) if total > 0 else None
        sca_summary.append({
            "agent_id":        aid,
            "agent_name":      ag.get("name", ""),
            "policy":          sca.get("policy", s.get("rule", {}).get("description", "")),
            "policy_id":       policy_id,
            "timestamp":       s.get("@timestamp", ""),
            "passed":          passed,
            "failed":          failed,
            "not_applicable":  int(sca.get("invalid") or 0),
            "score_percent":   score,
        })
    report["wazuh_sca"] = sca_summary if sca_summary else {
        "note": "No SCA summary events in last 60 days — agents may not have SCA policies configured",
        "total_policies": 0
    }
except Exception as e:
    report["wazuh_sca"] = {"error": str(e),
                            "note": "SCA full detail requires Wazuh API (port 55000)"}

# === Wazuh Compliance — PCI DSS / GDPR — last 24h ===
try:
    comp = _wazuh_query({
        "size": 0,
        "query": _W24,
        "aggs": {
            "pci_dss":      {"terms": {"field": "rule.pci_dss",      "size": 30,
                                       "order": {"_count": "desc"}}},
            "gdpr":         {"terms": {"field": "rule.gdpr",         "size": 20,
                                       "order": {"_count": "desc"}}},
            "hipaa":        {"terms": {"field": "rule.hipaa",        "size": 20,
                                       "order": {"_count": "desc"}}},
            "nist_800_53":  {"terms": {"field": "rule.nist_800_53",  "size": 20,
                                       "order": {"_count": "desc"}}},
            "gpg13":        {"terms": {"field": "rule.gpg13",        "size": 20,
                                       "order": {"_count": "desc"}}},
        }
    })
    if "_error" in comp:
        raise Exception(comp["_error"])
    ca = comp.get("aggregations", {})
    def _comp_list(key):
        return [{"requirement": b["key"], "count": b["doc_count"]}
                for b in ca.get(key, {}).get("buckets", [])]
    report["wazuh_compliance"] = {
        "window":    "24h",
        "pci_dss":   _comp_list("pci_dss"),
        "gdpr":      _comp_list("gdpr"),
        "hipaa":     _comp_list("hipaa"),
        "nist_800_53": _comp_list("nist_800_53"),
        "gpg13":     _comp_list("gpg13"),
    }
except Exception as e:
    report["wazuh_compliance"] = {"error": str(e), "window": "24h"}

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
import math

class _CleanEncoder(json.JSONEncoder):
    def iterencode(self, o, _one_shot=False):
        return super().iterencode(self._clean(o), _one_shot)
    def _clean(self, o):
        if isinstance(o, float):
            return None if (math.isnan(o) or math.isinf(o)) else o
        if isinstance(o, dict):
            return {k: self._clean(v) for k, v in o.items()}
        if isinstance(o, list):
            return [self._clean(v) for v in o]
        return o

output = json.dumps(report, indent=2, cls=_CleanEncoder)

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
