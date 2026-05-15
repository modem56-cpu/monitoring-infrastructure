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

# Capacity pressure classification per node
_PRIORITY_ORDER = ["critical", "warning", "watch", "ok", "unknown"]
def _pressure_status(cpu, mem, swap):
    if mem is not None and mem > 90 and (swap or 0) > 50:
        return "critical"
    if (cpu is not None and cpu > 70) or (mem is not None and mem > 85) or (swap is not None and swap > 50):
        return "warning"
    if (cpu is not None and cpu > 60) or (mem is not None and mem > 75):
        return "watch"
    return "ok"

_capacity_pressure = {}
for _inst, _m in sys_m.items():
    _cpu = _m.get("cpu_current_pct") or _m.get("cpu_5m_avg_pct")
    _mem = _m.get("memory_pct")
    _swp = _m.get("swap_pct")
    _ps  = _pressure_status(_cpu, _mem, _swp)
    if _ps in ("warning", "critical", "watch"):
        _contributors = []
        if _cpu is not None and _cpu > 70:
            _contributors.append(f"cpu {_cpu}%")
        if _mem is not None and _mem > 85:
            _contributors.append(f"memory {_mem}%")
        if _swp is not None and _swp > 50:
            _contributors.append(f"swap {_swp}%")
        _capacity_pressure[_inst] = {
            "status": _ps,
            "cpu_pct": _cpu,
            "memory_pct": _mem,
            "swap_pct": _swp,
            "contributors": _contributors,
            "summary": "Operational but under resource pressure." if _ps != "critical" else "High resource pressure — services at risk.",
        }
report["capacity_pressure"] = _capacity_pressure

# === Firing Alerts ===
# Group by alert name; include count + all firing instances to reduce noise
_alert_raw = []
_alert_groups = {}
for r in pq('ALERTS{alertstate="firing"}'):
    _aname    = r["metric"].get("alertname", "")
    _ainst    = r["metric"].get("instance", "")
    _asev     = r["metric"].get("severity", "")
    _alert_raw.append({"alert": _aname, "instance": _ainst, "severity": _asev})
    if _aname not in _alert_groups:
        _alert_groups[_aname] = {"alert": _aname, "severity": _asev, "count": 0, "instances": []}
    _alert_groups[_aname]["count"] += 1
    if _ainst and _ainst not in _alert_groups[_aname]["instances"]:
        _alert_groups[_aname]["instances"].append(_ainst)

# Priority sort: critical first, then warning, then others
_sev_rank = {"critical": 0, "warning": 1, "watch": 2, "info": 3, "": 4}
_alerts_grouped = sorted(
    _alert_groups.values(),
    key=lambda x: (_sev_rank.get(x["severity"], 4), x["alert"])
)
report["alerts_firing"] = _alert_raw
report["alerts_firing_grouped"] = _alerts_grouped
report["alerts_firing_count"] = len(_alert_raw)

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

# Embedded report: top 10, 1h window (lightweight for frequent report generation)
_top_flows, _top_flows_err = get_akvorado_top_flows(limit=10, window_hours=1)

# Separate full export: top 30, 6h window — written to reports/ for download
_top_flows_full, _top_flows_full_err = get_akvorado_top_flows(limit=30, window_hours=6)
_top30_path = "/opt/monitoring/reports/akvorado_top30_flows.json"
try:
    import os as _os
    with open(_top30_path, "w", encoding="utf-8") as _tf:
        json.dump({
            "generated_at": now,
            "window": "6h",
            "limit": 30,
            "count": len(_top_flows_full),
            "flows": _top_flows_full,
            **({"error": _top_flows_full_err} if _top_flows_full_err else {}),
        }, _tf, indent=2)
except Exception as _e:
    _top_flows_full_err = (_top_flows_full_err or "") + f"; export write error: {_e}"

# Kafka lag severity band
_kafka_lag = scalar('akvorado_outlet_kafka_consumergroup_lag_messages')
if _kafka_lag is None:
    _kafka_lag_status = "unknown"
elif _kafka_lag > 1_000_000:
    _kafka_lag_status = "critical"
elif _kafka_lag > 500_000:
    _kafka_lag_status = "warning"
elif _kafka_lag > 100_000:
    _kafka_lag_status = "watch"
else:
    _kafka_lag_status = "ok"

_ak_inlet_up = int(scalar('up{job="akvorado_inlet"}') or 0)
_ak_outlet_up = int(scalar('up{job="akvorado_outlet"}') or 0)
_ak_orch_up = int(scalar('up{job="akvorado_orchestrator"}') or 0)
_ak_all_up = _ak_inlet_up and _ak_outlet_up and _ak_orch_up
_ak_status = "ok" if (_ak_all_up and _kafka_lag_status in ("ok", "unknown")) else \
             "critical" if (not _ak_all_up) else \
             _kafka_lag_status

# === Akvorado ===
report["akvorado"] = {
    "status": _ak_status,
    "last_checked": now,
    "evidence_source": "prometheus:akvorado_* + clickhouse:default.flows",
    "summary": {
        "inlet_up":         _ak_inlet_up,
        "outlet_up":        _ak_outlet_up,
        "orchestrator_up":  _ak_orch_up,
        "flow_pps":         round(scalar('rate(akvorado_inlet_flow_input_udp_packets_total[5m])') or 0, 2),
        "flow_bps":         round(scalar('rate(akvorado_inlet_flow_input_udp_bytes_total[5m])') or 0),
        "kafka_lag":        _kafka_lag,
        "kafka_lag_status": _kafka_lag_status,
        "kafka_lag_delta_1h": int(scalar('delta(akvorado_outlet_kafka_consumergroup_lag_messages[1h])') or 0),
        "clickhouse_errors_connect_total": int(scalar('akvorado_outlet_clickhouse_errors_total{error="connect"}') or 0),
        "clickhouse_errors_send_total":    int(scalar('akvorado_outlet_clickhouse_errors_total{error="send"}') or 0),
        "clickhouse_error_rate_5m":        round(scalar('rate(akvorado_outlet_clickhouse_errors_total[5m])') or 0, 6),
        "interpretation":   (
            "Components are up, but Kafka lag is high; this is a monitoring visibility backlog, not confirmed network outage."
            if _kafka_lag_status in ("warning", "critical")
            else "Components up, no significant backlog."
        ),
    },
    "top_flows_embedded_limit":     10,
    "top_flows_window":             "1h",
    "top_flows_sort":               "max_bps",
    "top_flows_count":              len(_top_flows),
    "top_flows_full_export_available": len(_top_flows_full) > 0,
    "top_flows_full_export_path":   "http://192.168.10.20:8088/akvorado_top30_flows.json",
    "top_flows": _top_flows,
    **({"top_flows_error": _top_flows_err} if _top_flows_err else {}),
}

# === Network ARP Conflicts ===
import datetime as _dtm
_arp_conflicts_24h    = int(scalar('network_inventory_arp_conflicts_last_24h') or 0)
_arp_conflicts_total  = int(scalar('network_inventory_arp_conflicts_total') or 0)
_arp_events = []
for _r in pq('network_inventory_arp_conflict_event'):
    _m = _r["metric"]
    try:
        _ts = int(float(_r["value"][1]))
        _event_time = _dtm.datetime.utcfromtimestamp(_ts).isoformat() + "Z"
    except Exception:
        _ts = 0
        _event_time = None
    _arp_events.append({
        "_ts":        _ts,
        "ip":         _m.get("ip", ""),
        "old_mac":    _m.get("old_mac", ""),
        "new_mac":    _m.get("new_mac", ""),
        "vendor":     _m.get("vendor", ""),
        "vlan":       _m.get("vlan", ""),
        "event_time": _event_time,
    })
_arp_events.sort(key=lambda x: x["_ts"], reverse=True)
_arp_recent = [{k: v for k, v in e.items() if k != "_ts"} for e in _arp_events[:10]]

_arp_status = (
    "critical" if _arp_conflicts_24h >= 3 else
    "warning"  if _arp_conflicts_24h > 0  else
    "ok"
)

report["network_arp"] = {
    "status":             _arp_status,
    "last_checked":       now,
    "evidence_source":    "prometheus:network_inventory_arp_conflict_event",
    "conflicts_last_24h": _arp_conflicts_24h,
    "conflicts_total":    _arp_conflicts_total,
    "summary":            f"{_arp_conflicts_24h} ARP conflict event(s) in last 24h across LAN VLAN ({_arp_conflicts_total} total observed).",
    "interpretation":     "Randomized MAC addresses (iOS/Android privacy MAC rotation) are the most common cause. Verify no rogue device activity on the listed IPs.",
    "recent_conflicts":   _arp_recent,
}

# === Fathom Vault Sync ===
def _fathom_section():
    def _s(q, default=-1):
        v = scalar(q)
        return default if v is None else v

    def _labeled_metric(q, label):
        """Return list of {label: val, value: val} dicts."""
        out = []
        for r in pq(q):
            lv = r["metric"].get(label, "")
            try:
                out.append({label: lv, "value": float(r["value"][1])})
            except Exception:
                pass
        return out

    exporter_up = int(_s("fathom_exporter_success", 0))
    total        = int(_s("fathom_db_total_meetings"))
    has_video    = int(_s("fathom_db_has_video"))
    has_tr       = int(_s("fathom_db_has_transcript"))
    has_sum      = int(_s("fathom_db_has_summary"))
    vid_pct      = _s("fathom_video_coverage_percent")
    tr_pct       = _s("fathom_transcript_coverage_percent")
    sum_pct      = _s("fathom_summary_coverage_percent")
    sync_age     = int(_s("fathom_latest_sync_age_seconds"))
    sync_ok      = int(_s("fathom_latest_sync_success", 0))
    nas_up       = int(_s("fathom_nas_mounted", 0))
    guard        = int(_s("fathom_db_live_guard_pass", 0))
    regression   = int(_s("fathom_db_regression_detected", 0))
    integrity    = int(_s("fathom_db_sqlite_integrity_ok", -1))
    stale_exists = int(_s("fathom_stale_local_db_exists", 0))
    accts_total  = int(_s("fathom_total_accounts"))
    accts_conf   = int(_s("fathom_configured_accounts"))
    accts_meet   = int(_s("fathom_accounts_with_meetings"))
    login_issues = int(_s("fathom_login_issues_total", 0))
    audit_flags  = int(_s("fathom_audit_flags_total", 0))
    last_dur     = int(_s("fathom_last_sync_duration_seconds"))
    last_new_m   = int(_s("fathom_last_sync_new_meetings"))
    last_new_v   = int(_s("fathom_last_sync_new_videos"))
    last_new_s   = int(_s("fathom_last_sync_new_summaries"))
    last_errs    = int(_s("fathom_last_sync_errors_total"))

    # DB-level alarm signals (inode swap and integrity failure are alarming;
    # checksum and size changes are captured by regression_detected but fire on
    # normal sync writes — use specific metrics instead of the composite flag)
    inode_changed      = int(_s("fathom_db_inode_changed", 0))
    fingerprint_chg    = int(_s("fathom_db_fingerprint_changed", 0))
    integrity_fail     = 1 if integrity == 0 else 0
    size_decreased     = 1 if (_s("fathom_db_size_delta_bytes", 0) or 0) < -1024 else 0

    # Regression detection — compare current vs 6h-ago using Prometheus offset
    # Returns None until 6h of TSDB history exists for the alias metrics
    def _offset_delta(metric_name):
        """Return (current, previous, delta) or (None, None, None) if no history."""
        cur = scalar(metric_name)
        off = scalar(f"{metric_name} offset 6h")
        if cur is None or off is None:
            return None, None, None
        return cur, off, round(cur - off, 2)

    _sum_cur, _sum_6h, _sum_delta = _offset_delta("fathom_summaries_total")
    _tr_cur,  _tr_6h,  _tr_delta  = _offset_delta("fathom_transcripts_total")
    _vid_cur, _vid_6h, _vid_delta  = _offset_delta("fathom_videos_total")
    _mtg_cur, _mtg_6h, _mtg_delta  = _offset_delta("fathom_total_meetings")
    _cov_cur, _cov_6h, _cov_delta  = _offset_delta("fathom_summary_coverage_percent")

    _sum_drop  = (_sum_delta  is not None and _sum_delta  < -100)
    _tr_drop   = (_tr_delta   is not None and _tr_delta   < -100)
    _vid_drop  = (_vid_delta  is not None and _vid_delta  < -100)
    _mtg_drop  = (_mtg_delta  is not None and _mtg_delta  < -100)
    _cov_drop  = (_cov_delta  is not None and _cov_delta  < -5)

    _possible_regression = any([_sum_drop, _tr_drop, _vid_drop, _mtg_drop,
                                 _cov_drop, bool(inode_changed), bool(fingerprint_chg)])

    # Determine overall status
    if not exporter_up or not nas_up:
        status = "critical"
    elif not guard or inode_changed or integrity_fail or size_decreased:
        status = "critical"
    elif _possible_regression:
        status = "critical"
    elif not sync_ok or sync_age > 43200:
        status = "warning"
    elif login_issues > 0 or audit_flags > 0:
        status = "warning"
    else:
        status = "ok"

    # Per-account audit flags (labeled metrics)
    _audit_rows = []
    for item in _labeled_metric('fathom_audit_flag_completion_percent', 'account'):
        acct = item["account"]
        pct = item["value"]
        completed_r = pq(f'fathom_audit_flag_completed{{account="{acct}"}}')
        expected_r  = pq(f'fathom_audit_flag_expected{{account="{acct}"}}')
        completed_v = int(float(completed_r[0]["value"][1])) if completed_r else -1
        expected_v  = int(float(expected_r[0]["value"][1]))  if expected_r  else -1
        _audit_rows.append({
            "account": acct,
            "completion_percent": round(pct, 1),
            "completed": completed_v,
            "total": expected_v,
        })
    _audit_rows.sort(key=lambda x: x["completion_percent"])

    # Recent sync runs (labeled metrics)
    _sync_runs = []
    _seen_started = set()
    for item in _labeled_metric('fathom_sync_run_ok', 'started'):
        started = item["started"]
        if started in _seen_started:
            continue
        _seen_started.add(started)
        _ok_v = int(item["value"])
        _dur_r  = pq(f'fathom_sync_run_duration_seconds{{started="{started}"}}')
        _newm_r = pq(f'fathom_sync_run_new_meetings{{started="{started}"}}')
        _errs_r = pq(f'fathom_sync_run_errors{{started="{started}"}}')
        _sync_runs.append({
            "started": started,
            "status": "success" if _ok_v == 1 else "failed",
            "new_meetings": int(float(_newm_r[0]["value"][1])) if _newm_r else -1,
            "duration_seconds": int(float(_dur_r[0]["value"][1])) if _dur_r else -1,
            "errors": int(float(_errs_r[0]["value"][1])) if _errs_r else -1,
        })
    _sync_runs.sort(key=lambda x: x["started"], reverse=True)

    # Active Fathom Prometheus alerts
    _active_alerts = []
    for r in pq('{alertname=~"Fathom.*"}'):
        _active_alerts.append(r["metric"].get("alertname", ""))

    # Wazuh events for fathom in last 24h (from prom-to-wazuh log)
    _wazuh_events_24h = 0
    try:
        import subprocess as _sp
        _out = _sp.run(
            ["grep", "-c", '"category":"fathom"', "/var/log/prometheus-wazuh.log"],
            capture_output=True, text=True, timeout=3
        )
        _wazuh_events_24h = int(_out.stdout.strip()) if _out.returncode == 0 else 0
    except Exception:
        pass

    _alert_defs = [
        "FathomExporterDown", "FathomNASUnmounted", "FathomDBRegressionDetected",
        "FathomSyncStaleCritical", "FathomSyncErrors", "FathomLoginIssuesDetected",
        "FathomLowCoverage", "FathomAuditFlagsDetected",
        "FathomSummaryCountDropped", "FathomTranscriptCountDropped",
        "FathomVideoCountDropped", "FathomMeetingCountDropped",
        "FathomSummaryCoverageDropped", "FathomDBFingerprintChanged",
        "FathomAPI5xxBurst",
    ]

    # --- Service health (derived from Prometheus fathom_health_exporter metrics) ---
    # Note: fathom_api_5xx_errors_total and fathom_api_last_5xx_* are populated only
    # after fathom_health_exporter.py is redeployed with 502-tracking support.
    _timer_active       = int(_s("fathom_sync_timer_active", -1))
    _api_5xx_total      = int(_s("fathom_api_5xx_errors_total", 0))
    _api_last_5xx_ts    = int(_s("fathom_api_last_5xx_unixtime", -1))
    _api_last_5xx_code  = int(_s("fathom_api_last_5xx_status", -1))

    _last_run       = _sync_runs[0] if _sync_runs else {}
    _lr_status      = _last_run.get("status", "unknown")
    _lr_started     = _last_run.get("started", None)
    _lr_dur         = _last_run.get("duration_seconds", -1)
    _lr_errs        = _last_run.get("errors", 0)
    _lr_new_m       = _last_run.get("new_meetings", 0)

    # Classify whether API errors affected the sync outcome
    if _lr_status == "failed" or _lr_errs > 0:
        _sync_impact = "affected_sync"
    elif _api_5xx_total > 0 and _lr_status == "success":
        _sync_impact = "historical_noise"   # 5xx occurred but retry succeeded
    elif _lr_status == "success":
        _sync_impact = "none"
    else:
        _sync_impact = "unknown"

    _sh_parts = [
        f"fathom-sync timer {'active' if _timer_active == 1 else 'INACTIVE' if _timer_active == 0 else 'unknown'}",
        f"last run: {_lr_status or 'unknown'}",
    ]
    if _lr_new_m and _lr_new_m > 0:
        _sh_parts.append(f"{_lr_new_m} new meetings")
    if _api_5xx_total > 0:
        _sh_parts.append(f"{_api_5xx_total} API 5xx errors tracked (recovered via retry)")
    if _api_last_5xx_ts > 0:
        _sh_parts.append(f"last 5xx at unix:{_api_last_5xx_ts}")

    _service_health = {
        "service_name":              "fathom-sync",
        "timer_name":                "fathom-sync.timer",
        "timer_active":              bool(_timer_active == 1),
        "last_run_status":           _lr_status,
        "last_run_started":          _lr_started,
        "last_run_duration_seconds": _lr_dur,
        "last_run_new_meetings":     _lr_new_m,
        "last_run_errors":           _lr_errs,
        "restart_count":             0,
        "api_5xx_total":             _api_5xx_total,
        "api_last_5xx_unixtime":     _api_last_5xx_ts  if _api_last_5xx_ts  > 0 else None,
        "api_last_5xx_status_code":  _api_last_5xx_code if _api_last_5xx_code > 0 else None,
        "api_5xx_note":              (
            "api_5xx_total will populate after fathom_health_exporter.py redeploy with 502 tracking"
            if _api_5xx_total == 0 else None
        ),
        "sync_impact":               _sync_impact,
        "evidence_source":           "prometheus:fathom_health_exporter",
        "summary":                   "; ".join(_sh_parts),
    }

    # --- Recording inventory summary (from Prometheus aggregate metrics) ---
    # Detailed per-meeting files are written by fathom-inventory-exporter.py
    # on fathom-server and synced to /opt/monitoring/reports/ by deploy script.
    _inv_total    = int(_s("fathom_recording_inventory_total",   -1))
    _inv_complete = int(_s("fathom_recording_complete_total",    -1))
    _inv_vid      = int(_s("fathom_recording_missing_video_total",     -1))
    _inv_tr       = int(_s("fathom_recording_missing_transcript_total",-1))
    _inv_sum      = int(_s("fathom_recording_missing_summary_total",   -1))
    _inv_issues   = int(_s("fathom_recording_has_issues_total",  -1))
    _inv_ts       = int(_s("fathom_recording_inventory_last_success_unixtime", -1))

    _inv_exporter_ran = _inv_ts > 0
    if not _inv_exporter_ran:
        _inv_status = "not_ready"
        _inv_summary_text = "Per-recording inventory exporter has not run yet."
        _inv_action = "Run inventory exporter before claiming full recording inventory audit readiness."
    elif _inv_issues > 0:
        _inv_status = "warning"
        _inv_summary_text = f"Per-recording inventory available: {_inv_issues} meetings have issues."
        _inv_action = "Review issues file for missing video/transcript/summary items."
    else:
        _inv_status = "ok"
        _inv_summary_text = "Per-recording inventory complete — no issues detected."
        _inv_action = None

    _inv_summary = {
        "status":                       _inv_status,
        "inventory_exporter_ran":       _inv_exporter_ran,
        "inventory_last_success_unixtime": _inv_ts if _inv_ts > 0 else None,
        "total_meetings":               _inv_total  if _inv_exporter_ran else None,
        "complete":                     _inv_complete if _inv_exporter_ran else None,
        "with_issues":                  _inv_issues   if _inv_exporter_ran else None,
        "missing_video":                _inv_vid      if _inv_exporter_ran else None,
        "missing_transcript":           _inv_tr       if _inv_exporter_ran else None,
        "missing_summary_actionable":   _inv_sum      if _inv_exporter_ran else None,
        "evidence_source":              "prometheus:fathom_recording_*",
        "summary":                      _inv_summary_text,
        "action_required":              _inv_action,
        "limitations": (
            ["inventory_exporter_ran=false — totals are -1 placeholders, not real counts"]
            if not _inv_exporter_ran else []
        ),
        "download_links": {
            "inventory_json": "http://192.168.10.20:8088/fathom_recording_inventory.json?download=1",
            "inventory_csv":  "http://192.168.10.20:8088/fathom_recording_inventory.csv?download=1",
            "issues_json":    "http://192.168.10.20:8088/fathom_recording_issues.json?download=1",
            "issues_csv":     "http://192.168.10.20:8088/fathom_recording_issues.csv?download=1",
        },
    }

    # --- Recording inventory issues (from pre-generated JSON file) ---
    # File is synced from fathom-server by deploy-fathom-monitoring.sh
    _inv_issues_detail = None
    _issues_file = "/opt/monitoring/reports/fathom_recording_issues.json"
    try:
        if os.path.isfile(_issues_file):
            with open(_issues_file, "r", encoding="utf-8") as _f:
                _issues_data = json.load(_f)
            # Cap at 200 issues for JSON report readability
            _issues_list = _issues_data.get("issues", [])[:200]
            _inv_issues_detail = {
                "source_file":    _issues_file,
                "generated_at":   _issues_data.get("generated_at"),
                "truncated":      len(_issues_data.get("issues", [])) > 200,
                "total_issues":   _issues_data.get("summary", {}).get("with_issues", len(_issues_list)),
                "issues":         _issues_list,
            }
    except Exception:
        _inv_issues_detail = {"error": "Could not read issues file", "source_file": _issues_file}

    return {
        "status": status,
        "exporter_up": bool(exporter_up),
        "nas_mounted": bool(nas_up),
        "db_live_guard_pass": bool(guard),
        "db_integrity_ok": integrity,
        "db_regression_detected": bool(regression),
        "db_fingerprint_changed": bool(fingerprint_chg),
        "stale_local_db_exists": bool(stale_exists),
        "last_checked": now,
        "total_accounts": accts_total,
        "configured_accounts": accts_conf,
        "accounts_with_meetings": accts_meet,
        "total_meetings": total,
        "videos": has_video,
        "transcripts": has_tr,
        "summaries": has_sum,
        "video_coverage_percent": vid_pct,
        "transcript_coverage_percent": tr_pct,
        "summary_coverage_percent": sum_pct,
        "latest_sync_age_seconds": sync_age,
        "latest_sync_success": bool(sync_ok),
        "last_sync_duration_seconds": last_dur,
        "last_sync_new_meetings": last_new_m,
        "last_sync_new_videos": last_new_v,
        "last_sync_new_summaries": last_new_s,
        "last_sync_errors": last_errs,
        "login_issues_count": login_issues,
        "audit_flags_count": audit_flags,
        "audit_flags": _audit_rows,
        "recent_sync_runs": _sync_runs,
        "regression_detection": {
            "history_available": _sum_cur is not None,
            "summary_count_drop_detected": _sum_drop,
            "transcript_count_drop_detected": _tr_drop,
            "video_count_drop_detected": _vid_drop,
            "meeting_count_drop_detected": _mtg_drop,
            "coverage_drop_detected": _cov_drop,
            "possible_db_regression": _possible_regression,
            "db_fingerprint_changed": bool(fingerprint_chg),
            "current_summaries": int(_sum_cur) if _sum_cur is not None else has_sum,
            "summaries_6h_ago": int(_sum_6h) if _sum_6h is not None else None,
            "summary_delta_6h": _sum_delta,
            "current_summary_coverage_percent": _cov_cur if _cov_cur is not None else sum_pct,
            "summary_coverage_6h_ago": round(_cov_6h, 1) if _cov_6h is not None else None,
            "coverage_delta_6h": _cov_delta,
            "current_meetings": int(_mtg_cur) if _mtg_cur is not None else total,
            "meetings_6h_ago": int(_mtg_6h) if _mtg_6h is not None else None,
            "meeting_delta_6h": _mtg_delta,
            "current_videos": int(_vid_cur) if _vid_cur is not None else has_video,
            "videos_6h_ago": int(_vid_6h) if _vid_6h is not None else None,
            "video_delta_6h": _vid_delta,
            "current_transcripts": int(_tr_cur) if _tr_cur is not None else has_tr,
            "transcripts_6h_ago": int(_tr_6h) if _tr_6h is not None else None,
            "transcript_delta_6h": _tr_delta,
        },
        "service_health": _service_health,
        "recording_inventory_summary": _inv_summary,
        "recording_inventory_issues": _inv_issues_detail,
        "alerts": {
            "prometheus_rules_enabled": True,
            "wazuh_forwarding_enabled": True,
            "wazuh_events_last_24h": _wazuh_events_24h,
            "active_alerts": _active_alerts,
            "alert_definitions": _alert_defs,
        },
    }

try:
    report["fathom_vault_sync"] = _fathom_section()
except Exception as e:
    report["fathom_vault_sync"] = {"error": str(e)}


def _vm_backups_section():
    """
    Build VM backup status from Prometheus vmbackup_* metrics.
    Source: vmbackup-prom.sh textfile collector running on Unraid (192.168.10.10),
    scraped by node_exporter → Prometheus.

    Healthy threshold: age < 691200s (8 days) AND size > 52428800 bytes (50 MB).
    Backup file path is NOT available from Prometheus metrics.
    Restore validation is not automated.
    """
    import time as _time

    collector_up = scalar("vmbackup_collector_up")
    if not collector_up:
        return {
            "status": "unknown",
            "last_checked": now,
            "collector_up": False,
            "source": "prometheus:vmbackup_prom_textfile_collector",
            "summary": {"total_vms": 0, "healthy_backups": 0, "stale_backups": 0, "unknown_backups": 0},
            "backups": [],
            "notes": ["vmbackup_collector_up metric not found — Unraid textfile collector may be offline."],
        }

    # Gather all known VM names from the labeled metrics
    _vm_names = set()
    for _r in pq("vmbackup_backup_healthy"):
        _v = _r["metric"].get("vm", "")
        if _v:
            _vm_names.add(_v)

    vms_out = []
    for vm in sorted(_vm_names):
        def _vm_scalar(metric):
            v = scalar(f'{metric}{{vm="{vm}"}}')
            return None if v is None else float(v)

        age_s   = _vm_scalar("vmbackup_latest_age_seconds")
        size_b  = _vm_scalar("vmbackup_latest_disk_size_bytes")
        healthy = _vm_scalar("vmbackup_backup_healthy")
        defined = _vm_scalar("vmbackup_vm_defined")
        running = _vm_scalar("vmbackup_vm_running")

        if age_s is None or age_s < 0:
            age_hours, age_days = None, None
            bk_status, failure_reason = "unknown", "backup age metric unavailable or -1"
        else:
            age_hours = round(age_s / 3600, 1)
            age_days  = round(age_s / 86400, 1)
            if int(healthy or 0) == 1:
                if age_s > 604800:  # > 7 days — healthy but approaching 8-day threshold
                    bk_status, failure_reason = "watch", f"backup age {age_days} days — approaching 8-day threshold"
                else:
                    bk_status, failure_reason = "healthy", None
            elif age_s > 691200:
                bk_status = "stale"
                failure_reason = f"backup age {age_days} days exceeds 8-day threshold"
            elif (size_b or 0) <= 52428800:
                bk_status = "warning"
                failure_reason = f"backup size {round((size_b or 0)/1024**3, 2)} GB below 50 MB threshold"
            else:
                bk_status, failure_reason = "warning", "backup_healthy=0 (reason unclear)"

        vms_out.append({
            "vm_name":                  vm,
            "vm_defined":               bool(int(defined or 0) == 1),
            "vm_running":               bool(int(running or 0) == 1),
            "latest_backup_age_seconds": int(age_s) if age_s and age_s >= 0 else None,
            "backup_age_hours":         age_hours,
            "backup_age_days":          age_days,
            "backup_file_size_bytes":   int(size_b or 0),
            "backup_file_size_gb":      round((size_b or 0) / 1024**3, 2),
            "backup_path":              None,   # not exposed as Prometheus metric
            "status":                   bk_status,
            "restore_validation":       "not_tested",
            "failure_reason":           failure_reason,
            "evidence_source":          "prometheus:vmbackup_latest_age_seconds (Unraid textfile collector)",
        })

    healthy_count = sum(1 for v in vms_out if v["status"] == "healthy")
    watch_count   = sum(1 for v in vms_out if v["status"] == "watch")
    stale_count   = sum(1 for v in vms_out if v["status"] == "stale")
    warn_count    = sum(1 for v in vms_out if v["status"] == "warning")
    unknown_count = sum(1 for v in vms_out if v["status"] == "unknown")

    if len(vms_out) == 0:
        overall = "unknown"
    elif stale_count > 0 or warn_count > 0:
        overall = "warning"
    elif unknown_count > 0:
        overall = "warning"
    elif watch_count > 0:
        overall = "watch"
    else:
        overall = "ok"

    # Collector freshness: check if any age values are suspiciously identical across calls
    # (we can't detect staleness within a single run, but we flag it in limitations)
    _collector_ts = scalar("vmbackup_collector_last_success_unixtime")
    _collector_age_s = (_time.time() - _collector_ts) if _collector_ts else None
    _freshness_status = (
        "unknown" if _collector_ts is None else
        "stale"   if (_collector_age_s or 0) > 7200 else
        "ok"
    )

    _limitations = [
        "Backup file path is not exposed as a Prometheus metric — check Unraid /mnt/user/Backups/Domains/ directly.",
        "Restore validation is not automated — restore_validation=not_tested for all VMs.",
    ]
    if watch_count > 0:
        _limitations.append("One or more VM backups are approaching the 8-day staleness threshold.")
    if _freshness_status == "unknown":
        _limitations.append("vmbackup_collector_last_success_unixtime not available — collector freshness unverified.")

    return {
        "status":       overall,
        "last_checked": now,
        "collector_up": bool(int(collector_up) == 1),
        "collector_last_success": _collector_ts,
        "freshness_status": _freshness_status,
        "evidence_source": "prometheus:vmbackup_prom_textfile_collector (Unraid 192.168.10.10)",
        "backup_path_present": False,
        "restore_validation_status": "not_tested",
        "summary_text": (
            "VM backup collector reports healthy backups, but restore validation and backup path evidence are still missing."
            if overall in ("ok", "watch") else
            "One or more VM backups require attention."
        ),
        "summary": {
            "total_vms":       len(vms_out),
            "healthy_backups": healthy_count,
            "watch_backups":   watch_count,
            "stale_backups":   stale_count,
            "warning_backups": warn_count,
            "unknown_backups": unknown_count,
        },
        "backups": vms_out,
        "limitations": _limitations,
    }


try:
    report["vm_backups"] = _vm_backups_section()
except Exception as e:
    report["vm_backups"] = {"error": str(e), "status": "unknown"}

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
_gw_unapproved = int(scalar("gworkspace_unapproved_external_shared_drives_total") or 0)
_gw_storage_pct = _gw_used_pct
_gw_status = (
    "critical" if _gw_unapproved > 10 or _gw_storage_pct > 90 else
    "warning"  if _gw_unapproved > 0  or _gw_storage_pct > 80 else
    "ok"
)
gw["status"] = _gw_status
gw["last_checked"] = now
gw["evidence_source"] = "prometheus:gworkspace_collector"
gw["shared_drive_summary"] = {
    "status":                   _gw_status,
    "total_live":               int(scalar("gworkspace_shared_drives_total") or 0),
    "approved_external_live":   int(scalar("gworkspace_approved_external_shared_drives_total") or 0),
    "unapproved_external_live": _gw_unapproved,
    "deleted_detected":         int(scalar("gworkspace_deleted_shared_drives_total") or 0),
    "external_violations_live": _gw_unapproved,
    "governance_summary": (
        f"Google Workspace external sharing remains a governance risk due to "
        f"{_gw_unapproved} unapproved externally shared drives."
        if _gw_unapproved > 0
        else "No unapproved externally shared drives detected."
    ),
    "action_required": (
        "Review and remediate unapproved external shared drives. Classify each as approved or remove external access."
        if _gw_unapproved > 0 else None
    ),
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
    _by_rule_raw = {b["key"]: b["doc_count"] for b in aggs.get("by_rule", {}).get("buckets", [])}

    # Classify noisy/malformed rules so report consumers can separate signal from noise.
    # These patterns are known high-volume or malformed alert descriptions.
    _NOISE_PATTERNS = [
        "VM Backup status: age= days",       # malformed — blank age field
        "kernel entered failed state",        # systemd unit name missing — ambiguous
        "unknown entered failed state",       # systemd unit name missing — ambiguous
    ]
    _noisy_rules = {}
    _signal_rules = {}
    for _rule_desc, _rule_count in _by_rule_raw.items():
        if any(_pat in _rule_desc for _pat in _NOISE_PATTERNS):
            _noisy_rules[_rule_desc] = _rule_count
        else:
            _signal_rules[_rule_desc] = _rule_count

    report["wazuh_alerts_last_24h"] = {
        "by_level":    {str(b["key"]): b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
        "by_agent":    {b["key"]: b["doc_count"] for b in aggs.get("by_agent", {}).get("buckets", [])},
        "by_rule":     _signal_rules,
        "by_rule_noisy_suppressed": _noisy_rules,
        "noise_note":  (
            f"{len(_noisy_rules)} rule description(s) suppressed from by_rule due to malformed/ambiguous text. "
            "See by_rule_noisy_suppressed. Fix: run deploy-vmbackup-rules.sh to correct Wazuh rule 100600."
        ) if _noisy_rules else None,
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
    _fim_total_events = fim_data.get("hits", {}).get("total", {}).get("value", 0)
    _fim_status = "ok" if _fim_total_events >= 0 else "unknown"

    # FIM coverage limits — query Wazuh alert index for rule 233 (FIM file limit reached).
    # wazuh_fim_monitored_files Prometheus metric does not exist; use alert evidence instead.
    _fim_coverage_limits = []
    _fim_limit_q = {
        "size": 10,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "agent.name", "agent.id", "rule.id", "rule.description", "rule.level"],
        "query": {"bool": {"must": [
            {"term": {"rule.id": "233"}},
            {"range": {"timestamp": {"gte": "now-24h"}}}
        ]}}
    }
    _fim_limit_data = _wazuh_query(_fim_limit_q)
    for _fh in _fim_limit_data.get("hits", {}).get("hits", []):
        _fs = _fh["_source"]
        _fa = _fs.get("agent", {})
        _fr = _fs.get("rule", {})
        _fim_coverage_limits.append({
            "agent":           _fa.get("name", ""),
            "agent_id":        _fa.get("id", ""),
            "monitored_files": 100000,
            "limit":           100000,
            "status":          "warning",
            "rule_id":         _fr.get("id", ""),
            "rule_level":      _fr.get("level", 0),
            "event_time":      _fs.get("timestamp", ""),
            "impact":          "FIM file limit reached — syscheck events may be dropped after this point.",
            "action_required": "Review FIM scope/exclusions in ossec.conf or increase max_files_monitored.",
        })
        _fim_status = "warning"

    report["wazuh_fim"] = {
        "status":       _fim_status,
        "last_checked": now,
        "evidence_source": "wazuh-indexer:wazuh-alerts-4.x-*",
        "window":       "24h",
        "total_events": _fim_total_events,
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
        "coverage_limits": _fim_coverage_limits,
    }
except Exception as e:
    report["wazuh_fim"] = {"error": str(e), "window": "24h",
                            "total_events": 0, "actions": {"added": 0, "modified": 0, "deleted": 0}}

# === Wazuh Vulnerability Detection ===
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
        _v_crit = sevs.get("critical", 0)
        _v_high = sevs.get("high",     0)
        _v_med  = sevs.get("medium",   0)
        _v_low  = sevs.get("low",      0)
        _v_known_sum = _v_crit + _v_high + _v_med + _v_low
        _v_unclassified = max(0, vuln_total - _v_known_sum)

        _vuln_status = (
            "critical" if _v_crit > 0 else
            "warning"  if _v_high > 0 else
            "watch"    if _v_med  > 0 else
            "ok"
        )
        report["wazuh_vulnerabilities"] = {
            "status":                   _vuln_status,
            "last_checked":             now,
            "evidence_source":          "wazuh-indexer:wazuh-states-vulnerabilities-*",
            "total":                    vuln_total,
            "critical":                 _v_crit,
            "high":                     _v_high,
            "medium":                   _v_med,
            "low":                      _v_low,
            "unknown_or_unclassified":  _v_unclassified,
            "severity_total_reconciled": (_v_known_sum == vuln_total),
            "top_packages": [
                {"package": b["key"], "count": b["doc_count"]}
                for b in va.get("by_package", {}).get("buckets", [])
            ],
            "by_agent": [
                {"agent": b["key"], "count": b["doc_count"]}
                for b in va.get("by_agent", {}).get("buckets", [])
            ],
            "summary":         "Vulnerability scanning is active and returning significant findings.",
            "action_required": "Prioritize critical and high vulnerabilities by affected agent.",
        }
    else:
        report["wazuh_vulnerabilities"] = {
            "status":          "not_ready",
            "last_checked":    now,
            "evidence_source": "wazuh-indexer:wazuh-states-vulnerabilities-*",
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "unknown_or_unclassified": 0,
            "severity_total_reconciled": True,
            "top_packages": [], "by_agent": [],
            "summary":         "Vulnerability states index is empty.",
            "action_required": "Verify wazuh-modulesd vulnerability-scanner is running and indexer connector is active.",
        }
except Exception as e:
    report["wazuh_vulnerabilities"] = {
        "status": "unknown", "last_checked": now,
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "unknown_or_unclassified": 0, "severity_total_reconciled": False,
        "top_packages": [], "by_agent": [], "error": str(e),
        "summary": "Vulnerability data unavailable due to query error.",
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
