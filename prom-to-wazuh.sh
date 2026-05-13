#!/usr/bin/env bash
set -euo pipefail
#
# prom-to-wazuh.sh — Query Prometheus, write structured JSON log events
# for Wazuh logcollector to ingest.
#
# Runs every 60s via systemd timer. Each run produces one JSON line per
# check per instance. Wazuh decodes these with prometheus_alert decoder
# and evaluates them against prometheus_monitoring rules.
#

PROM="${PROM_URL:-http://127.0.0.1:9090}"
LOGFILE="${LOGFILE:-/var/log/prometheus-wazuh.log}"

# Ensure log file exists and is writable
touch "$LOGFILE" 2>/dev/null || true

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

query() {
  local q="$1"
  curl -sf --max-time 5 "${PROM}/api/v1/query" --data-urlencode "query=${q}" 2>/dev/null || echo '{"data":{"result":[]}}'
}

emit() {
  # $1=alertname $2=instance $3=alias $4=severity $5=value $6=summary
  printf '{"timestamp":"%s","source":"prometheus","alertname":"%s","instance":"%s","alias":"%s","severity":"%s","value":"%s","summary":"%s"}\n' \
    "$ts" "$1" "$2" "$3" "$4" "$5" "$6" >> "$LOGFILE"
}

# ============================================================
# 1. Node Down (up == 0)
# ============================================================
query 'up{job=~"node_.*|windows_.*"} == 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    inst = m.get('instance','')
    alias = m.get('alias','')
    job = m.get('job','')
    print(f'{inst}|{alias}|{job}')
" 2>/dev/null | while IFS='|' read -r inst alias job; do
  emit "NodeDown" "$inst" "$alias" "critical" "0" "Node $inst ($alias) is down"
done

# ============================================================
# 2. High CPU (sys_sample_cpu_busy_percent > 90)
# ============================================================
query 'sys_sample_cpu_busy_percent > 90' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    inst = m.get('instance','')
    alias = m.get('alias','')
    val = r['value'][1]
    print(f'{inst}|{alias}|{val}')
" 2>/dev/null | while IFS='|' read -r inst alias val; do
  emit "HighCPU" "$inst" "$alias" "warning" "$val" "CPU at ${val}% on $inst ($alias)"
done

# ============================================================
# 3. High Memory (> 90%)
# ============================================================
query '(sys_sample_mem_used_bytes / sys_sample_mem_total_bytes) * 100 > 90' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    inst = m.get('instance','')
    alias = m.get('alias','')
    val = r['value'][1]
    print(f'{inst}|{alias}|{val}')
" 2>/dev/null | while IFS='|' read -r inst alias val; do
  emit "MemoryPressure" "$inst" "$alias" "warning" "$val" "Memory at ${val}% on $inst ($alias)"
done

# ============================================================
# 4. Disk Almost Full (rootfs > 90%)
# ============================================================
query 'sys_sample_rootfs_used_percent > 90' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    inst = m.get('instance','')
    alias = m.get('alias','')
    val = r['value'][1]
    print(f'{inst}|{alias}|{val}')
" 2>/dev/null | while IFS='|' read -r inst alias val; do
  emit "DiskAlmostFull" "$inst" "$alias" "critical" "$val" "Disk at ${val}% on $inst ($alias)"
done

# ============================================================
# 5. High CPU Process (any single process > 90% CPU)
# ============================================================
query 'sys_topproc_pcpu_percent > 90 or sys_topproc_cpu_percent > 90' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    inst = m.get('instance','')
    alias = m.get('alias','')
    cmd = m.get('comm','') or m.get('cmd','')
    pid = m.get('pid','')
    user = m.get('user','') or m.get('name','')
    val = r['value'][1]
    print(f'{inst}|{alias}|{val}|{cmd}|{pid}|{user}')
" 2>/dev/null | while IFS='|' read -r inst alias val cmd pid user; do
  emit "HighCPUProcess" "$inst" "$alias" "warning" "$val" "Process $cmd (pid=$pid user=$user) at ${val}% CPU on $inst"
done

# ============================================================
# 6. SSH Sessions (audit log — all active sessions)
# ============================================================
query 'tower_ssh_sessions_user_src > 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    target = m.get('target','')
    user = m.get('user','')
    src = m.get('src','')
    val = r['value'][1]
    print(f'{target}|{user}|{src}|{val}')
" 2>/dev/null | while IFS='|' read -r target user src val; do
  emit "SSHSession" "${target}:22" "$user" "info" "$val" "SSH session: user=$user src=$src target=$target count=$val"
done

# ============================================================
# 7. Swap pressure (> 80%)
# ============================================================
query '(sys_sample_swap_used_bytes / sys_sample_swap_total_bytes) * 100 > 80' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    inst = m.get('instance','')
    alias = m.get('alias','')
    val = r['value'][1]
    print(f'{inst}|{alias}|{val}')
" 2>/dev/null | while IFS='|' read -r inst alias val; do
  emit "SwapPressure" "$inst" "$alias" "warning" "$val" "Swap at ${val}% on $inst ($alias)"
done

# ============================================================
# 8. Akvorado flow pipeline health
# ============================================================
query 'up{job=~"akvorado_.*"} == 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    job = m.get('job','')
    comp = m.get('component','')
    print(f'{job}|{comp}')
" 2>/dev/null | while IFS='|' read -r job comp; do
  emit "AkvoradoDown" "192.168.10.20:8082" "$comp" "critical" "0" "Akvorado $comp is down (job=$job)"
done

# Check for flow pipeline stall
no_flows=$(query 'rate(akvorado_inlet_flow_input_udp_packets_total[5m]) == 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
r = data.get('data',{}).get('result',[])
print(len(r))
" 2>/dev/null)
if [ "${no_flows:-0}" -gt 0 ]; then
  emit "AkvoradoNoFlows" "192.168.10.20:8082" "inlet" "warning" "0" "Akvorado inlet receiving no flow packets"
fi

# ============================================================
# 10. GWorkspace — External Sharing Unrestricted
# ============================================================
query 'gworkspace_extshare_unrestricted_users > 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    val = r['value'][1]
    print(f'{val}')
" 2>/dev/null | while IFS='|' read -r val; do
  emit "GWorkspaceExternalShare" "192.168.10.20:9100" "wazuh-server" "info" "$val" "GWorkspace: ${val} user(s) in unrestricted external sharing OU (known baseline — OU migration incomplete)"
done

# ============================================================
# 11. GWorkspace — Shared Drive Rapid Growth (>5 GB in 1h)
# ============================================================
query 'increase(gworkspace_shared_drive_size_bytes[1h]) / 1073741824 > 5' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    drive = m.get('drive','unknown')
    val = float(r['value'][1])
    print(f'{drive}|{val:.1f}')
" 2>/dev/null | while IFS='|' read -r drive val; do
  emit "GWorkspaceDriveGrowth" "192.168.10.20:9100" "wazuh-server" "warning" "$val" "Shared drive '${drive}' grew ${val} GB in the last hour — possible bulk upload"
done

# ============================================================
# 12. Employee Reconciliation — Orphaned GW Accounts
# ============================================================
query 'employee_reconcile_orphaned_accounts > 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    val = r['value'][1]
    print(f'{val}')
" 2>/dev/null | while read -r val; do
  emit "EmployeeOrphanedAccounts" "192.168.10.20:9100" "wazuh-server" "warning" "$val" "Employee reconcile: ${val} GW accounts have no employee roster match"
done

# ============================================================
# 13. Employee Reconciliation — Unauthorized Admin
# ============================================================
query 'employee_reconcile_admin_unregistered > 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    val = r['value'][1]
    print(f'{val}')
" 2>/dev/null | while read -r val; do
  emit "EmployeeUnauthorizedAdmin" "192.168.10.20:9100" "wazuh-server" "critical" "$val" "Employee reconcile: ${val} unauthorized GW admin accounts detected"
done

# ============================================================
# 14. Network — New Device Detected (only when baseline is set)
# ============================================================
query 'network_inventory_discovered_total > 0 and network_inventory_baseline_total > 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    val = r['value'][1]
    print(f'{val}')
" 2>/dev/null | while read -r val; do
  emit "NetworkNewDevice" "192.168.10.20:9100" "wazuh-server" "warning" "$val" "Network inventory: ${val} new/unknown device(s) detected on LAN since baseline"
done

# ============================================================
# 15. Network — ARP Conflict (last 24h, threshold >3 for DHCP churn)
# ============================================================
query 'network_inventory_arp_conflicts_last_24h > 3' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    val = r['value'][1]
    print(f'{val}')
" 2>/dev/null | while read -r val; do
  emit "NetworkARPConflict" "192.168.10.20:9100" "wazuh-server" "critical" "$val" "Network inventory: ${val} ARP conflicts in last 24h — possible MAC spoofing"
done

# ============================================================
# 14. Akvorado — Kafka Consumer Lag (>10k messages)
# ============================================================
query 'akvorado_outlet_kafka_consumergroup_lag_messages > 10000' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    comp = m.get('component','outlet')
    val = int(float(r['value'][1]))
    print(f'{comp}|{val}')
" 2>/dev/null | while IFS='|' read -r comp val; do
  emit "AkvoradoKafkaLag" "192.168.10.20:8082" "$comp" "warning" "$val" "Akvorado Kafka consumer lag: ${val} messages behind — flow data may be delayed"
done

# ============================================================
# 15. GWorkspace — User Over 50GB Quota
# ============================================================
query 'gworkspace_drive_users_over_quota > 0' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    val = r['value'][1]
    print(f'{val}')
" 2>/dev/null | while read -r val; do
  emit "GWorkspaceOverQuota" "192.168.10.20:9100" "wazuh-server" "warning" "$val" "GWorkspace: ${val} non-exempt user(s) over 50GB storage quota"
done

# ============================================================
# 16. Unraid Array Usage (> 90%)
# ============================================================
query 'tower_unraid_array_used_percent > 90' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('data',{}).get('result',[]):
    m = r['metric']
    target = m.get('target','')
    val = r['value'][1]
    print(f'{target}|{val}')
" 2>/dev/null | while IFS='|' read -r target val; do
  emit "UnraidArrayFull" "$target" "unraid" "critical" "$val" "Unraid array at ${val}% capacity on ${target}"
done
