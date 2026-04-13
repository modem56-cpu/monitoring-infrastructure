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
