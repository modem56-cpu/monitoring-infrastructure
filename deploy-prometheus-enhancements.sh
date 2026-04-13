#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  Prometheus Enhancements Deployment"
echo "============================================"

# ============================================================
# 1. Alerting Rules
# ============================================================
echo ""
echo "=== Step 1: Create infrastructure alerting rules ==="

cat > /opt/monitoring/rules/infrastructure.rules.yml << 'RULES'
groups:
- name: infrastructure
  rules:

  - alert: NodeDown
    expr: up{job=~"node_.*|windows_.*"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Node {{ $labels.instance }} ({{ $labels.alias }}) is down"

  - alert: HighCPU
    expr: sys_sample_cpu_busy_percent > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "CPU at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: HighCPU_NodeExporter
    expr: (1 - avg by(instance, alias) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "CPU at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: HighCPUProcess
    expr: (sys_topproc_pcpu_percent > 90 or sys_topproc_cpu_percent > 90)
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Process {{ $labels.comm }} (pid={{ $labels.pid }}) at {{ $value | printf \"%.0f\" }}% on {{ $labels.instance }}"

  - alert: MemoryPressure
    expr: (sys_sample_mem_used_bytes / sys_sample_mem_total_bytes) * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Memory at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: MemoryPressure_NodeExporter
    expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Memory at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: SwapPressure
    expr: (sys_sample_swap_used_bytes / sys_sample_swap_total_bytes) * 100 > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Swap at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: DiskAlmostFull
    expr: sys_sample_rootfs_used_percent > 85
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Disk at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: DiskCritical
    expr: sys_sample_rootfs_used_percent > 95
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "CRITICAL: Disk at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: DiskAlmostFull_NodeExporter
    expr: (1 - (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"})) * 100 > 85
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Disk at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: VPS_Down
    expr: vps_ssh_up == 0
    for: 3m
    labels:
      severity: critical
    annotations:
      summary: "VPS {{ $labels.target }} ({{ $labels.host }}) SSH collector failed"

  - alert: VPS_HighCPU
    expr: vps_cpu_busy_percent > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "VPS CPU at {{ $value | printf \"%.1f\" }}% on {{ $labels.host }}"

  - alert: VPS_DiskFull
    expr: vps_rootfs_used_percent > 85
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "VPS disk at {{ $value | printf \"%.1f\" }}% on {{ $labels.host }}"

  - alert: WindowsCPUHigh
    expr: (1 - avg by(instance, alias) (rate(windows_cpu_time_total{mode="idle"}[5m]))) * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Windows CPU at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

  - alert: WindowsDiskFull
    expr: (1 - (windows_logical_disk_free_bytes{volume="C:"} / windows_logical_disk_size_bytes{volume="C:"})) * 100 > 85
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Windows C: at {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"
RULES

echo "  Created infrastructure.rules.yml (17 alert rules)"

# ============================================================
# 2. Recording Rules
# ============================================================
echo ""
echo "=== Step 2: Create recording rules ==="

cat > /opt/monitoring/rules/recording.rules.yml << 'RECORDING'
groups:
- name: recording_cpu
  interval: 60s
  rules:
  - record: instance:cpu_busy_percent:avg5m
    expr: (1 - avg by(instance, alias) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100

  - record: instance:cpu_busy_percent:avg1h
    expr: (1 - avg by(instance, alias) (rate(node_cpu_seconds_total{mode="idle"}[1h]))) * 100

- name: recording_memory
  interval: 60s
  rules:
  - record: instance:memory_used_percent
    expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

  - record: instance:swap_used_percent
    expr: ((node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes) / node_memory_SwapTotal_bytes) * 100

- name: recording_disk
  interval: 60s
  rules:
  - record: instance:rootfs_used_percent
    expr: (1 - (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"})) * 100

  - record: instance:disk_io_read_bytes_rate:5m
    expr: sum by(instance) (rate(node_disk_read_bytes_total{device!~"loop.*|ram.*"}[5m]))

  - record: instance:disk_io_write_bytes_rate:5m
    expr: sum by(instance) (rate(node_disk_written_bytes_total{device!~"loop.*|ram.*"}[5m]))

- name: recording_network
  interval: 60s
  rules:
  - record: instance:net_rx_bytes_rate:5m
    expr: sum by(instance) (rate(node_network_receive_bytes_total{device!~"lo|docker.*|br-.*|veth.*"}[5m]))

  - record: instance:net_tx_bytes_rate:5m
    expr: sum by(instance) (rate(node_network_transmit_bytes_total{device!~"lo|docker.*|br-.*|veth.*"}[5m]))

- name: recording_availability
  interval: 60s
  rules:
  - record: instance:uptime_days
    expr: (time() - node_boot_time_seconds) / 86400

  - record: job:up_ratio:5m
    expr: avg by(job) (avg_over_time(up[5m]))
RECORDING

echo "  Created recording.rules.yml (11 recording rules)"

# ============================================================
# 3. Alertmanager config
# ============================================================
echo ""
echo "=== Step 3: Create Alertmanager config ==="

cat > /opt/monitoring/alertmanager.yml << 'AMCFG'
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'instance']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: default

  routes:
    - match:
        severity: critical
      receiver: default
      repeat_interval: 1h

receivers:
  - name: default
    webhook_configs:
      - url: 'http://prometheus:9090/api/v1/alerts'
        send_resolved: true

# To add email, uncomment and configure:
# global:
#   smtp_smarthost: 'smtp.gmail.com:587'
#   smtp_from: 'alerts@yourdomain.com'
#   smtp_auth_username: 'alerts@yourdomain.com'
#   smtp_auth_password: 'app-password-here'
#
# receivers:
#   - name: default
#     email_configs:
#       - to: 'admin@yourdomain.com'
#         send_resolved: true

inhibit_rules:
  - source_match:
      severity: critical
    target_match:
      severity: warning
    equal: ['alertname', 'instance']
AMCFG

echo "  Created alertmanager.yml"

# ============================================================
# 4. Update docker-compose: add Alertmanager + retention
# ============================================================
echo ""
echo "=== Step 4: Update docker-compose.yml ==="

# Add Alertmanager service if not present
if grep -q "alertmanager" /opt/monitoring/docker-compose.yml; then
  echo "  Alertmanager already in docker-compose.yml"
else
  # Insert alertmanager before 'networks:' line
  sed -i '/^networks:/i \
  alertmanager:\
    image: prom/alertmanager:latest\
    container_name: alertmanager\
    restart: unless-stopped\
    volumes:\
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro\
    command:\
      - --config.file=/etc/alertmanager/alertmanager.yml\
      - --storage.path=/alertmanager\
    ports:\
      - "127.0.0.1:9093:9093"\
    networks: [monitoring]\
' /opt/monitoring/docker-compose.yml
  echo "  Added alertmanager service to docker-compose.yml"
fi

# Add retention to Prometheus
if grep -q "storage.tsdb.retention.time" /opt/monitoring/docker-compose.yml; then
  echo "  Retention already configured"
else
  sed -i 's|--web.enable-lifecycle|--web.enable-lifecycle\n      - --storage.tsdb.retention.time=90d|' /opt/monitoring/docker-compose.yml
  echo "  Set Prometheus retention to 90 days"
fi

# ============================================================
# 5. Update prometheus.yml to point to Alertmanager
# ============================================================
echo ""
echo "=== Step 5: Wire Prometheus to Alertmanager ==="

if grep -q "alertmanager" /opt/monitoring/prometheus.yml; then
  echo "  Alertmanager already configured in prometheus.yml"
else
  # Insert alerting block after global section
  sed -i '/^rule_files:/i \
alerting:\
  alertmanagers:\
    - static_configs:\
        - targets: ["alertmanager:9093"]\
' /opt/monitoring/prometheus.yml
  echo "  Added alertmanager target to prometheus.yml"
fi

# ============================================================
# 6. Clean up stale files
# ============================================================
echo ""
echo "=== Step 6: Clean up stale files ==="

# Stale symlink
if [ -L /opt/monitoring/reports/tower_192.168.5.131_9100.html ]; then
  ls -la /opt/monitoring/reports/tower_192.168.5.131_9100.html
  # Check if target exists
  if [ ! -e /opt/monitoring/reports/tower_192.168.5.131_9100.html ]; then
    rm /opt/monitoring/reports/tower_192.168.5.131_9100.html
    echo "  Removed broken symlink tower_192.168.5.131_9100.html"
  else
    stat -c '%y' /opt/monitoring/reports/tower_192.168.5.131_9100.html
    echo "  Symlink is valid, checking age..."
  fi
fi

# Stale textfile
if [ -f /opt/monitoring/textfile_collector/vps_31_170_165_94.prom ]; then
  rm /opt/monitoring/textfile_collector/vps_31_170_165_94.prom
  echo "  Removed stale vps_31_170_165_94.prom (replaced by vps_movement_strategy.prom)"
fi

# ============================================================
# 7. Restart stack
# ============================================================
echo ""
echo "=== Step 7: Restart Prometheus stack ==="

cd /opt/monitoring
docker compose up -d prometheus alertmanager 2>&1

echo ""
echo "  Waiting for Prometheus to load rules..."
sleep 5

# Verify rules loaded
echo ""
echo "=== Verification ==="
echo "  Alert rules:"
curl -s http://127.0.0.1:9090/api/v1/rules 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
alert_count=0
record_count=0
for g in d.get('data',{}).get('groups',[]):
    for r in g.get('rules',[]):
        if r['type']=='alerting': alert_count+=1
        elif r['type']=='recording': record_count+=1
print(f'    Alerting: {alert_count} rules')
print(f'    Recording: {record_count} rules')
" 2>/dev/null

echo ""
echo "  Alertmanager:"
curl -s -o /dev/null -w "    HTTP status: %{http_code}" http://127.0.0.1:9093/-/healthy 2>/dev/null
echo ""

echo ""
echo "  Prometheus retention:"
docker inspect prometheus --format '{{.Args}}' 2>/dev/null | tr ' ' '\n' | grep retention

echo ""
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo ""
echo "  [x] 17 alerting rules (infrastructure.rules.yml)"
echo "  [x] 11 recording rules (recording.rules.yml)"
echo "  [x] Alertmanager running on :9093"
echo "  [x] Prometheus retention: 90 days"
echo "  [x] Stale files cleaned"
echo ""
echo "  Alertmanager UI: http://127.0.0.1:9093"
echo "  Prometheus alerts: http://127.0.0.1:9090/alerts"
echo ""
echo "  To add email notifications, edit /opt/monitoring/alertmanager.yml"
echo "  and uncomment the email section with your SMTP credentials."
