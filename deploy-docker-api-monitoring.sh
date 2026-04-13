#!/usr/bin/env bash
set -euo pipefail

echo "=== Step 1: Add container & API alert rules ==="
cat > /opt/monitoring/rules/containers.rules.yml << 'RULES'
groups:
- name: containers
  rules:

  - alert: ContainerDown
    expr: absent(container_last_seen{name!=""}) or (time() - container_last_seen{name!=""}) > 120
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Container {{ $labels.name }} not seen for 2+ minutes"

  - alert: ContainerHighCPU
    expr: rate(container_cpu_usage_seconds_total{name!=""}[5m]) * 100 > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Container {{ $labels.name }} CPU at {{ $value | printf \"%.1f\" }}%"

  - alert: ContainerHighMemory
    expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!=""}) * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Container {{ $labels.name }} memory at {{ $value | printf \"%.1f\" }}% of limit"

  - alert: ContainerRestarting
    expr: increase(container_start_time_seconds{name!=""}[15m]) > 1
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: "Container {{ $labels.name }} restarted"

  - alert: APIEndpointDown
    expr: probe_success{job="bb_api_health"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "API endpoint {{ $labels.instance }} is DOWN"

  - alert: APISlowResponse
    expr: probe_duration_seconds{job="bb_api_health"} > 5
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "API {{ $labels.instance }} responding slowly ({{ $value | printf \"%.1f\" }}s)"

- name: container_recording
  interval: 30s
  rules:
  - record: container:cpu_usage_percent:rate5m
    expr: rate(container_cpu_usage_seconds_total{name!=""}[5m]) * 100

  - record: container:memory_usage_mb
    expr: container_memory_usage_bytes{name!=""} / 1024 / 1024

  - record: container:network_rx_bytes_rate:5m
    expr: rate(container_network_receive_bytes_total{name!=""}[5m])

  - record: container:network_tx_bytes_rate:5m
    expr: rate(container_network_transmit_bytes_total{name!=""}[5m])
RULES

echo "  Created containers.rules.yml"

echo ""
echo "=== Step 2: Start cAdvisor + restart Prometheus ==="
cd /opt/monitoring
docker compose up -d cadvisor prometheus 2>&1

echo ""
echo "=== Step 3: Verify ==="
sleep 3

echo "  cAdvisor:"
docker ps --filter name=cadvisor --format "  {{.Names}} — {{.Status}}"

echo "  Prometheus targets:"
curl -s 'http://127.0.0.1:9090/api/v1/targets' 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
for t in d['data']['activeTargets']:
    j=t['labels'].get('job','')
    if j in ('cadvisor','bb_api_health'):
        print(f'    {j:20s} {t[\"labels\"].get(\"instance\",\"\"):50s} {t[\"health\"]}')
" 2>/dev/null

echo ""
echo "=== Done ==="
echo "  cAdvisor running on :8080 (internal)"
echo "  Container metrics: container_cpu_*, container_memory_*, container_network_*"
echo "  API probes: Grafana, Prometheus, Alertmanager, cAdvisor, Akvorado"
