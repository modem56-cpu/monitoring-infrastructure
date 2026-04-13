#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  Akvorado Integration Deployment"
echo "============================================"

echo ""
echo "=== Step 1: Add Akvorado Prometheus scrape targets ==="

# Check if already added
if grep -q "akvorado_inlet" /opt/monitoring/prometheus.yml 2>/dev/null; then
  echo "  Already configured, skipping."
else
  cat >> /opt/monitoring/prometheus.yml << 'PROM'

  # --- Akvorado Metrics ---
  - job_name: akvorado_inlet
    scrape_interval: 30s
    metrics_path: /api/v0/inlet/metrics
    static_configs:
      - targets: ['akvorado-akvorado-inlet-1:8080']
        labels: { component: 'inlet' }

  - job_name: akvorado_outlet
    scrape_interval: 30s
    metrics_path: /api/v0/outlet/metrics
    static_configs:
      - targets: ['akvorado-akvorado-outlet-1:8080']
        labels: { component: 'outlet' }

  - job_name: akvorado_orchestrator
    scrape_interval: 60s
    metrics_path: /api/v0/orchestrator/metrics
    static_configs:
      - targets: ['akvorado-akvorado-orchestrator-1:8080']
        labels: { component: 'orchestrator' }
PROM
  echo "  Added 3 Akvorado scrape targets"
fi

echo ""
echo "=== Step 2: Add Akvorado alert rules ==="

cat > /opt/monitoring/rules/akvorado.rules.yml << 'RULES'
groups:
- name: akvorado
  rules:

  - alert: AkvoradoInletDown
    expr: up{job="akvorado_inlet"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Akvorado Inlet is DOWN — no flow data being collected"

  - alert: AkvoradoOutletDown
    expr: up{job="akvorado_outlet"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Akvorado Outlet is DOWN — flow data not being processed"

  - alert: AkvoradoNoFlows
    expr: rate(akvorado_inlet_flow_input_udp_packets_total[5m]) == 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Akvorado Inlet receiving no flow packets for 5+ minutes"

  - alert: AkvoradoFlowErrors
    expr: rate(akvorado_inlet_flow_input_udp_errors_total[5m]) > 0
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "Akvorado Inlet flow input errors: {{ $value | printf \"%.1f\" }}/s"

  - alert: AkvoradoKafkaLag
    expr: akvorado_outlet_kafka_consumergroup_lag_messages > 10000
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Akvorado Kafka consumer lag: {{ $value | printf \"%.0f\" }} messages behind"

  - alert: AkvoradoClickHouseSlow
    expr: histogram_quantile(0.95, rate(akvorado_outlet_clickhouse_insert_time_seconds_bucket[5m])) > 5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Akvorado ClickHouse inserts slow: p95 = {{ $value | printf \"%.1f\" }}s"

- name: akvorado_recording
  interval: 30s
  rules:
  - record: akvorado:flow_packets_rate:5m
    expr: rate(akvorado_inlet_flow_input_udp_packets_total[5m])

  - record: akvorado:flow_bytes_rate:5m
    expr: rate(akvorado_inlet_flow_input_udp_bytes_total[5m])

  - record: akvorado:flows_processed_rate:5m
    expr: rate(akvorado_outlet_core_received_flows_total[5m])

  - record: akvorado:kafka_messages_rate:5m
    expr: rate(akvorado_inlet_kafka_sent_messages_total[5m])
RULES

echo "  Created akvorado.rules.yml (6 alerts + 4 recording rules)"

echo ""
echo "=== Step 3: Add Akvorado events to Wazuh bridge ==="

# Add akvorado checks to prom-to-wazuh.sh
if grep -q "akvorado" /usr/local/bin/prom-to-wazuh.sh 2>/dev/null; then
  echo "  Akvorado already in Wazuh bridge"
else
  cat >> /usr/local/bin/prom-to-wazuh.sh << 'BRIDGE'

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
BRIDGE
  echo "  Added Akvorado checks to Wazuh bridge"
fi

echo ""
echo "=== Step 4: Restart Prometheus ==="
cd /opt/monitoring
docker restart prometheus 2>&1

echo ""
echo "=== Done ==="
echo "  Prometheus: 3 new scrape targets (inlet, outlet, orchestrator)"
echo "  Alerts: AkvoradoInletDown, OutletDown, NoFlows, FlowErrors, KafkaLag, ClickHouseSlow"
echo "  Recording: flow packet/byte rates, processed flows, kafka throughput"
echo "  Wazuh: AkvoradoDown + AkvoradoNoFlows bridge events"
