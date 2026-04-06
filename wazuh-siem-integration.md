# Wazuh SIEM Integration Plan

## Overview

Integrate the Prometheus monitoring platform with Wazuh SIEM to enable:
- Automated alerting on infrastructure anomalies
- Audit trail for SSH sessions and process activity
- Correlation of monitoring events with security events
- Leadership-level dashboards for compliance and incident response

---

## Data Sources Available for Ingestion

| Source | Metric/Log | SIEM Value |
|--------|-----------|------------|
| `tower_ssh_sessions_user_src` | Active SSH sessions per user/IP | Detect unauthorized access, lateral movement |
| `sys_topproc_cpu_percent` | Top processes by CPU | Detect crypto miners, runaway processes |
| `sys_sample_*` | System health snapshot | Detect resource exhaustion attacks |
| `up == 0` | Node down | Infrastructure availability SLA |
| `patch_reports_final.sh` stdout | Pipeline logs | Operational audit trail |
| Alertmanager webhook | Structured alerts | Centralized incident management |

---

## Implementation Steps

### Step 1: Prometheus Alerting Rules

Create `/etc/prometheus/rules/infrastructure.yml`:

```yaml
groups:
  - name: infrastructure
    rules:

      - alert: NodeDown
        expr: up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Node {{ $labels.instance }} is down"

      - alert: HighCPUProcess
        expr: sys_topproc_cpu_percent > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU process on {{ $labels.instance }}: {{ $labels.comm }}"

      - alert: DiskAlmostFull
        expr: sys_sample_rootfs_used_percent > 90
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Disk > 90% on {{ $labels.instance }}"

      - alert: MemoryPressure
        expr: (sys_sample_mem_used_bytes / sys_sample_mem_total_bytes) > 0.90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Memory > 90% on {{ $labels.instance }}"

      - alert: SSHSessionAnomaly
        expr: tower_ssh_sessions_user_src > 0
        labels:
          severity: info
        annotations:
          summary: "SSH session: user={{ $labels.user }} src={{ $labels.src }} target={{ $labels.target }}"
```

### Step 2: Alertmanager Configuration

Install: `apt install prometheus-alertmanager`

`/etc/prometheus/alertmanager.yml`:

```yaml
route:
  group_by: ['alertname', 'instance']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 1h
  receiver: wazuh-webhook

receivers:
  - name: wazuh-webhook
    webhook_configs:
      - url: 'http://127.0.0.1:55000/active-response/run'
        send_resolved: true
```

### Step 3: Wazuh Custom Decoder

`/var/ossec/etc/decoders/prometheus_alerts.xml`:

```xml
<decoder name="prometheus_alert">
  <prematch>{"status":"firing"</prematch>
  <regex>"alertname":"(\w+)".*"instance":"([^"]+)".*"severity":"(\w+)"</regex>
  <order>alert_name, instance, severity</order>
</decoder>
```

### Step 4: Wazuh Custom Rules

`/var/ossec/etc/rules/prometheus_monitoring.xml`:

```xml
<group name="prometheus_monitoring">

  <rule id="100100" level="3">
    <decoded_as>prometheus_alert</decoded_as>
    <description>Prometheus alert: $(alert_name) on $(instance)</description>
  </rule>

  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <field name="alert_name">NodeDown</field>
    <description>CRITICAL: Node down - $(instance)</description>
  </rule>

  <rule id="100102" level="8">
    <if_sid>100100</if_sid>
    <field name="alert_name">HighCPUProcess</field>
    <description>WARNING: High CPU process on $(instance)</description>
  </rule>

  <rule id="100103" level="10">
    <if_sid>100100</if_sid>
    <field name="alert_name">DiskAlmostFull</field>
    <description>CRITICAL: Disk full threshold reached on $(instance)</description>
  </rule>

  <rule id="100104" level="7">
    <if_sid>100100</if_sid>
    <field name="alert_name">SSHSessionAnomaly</field>
    <description>INFO: SSH session detected - $(instance)</description>
  </rule>

</group>
```

### Step 5: Filebeat for Log Shipping

`/etc/filebeat/inputs.d/monitoring.yml`:

```yaml
- type: log
  paths:
    - /var/log/monitoring-pipeline.log
  fields:
    log_type: prometheus_pipeline
  fields_under_root: true

- type: journald
  units:
    - prom-html-dashboards.service
    - prom-refresh-html.service
  fields:
    log_type: monitoring_systemd
```

---

## Event Flow Diagram

```
Prometheus TSDB
     │
     │ evaluate rules every 15s
     ▼
Alertmanager
     │ group + deduplicate
     │ POST JSON webhook
     ▼
Wazuh Active Response / Filebeat input
     │
     │ decode fields
     ▼
Wazuh Manager
     ├─ prometheus_alert decoder
     └─ prometheus_monitoring rules
          │
          ▼
     Wazuh Dashboard (OpenSearch)
          ├─ Alert: NodeDown        → level 12 → escalate
          ├─ Alert: DiskAlmostFull  → level 10 → notify ops
          ├─ Alert: HighCPUProcess  → level 8  → investigate
          ├─ Alert: MemoryPressure  → level 7  → watch
          └─ Alert: SSHSession      → level 3  → audit log
```

---

## Audit Use Cases

| Use Case | Data Source | Wazuh Rule |
|----------|-------------|-----------|
| Who logged in via SSH | tower_ssh_sessions_user_src | 100104 |
| Unexpected process running | sys_topproc_cpu_percent | 100102 |
| Server went offline | up == 0 | 100101 |
| Disk approaching capacity | sys_sample_rootfs_used_percent | 100103 |
| Memory exhaustion risk | sys_sample_mem_used / total | 100103 |
| VPS metrics collection failure | pipeline log (patch_reports_final.sh stderr) | filebeat → custom rule |
