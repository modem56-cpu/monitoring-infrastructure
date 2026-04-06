# Next Steps & Roadmap

## Immediate — Data Quality

- [ ] **10.24 Filesystem Root showing 100%**
  - Verify disk is not actually full on fathom-vault-server
  - node_exporter on 10.24 only exposes `/tmp` (tmpfs) in filesystem metrics — no `/` mountpoint
  - Fix: add `--collector.filesystem.mount-points-exclude` config to node_exporter on 10.24 to ensure `/` is included
  - Or: update sys-sample-prom.sh on 10.24 to correctly compute rootfs percent

- [ ] **10.24 Disk I/O showing zero rates**
  - sys_sample_disk_read_bps and write_bps both report 0 from textfile collector
  - Verify `/proc/diskstats` is readable and device filter in sys-sample-prom.sh matches `vda`
  - May be genuinely idle; confirm with `iostat -x 1 5` on 10.24

- [ ] **VPS node_exporter DOWN (31.170.165.94:9100)**
  - Direct scrape failing; SSH-pull method works
  - Investigate: firewall blocking 9100, service not running, or not bound to 0.0.0.0
  - Options: open firewall rule for Prometheus IP, or continue with SSH-pull only

---

## Short Term — Wazuh SIEM Integration

### Phase 1: Alert Forwarding

- [ ] **Configure Prometheus Alertmanager**
  - Install and configure `/etc/prometheus/alertmanager.yml`
  - Define alerting rules in `/etc/prometheus/rules/`:
    - `node_down.yml` — up == 0 for any target
    - `high_cpu.yml` — sys_topproc_cpu_percent > 90 for unexpected processes
    - `disk_full.yml` — sys_sample_rootfs_used_percent > 90
    - `ssh_anomaly.yml` — unknown user in tower_ssh_sessions_user_src
    - `memory_pressure.yml` — sys_sample_mem_used_bytes / total > 0.90

- [ ] **Alertmanager → Wazuh webhook**
  - Configure Alertmanager `receivers` with webhook pointing to Wazuh active response endpoint
  - Or: write alerts to a log file, ship via Filebeat to Wazuh

### Phase 2: Log Shipping

- [ ] **Filebeat on wazuh-server**
  - Ship patch_reports_final.sh output (stdout/stderr) to Wazuh
  - Monitor `/var/log/syslog` for systemd service failures
  - Configuration: `/etc/filebeat/filebeat.yml` → Wazuh indexer input

- [ ] **Wazuh custom decoder**
  - Decode Prometheus alert JSON fields: `alertname`, `severity`, `instance`, `value`
  - File: `/var/ossec/etc/decoders/prometheus_alerts.xml`

- [ ] **Wazuh custom rule set**
  - Map alert names to Wazuh rule IDs (100100–100199 range)
  - Severity mapping: Prometheus `critical` → Wazuh level 12, `warning` → level 8
  - File: `/var/ossec/etc/rules/prometheus_monitoring.xml`

### Phase 3: SIEM Correlation

- [ ] **SSH anomaly correlation**
  - Wazuh rule: SSH session from unexpected IP on monitored host → alert
  - Cross-correlate with `tower_ssh_sessions_user_src` metric changes

- [ ] **Process spike events**
  - Alert when a process not in approved whitelist appears in top CPU

- [ ] **Node availability SLA**
  - Track uptime percentage per host in Wazuh dashboard

---

## Wazuh SIEM Integration Architecture

```
Prometheus Alertmanager
        │  POST webhook (JSON)
        ▼
Wazuh Active Response endpoint
  OR
Filebeat → Wazuh indexer input
        │
        ▼
Wazuh Manager
  ├── prometheus_alerts decoder (custom XML)
  └── prometheus_monitoring rules (custom XML)
        │
        ▼
Wazuh Dashboard / OpenSearch
  ├── SSH anomaly events       (rule 100101)
  ├── Process spike events     (rule 100102)
  ├── Disk threshold events    (rule 100103)
  ├── Memory pressure events   (rule 100104)
  └── Node down events         (rule 100105) → escalation
```

---

## Medium Term — Coverage & Retention

- [ ] **Router metrics (192.168.10.1)**
  - Currently: ICMP/TCP blackbox only
  - Add: SNMP exporter or SSH-based interface stats

- [ ] **Grafana dashboards**
  - Historical trend views for all sys_sample_* metrics
  - Long-term CPU/memory/disk trend over 30 days

- [ ] **Prometheus retention policy**
  - Set explicit `--storage.tsdb.retention.time=30d` in Prometheus unit
  - Current default: 15 days

- [ ] **Timer failure alerting**
  - Add `OnFailure=` systemd unit for prom-html-dashboards and prom-refresh-html
  - Alert via email or Wazuh if HTML generation stalls

- [ ] **VPS firewall review**
  - Evaluate opening :9100 from Prometheus IP only (firewall `--source` rule)
  - Reduces SSH overhead for VPS collection

---

## Backlog — Nice to Have

- [ ] Per-host historical RSS/CPU sparklines in dashboard
- [ ] Docker container health status per container (not just count)
- [ ] Alertmanager silence management UI
- [ ] Dashboard authentication (basic auth or mTLS on :8088)
- [ ] Automated backup of `/opt/monitoring/` to Unraid NAS
