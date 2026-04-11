# Next Steps & Roadmap

## Immediate — Data Quality

- [x] ~~**10.20 node_exporter DOWN**~~ — Fixed: Docker container restarted, Prometheus target updated to Docker DNS
- [x] ~~**VPS metrics stale since March 22**~~ — Fixed: SSH known_hosts refreshed, collection resumed
- [x] ~~**5.131 node_exporter unreachable**~~ — Fixed: UFW rule broadened to allow 192.168.10.0/24 on port 9100
- [x] ~~**SSH sessions not detected on 10.20**~~ — Fixed: switched from `who` to `w -h -i` with full username resolution
- [x] ~~**Duplicate dashboard views (race condition)**~~ — Fixed: removed cron jobs, duplicate generators, added systemd ordering

- [ ] **10.24 VM currently down**
  - fathom-vault-server is offline; revisit when VM is brought back up
  - Known issues: filesystem root showing 100%, disk I/O showing zero rates

- [ ] **10.20 disk at 90%+ usage**
  - Root filesystem on wazuh-server approaching capacity
  - Investigate: Docker images/volumes, log retention, Prometheus TSDB size

- [ ] **VPS node_exporter DOWN (31.170.165.94:9100)**
  - Direct scrape still failing; SSH-pull method works
  - Options: open firewall rule for Prometheus IP, or continue with SSH-pull only

- [ ] **sys_sample.prom on 10.20 requires root to regenerate**
  - Script writes state files to /run/ which needs root
  - Currently runs via systemd timer as root; manual runs need sudo

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

- [ ] **Alertmanager -> Wazuh webhook**
  - Configure Alertmanager `receivers` with webhook pointing to Wazuh active response endpoint

### Phase 2: Log Shipping

- [ ] **Filebeat on wazuh-server** — ship pipeline logs and systemd service failures to Wazuh
- [ ] **Wazuh custom decoder** — decode Prometheus alert JSON fields
- [ ] **Wazuh custom rule set** — map alert names to Wazuh rule IDs (100100-100199)

### Phase 3: SIEM Correlation

- [ ] **SSH anomaly correlation** — alert on SSH from unexpected IPs
- [ ] **Process spike events** — alert on unapproved processes in top CPU
- [ ] **Node availability SLA** — track uptime percentage per host

---

## Medium Term — Coverage & Retention

- [ ] **Router metrics (192.168.10.1)** — add SNMP exporter or SSH-based interface stats
- [ ] **Grafana dashboards** — historical trend views for sys_sample_* over 30 days
- [ ] **Prometheus retention policy** — set `--storage.tsdb.retention.time=30d`
- [ ] **Timer failure alerting** — add `OnFailure=` systemd unit for HTML generation services

---

## Backlog — Nice to Have

- [ ] Per-host historical RSS/CPU sparklines in dashboard
- [ ] Docker container health status per container (not just count)
- [ ] Dashboard authentication (basic auth or mTLS on :8088)
- [ ] Automated backup of `/opt/monitoring/` to Unraid NAS
- [ ] Centralize ADMIN_IPS into a shared config file instead of per-script
