# Next Steps & Roadmap

## Completed — April 2026

- [x] ~~**10.20 node_exporter DOWN**~~ — Fixed: Docker container restarted, target updated to Docker DNS
- [x] ~~**VPS metrics stale since March 22**~~ — Fixed: SSH known_hosts refreshed, collection resumed
- [x] ~~**5.131 node_exporter unreachable**~~ — Fixed: UFW rule broadened to allow 192.168.10.0/24 on port 9100
- [x] ~~**SSH sessions not detected on 10.20**~~ — Fixed: switched from `who` to `w -h -i` with full username resolution
- [x] ~~**Duplicate dashboard views (race condition)**~~ — Fixed: removed cron jobs, duplicate generators, added systemd ordering
- [x] ~~**Grafana dashboards**~~ — 10 dashboards deployed covering entire infrastructure
- [x] ~~**Prometheus alerting + recording rules**~~ — 30 alerting + 19 recording rules
- [x] ~~**Alertmanager**~~ — Deployed with webhook receiver
- [x] ~~**Prometheus retention**~~ — 90 days with admin API enabled
- [x] ~~**Router metrics (192.168.10.1)**~~ — SNMP + blackbox probes + syslog to Wazuh
- [x] ~~**Wazuh SIEM integration**~~ — 6 agents, custom rules/decoders, auditd, FIM, active response, vuln detection
- [x] ~~**fathom-vault (10.24)**~~ — Brought online with node-exporter, sys_sample, sys_topproc, Wazuh agent 007
- [x] ~~**Docker container monitoring**~~ — cAdvisor for per-container metrics
- [x] ~~**Google Workspace integration v1**~~ — Login/admin/drive events, storage enforcement, shared drives
- [x] ~~**Google Workspace integration v2**~~ — Group-based extshare, per-user Drive/Gmail/Photos split, org storage totals, Drive API for shared drive sizing
- [x] ~~**Akvorado flow pipeline monitoring**~~ — 3 scrape targets, 6 alert rules, Wazuh bridge, Grafana dashboard
- [x] ~~**JSON report generator**~~ — generate-report.py, auto-refreshed every 5min
- [x] ~~**Disk cleanup**~~ — Removed 53K+ .bak files, freed 3 GB
- [x] ~~**VM Backup Monitoring**~~ — vmbackup-prom.sh on Unraid, alerts, Grafana dashboard
- [x] ~~**Fathom-vaultserver incident investigation**~~ — Documented, prevention monitoring deployed
- [x] ~~**Fathom-server VM recovery**~~ — Restored from backup XML, reinstalled all monitoring
- [x] ~~**Wazuh manager recovery**~~ — Reinstalled after agent package conflict, all rules/decoders restored
- [x] ~~**UDM ARP Collector**~~ — SNMP + OUI + rDNS → Prometheus textfile + Akvorado JSON (94 devices, 4 VLANs)
- [x] ~~**Akvorado per-device network enrichment**~~ — network-sources live; SrcNetName/Tenant/Role populated; UFW fixed; HTTP/1.0 server; ClickHouse OOM crash loop resolved

---

## Immediate Priority

- [ ] **Git commit all changes** ← *overdue*
  - Stage and commit all configuration, scripts, rules, and documentation
  - Includes: ARP collector, json-server, deploy scripts, akvorado config, ClickHouse server.xml, all doc updates

- [ ] **Prevent accidental wazuh-agent install on manager**
  - `sudo apt-mark hold wazuh-agent` on wazuh-server (192.168.10.20)
  - One line; prevents recurrence of April 13 incident

- [ ] **Verify fathom-vaultserver backup is healthy (Saturday April 19, 2:05 AM)**
  - Expect backup size > 5 GB (was 6.4 MB = empty disk)
  - Check: Grafana VM Backups dashboard / Prometheus `vmbackup_size_bytes`

---

## Short Term — Pending Delivery

- [ ] **Alertmanager email/Slack notifications**
  - Currently webhook-only; no team visibility when alerts fire
  - Define routing: critical = page/email, warning = Slack channel
  - Required before platform can be called production-ready

- [ ] **Grafana ClickHouse datasource + device traffic panels**
  - Add ClickHouse datasource (URL: `http://clickhouse:8123`, DB: `default`)
  - Add panels to Akvorado dashboard: top talkers by `SrcNetName`, VLAN traffic breakdown, per-device bandwidth history
  - Currently requires Akvorado console; Grafana would give time-series context and alerting

- [ ] **Wazuh FIM for unraid-tower (agent 005)**
  - Agent registered with Docker bridge IP 172.17.0.2 instead of 192.168.10.10
  - Need re-enrollment with correct IP or `use_source_ip` fix
  - FIM activity exists but only visible when dashboard time range > 24h

- [ ] **auditd on remote agents**
  - Targets: vm-devops (004), unraid-tower (005), movement-strategy (006), fathom-vault (007)
  - Replicate the 20+ rule set deployed on wazuh-server

---

## Medium Term — Reliability & Coverage

- [ ] **ClickHouse system log TTL maintenance**
  - Monthly task: check system log table sizes, truncate if > 10 GB
  - `docker exec akvorado-clickhouse-1 clickhouse-client --query "SELECT table, formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE database='system' GROUP BY table ORDER BY sum(bytes_on_disk) DESC"`
  - Long-term: reduce system log TTL in server.xml from 30 to 7 days for metric_log and trace_log

- [ ] **Memory pressure on wazuh-server (at ~87% RAM)**
  - Running 20+ containers + Wazuh manager on 8 GB
  - Consider: move Grafana/Prometheus to fathom-vault, or add RAM
  - ClickHouse configured at 90% RAM ratio; monitor for OOM events

- [ ] **Timer failure alerting**
  - Add `OnFailure=` systemd unit for HTML generation and ARP collector services
  - Alert if udm-arp-collector fails (Akvorado enrichment goes stale)

- [ ] **Dashboard authentication on :8088**
  - HTML reports served unauthenticated on LAN
  - Add basic auth or restrict to known IPs via nginx reverse proxy

- [ ] **Automated backup of `/opt/monitoring/` to Unraid NAS**
  - Daily rsync or git push to cover all config, scripts, and rules

- [ ] **Incident response runbooks**
  - Document response procedures for each alert category
  - Map Wazuh custom rules (100300–100508) to MITRE ATT&CK techniques

---

## Backlog — Nice to Have

- [ ] Grafana alerts on Akvorado flow enrichment staleness (data_total → 0 = JSON server down)
- [ ] Per-device bandwidth alerts (e.g., device > X Mbps sustained for Y minutes)
- [ ] VLAN traffic baseline anomaly detection (Prometheus recording rules)
- [ ] VPS node_exporter direct scrape (open firewall or continue SSH-pull only)
- [ ] Centralize ADMIN_IPS into a shared config file across all patch scripts
- [ ] Per-host historical RSS/CPU sparklines in HTML dashboards
