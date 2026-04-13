# Next Steps & Roadmap

## Completed — April 2026

- [x] ~~**10.20 node_exporter DOWN**~~ — Fixed: Docker container restarted, Prometheus target updated to Docker DNS
- [x] ~~**VPS metrics stale since March 22**~~ — Fixed: SSH known_hosts refreshed, collection resumed
- [x] ~~**5.131 node_exporter unreachable**~~ — Fixed: UFW rule broadened to allow 192.168.10.0/24 on port 9100
- [x] ~~**SSH sessions not detected on 10.20**~~ — Fixed: switched from `who` to `w -h -i` with full username resolution
- [x] ~~**Duplicate dashboard views (race condition)**~~ — Fixed: removed cron jobs, duplicate generators, added systemd ordering
- [x] ~~**Grafana dashboards**~~ — 10 dashboards deployed covering entire infrastructure
- [x] ~~**Prometheus alerting rules**~~ — 30 rules across blackbox, infrastructure, containers, akvorado
- [x] ~~**Prometheus recording rules**~~ — 19 rules in recording.rules.yml
- [x] ~~**Alertmanager**~~ — Deployed with webhook receiver
- [x] ~~**Prometheus retention**~~ — Set to 90 days
- [x] ~~**Router metrics (192.168.10.1)**~~ — SNMP exporter + blackbox probes + syslog to Wazuh
- [x] ~~**Wazuh SIEM integration**~~ — 6 agents, custom rules/decoders, auditd, FIM, active response, vuln detection
- [x] ~~**10.24 fathom-vault**~~ — Brought online with node-exporter, sys_sample, sys_topproc, Wazuh agent 007
- [x] ~~**Docker container monitoring**~~ — cAdvisor deployed for per-container metrics
- [x] ~~**Google Workspace integration**~~ — Login/admin/drive events, storage enforcement, shared drives
- [x] ~~**Akvorado integration**~~ — 3 scrape targets, alerts, Wazuh bridge, Grafana dashboard
- [x] ~~**JSON report generator**~~ — generate-report.py, auto-refreshed every 5min
- [x] ~~**Disk cleanup**~~ — Removed 53K+ .bak files, freed 3 GB
- [x] ~~**VM Backup Monitoring**~~ — vmbackup-prom.sh on Unraid, Prometheus alerts, Grafana dashboard, Fleet Overview integration
- [x] ~~**Fathom-vaultserver incident investigation**~~ — Documented data loss, deployed prevention monitoring
- [x] ~~**Fathom-server VM recovery**~~ — Restored from backup XML, reinstalled all monitoring from scratch
- [x] ~~**Wazuh manager recovery**~~ — Reinstalled after accidental agent conflict, restored all custom rules/decoders

---

## Immediate Priority

- [ ] **Configure Alertmanager email/Slack notifications**
  - Currently webhook-only; need email or Slack receiver for team visibility
  - Define routing rules for severity-based notification

- [ ] **Git commit all changes**
  - Stage and commit all configuration, scripts, rules, and documentation updates

- [ ] **Consider splitting workloads — wazuh-server at 87% memory**
  - 192.168.10.20 running Wazuh Manager + Prometheus + Grafana + Alertmanager + cAdvisor + all collectors
  - Evaluate moving Grafana/Prometheus to a dedicated VM or offloading to fathom-vault

- [ ] **Verify fathom-vaultserver next weekly backup is healthy**
  - Next backup: Saturday April 19, 2:05 AM
  - Expect backup size > 5 GB (currently 6.4 MB = empty disk)
  - Monitor via Grafana VM Backups dashboard

- [ ] **Prevent accidental wazuh-agent install on manager**
  - Add apt pin or hold to prevent `wazuh-agent` from being installed on 192.168.10.20
  - `sudo apt-mark hold wazuh-agent` on wazuh-server

---

## Short Term — Security Hardening

- [ ] **Install auditd on remote agents**
  - Targets: vm-devops (004), unraid-tower (005), movement-strategy (006), fathom-vault (007)
  - Replicate the 20+ rule set from wazuh-server

- [ ] **Incident response runbook**
  - Document response procedures for each alert type
  - Include escalation paths and remediation steps

- [ ] **MITRE ATT&CK mapping across all rules**
  - Map Wazuh custom rules (100300-100508) to ATT&CK techniques
  - Map auditd rules to ATT&CK techniques
  - Document coverage gaps

---

## Medium Term — Reliability & Coverage

- [ ] **Timer failure alerting** — add `OnFailure=` systemd unit for HTML generation services
- [ ] **Dashboard authentication** — basic auth or mTLS on :8088
- [ ] **Automated backup of `/opt/monitoring/` to Unraid NAS**

---

## Backlog — Nice to Have

- [ ] Per-host historical RSS/CPU sparklines in dashboard
- [ ] Centralize ADMIN_IPS into a shared config file instead of per-script
- [ ] VPS node_exporter direct scrape (open firewall or continue SSH-pull only)
