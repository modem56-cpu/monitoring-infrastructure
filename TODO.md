# Next Steps & Roadmap — April 26, 2026

## Completed — Full History

### Infrastructure Foundation (February 2026)
- [x] Prometheus + Grafana + node_exporter stack
- [x] SSH session tracking, sys_sample, sys_topproc textfile collectors
- [x] HTML auto-generated dashboards on :8088
- [x] git repository initialized

### April 2026 Hardening Pass
- [x] node-exporter down 4 weeks → fixed (Docker DNS target)
- [x] VPS metrics stale since March 22 → fixed (SSH known_hosts refreshed)
- [x] 5.131 node_exporter unreachable → fixed (UFW broadened)
- [x] SSH sessions not detected on 10.20 → fixed (w -h -i)
- [x] Duplicate dashboard views (race condition) → fixed (systemd ordering)
- [x] Prometheus retention extended to 90 days
- [x] 30 alerting + 19 recording rules deployed
- [x] Alertmanager deployed (webhook receiver)

### Platform Expansion (April 12-15, 2026)
- [x] Wazuh SIEM: 6 agents, auditd, FIM, active response, vuln detection, SCA
- [x] Grafana: 11 dashboards covering all infrastructure
- [x] Google Workspace v1 + v2: login/admin/drive events, storage, group-based extshare
- [x] Akvorado: flow pipeline monitoring, 12-panel dashboard, Wazuh bridge
- [x] cAdvisor: per-container Docker monitoring
- [x] UDM Pro: SNMP + blackbox + syslog → Wazuh custom rules 100400-100407
- [x] fathom-vault (10.24): full monitoring + Wazuh agent 007
- [x] VM Backup Monitoring: vmbackup-prom.sh on Unraid, alerts, Grafana dashboard
- [x] JSON report generator: auto-refreshed every 5min
- [x] Disk cleanup: removed 53K+ .bak files, freed 3 GB
- [x] UDM ARP Collector v1: SNMP + OUI + rDNS → Prometheus + Akvorado enrichment
- [x] Akvorado device enrichment live: SrcNetName/Tenant/Role from ARP data

### April 16-18, 2026 — OOM + Stability
- [x] Wazuh Indexer OOM resolved → heap capped at -Xms1g -Xmx1g
- [x] Wazuh manager recovered after accidental agent install conflict
- [x] Google Workspace storage % fixed (personal + shared drive = true total)
- [x] Shared drive page cap removed (was truncating Yokly USA at 50k files)
- [x] monitoring-report.timer enabled (5-min JSON regeneration)
- [x] ContainerDown false positive fixed (max() over restartcount variants)
- [x] ZAP heap capped: 1985m → 384m, Docker limit 700m
- [x] Kafka UI heap capped: auto → 256m, Docker limit 512m
- [x] Swap expanded: 4 GB → 8 GB (/swap2.img, persisted in /etc/fstab)

### April 18, 2026 — Network Inventory
- [x] ARP collector v2: MAC-centric state, hostname overrides, Wazuh JSON export, audit metrics
- [x] device_names.json: 26 static hostname overrides deployed
- [x] Network inventory baseline sealed: 80 MACs (90 ARP entries, 4 VLANs)
- [x] Wazuh decoder + rules 100700-100707: new_device, arp_conflict, dhcp_ip_changed
- [x] Prometheus alert rules: NetworkNewDeviceDetected, NetworkARPConflict, NetworkARPCollectorStale
- [x] Grafana "Network Inventory & Audit" dashboard (UID: network-inventory)
- [x] Network inventory HTML report at :8088/network_inventory.html

### April 26, 2026 — Wazuh-Grafana, SOC Dashboard, Platform Hardening
- [x] Wazuh Indexer wired into Grafana as Elasticsearch datasource (172.18.0.1:9200)
- [x] iptables rule: Docker subnet (172.18.0.0/16) → host port 9200 (added via fix-grafana-wazuh-indexer.sh)
- [x] Security Operations Center dashboard — merged Alert CC + Wazuh Security Events (32 panels, 8 rows)
- [x] Export Reports dashboard at /d/export-reports (24 panels, CSV/JSON export enabled)
- [x] Removed 2 duplicate dashboards (Alert Command Center, Wazuh Security Events)
- [x] All 14 dashboards exported to /opt/monitoring/dashboards/
- [x] prom-to-wazuh.sh expanded from 7 to 14 checks (GWorkspace, employee reconcile, network)
- [x] Alertmanager.yml rewritten — Gmail SMTP replaces broken webhook receiver
- [x] Employee authorized_admins.json defined (5 admins; deploy pending root run)
- [x] 6 historical Wazuh Indexer events updated (csednie.regasa/josh/markangel rule.level 12→3)
- [x] generate-report.py wazuh_agents fixed — reads from Wazuh Indexer, 6 agents returning
- [x] PLATFORM_REVIEW.md created (7.5/10, P1–P4 gap analysis)
- [x] RESTORATION_GUIDE.md created (15 sections, full restore-from-scratch procedure)

---

## CRITICAL — Resolve Immediately (This Week)

- [ ] **Run `sudo bash /opt/monitoring/fix-p3-root.sh`**
  - Deploys: authorized_admins.json → /opt/monitoring/data/, updated reconcile script, iptables-persistent, logrotate configs, employees-sheet-sync.timer, Prometheus alert rules (Unraid array/disk + HostDisk), Prometheus reload
  - Must be run as root; script is idempotent

- [ ] **Set Gmail app password in alertmanager.yml**
  - Edit `/opt/monitoring/alertmanager.yml`, replace `REPLACE_WITH_GMAIL_APP_PASSWORD` with real app password
  - Then: `docker restart alertmanager`
  - Without this, no alert emails will be delivered

- [ ] **Git commit all changes** ← OVERDUE (3+ weeks behind)
  - Stage: ARP collector v2, device_names.json, deploy scripts, akvorado config, docker-compose.override.yml, ClickHouse server.xml, SOC dashboard, export-reports dashboard, alertmanager.yml, generate-report.py, prom-to-wazuh.sh, all fix scripts, all doc updates
  - `cd /opt/monitoring && git add -A && git commit -m "..."`

- [ ] **apt-mark hold wazuh-agent on wazuh-server**
  - `sudo apt-mark hold wazuh-agent`
  - Prevents recurrence of April 13 incident (agent install wiped manager package)

---

## HIGH PRIORITY — Deliver Within 30 Days

- [ ] **Alertmanager email delivery — activate after app password set**
  - Gmail SMTP is configured in alertmanager.yml; just needs app password + container restart
  - Test: `amtool alert add --alertmanager.url=http://localhost:9093 test-alert severity=critical`

- [ ] **Install Wazuh agents on remaining endpoints**
  - Targets: Unraid Tower (10.10), VM DevOps (5.131), fathom-vault (10.24), Windows VM (1.253)
  - **NEVER install wazuh-agent on the wazuh-server itself** (critical April 13 incident)
  - Verify with: `sudo /var/ossec/bin/agent_control -l`

- [ ] **Investigate duplicate MAC: 52:54:00:ad:42:13**
  - Appears at both 192.168.10.24 (fathom-vault) AND 192.168.10.25 (fathom-vault-2)
  - Same VLAN (SecurityApps) — either cloned VM without MAC regeneration or DHCP stale entry
  - If two VMs have identical MAC → ARP conflict alerts will fire; resolve by regenerating MAC on one VM

- [ ] **Google Workspace extshare policy decision**
  - 58 users currently unrestricted for external sharing (data loss / IP leakage risk)
  - Options: add to restrictive groups (hrou/itdevou/marketingou/trainingou) or document as accepted risk
  - IT/leadership decision required

- [ ] **Name the 62 unnamed network devices**
  - Edit /opt/monitoring/device_names.json with IP → hostname mappings
  - Changes take effect within 5 minutes (next ARP cycle)
  - Improves: Akvorado flow labels, Wazuh alerts, HTML inventory, Grafana tables

---

## SHORT TERM — Deliver Within 60 Days

- [ ] **auditd on all remote Wazuh agents**
  - Targets: vm-devops (001), unraid-tower (002), movement-strategy (003), fathom-vault (005)
  - Replicate 20+ rule set from wazuh-server: identity, SSH keys, priv-esc, root cmds, cron, systemd, Docker, WireGuard, kernel modules

- [ ] **Wazuh FIM fix for unraid-tower (agent 002)**
  - Agent registered with Docker bridge IP 172.17.0.2 instead of 192.168.10.10
  - Re-enroll with correct IP or enable `use_source_ip` in ossec.conf

- [ ] **Incident response runbooks**
  - One runbook per alert category: NodeDown, SwapPressure, ContainerDown, ARP conflict, new device on SecurityApps, GWorkspace ExtShare spike
  - Map Wazuh rules 100300-100707 to MITRE ATT&CK techniques
  - Store in /opt/monitoring/runbooks/

- [ ] **Grafana ClickHouse datasource + device traffic panels**
  - Add ClickHouse datasource (URL: http://clickhouse:8123, DB: default)
  - Panels: top talkers by SrcNetName, VLAN traffic breakdown, per-device bandwidth history
  - Currently requires Akvorado console; Grafana gives time-series alerting capability

---

## MEDIUM TERM — Deliver Within 90 Days

- [ ] **RAM upgrade or workload migration**
  - Current: 7.8 GB RAM, swap 4.4/8.0 GB (55%) — tight but stable
  - Recommended: +8 GB RAM (brings to 16 GB, all working sets fit in RAM)
  - Alternative: migrate Prometheus+Grafana to fathom-vault (10.24)
  - Trigger: if swap exceeds 80% sustained → escalate

- [ ] **ClickHouse system log TTL maintenance**
  - Monthly: check system log table sizes, truncate if > 10 GB
  - Long-term: reduce metric_log + trace_log TTL from 30 to 7 days in server.xml
  - Command: `docker exec akvorado-clickhouse-1 clickhouse-client --query "SELECT table, formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE database='system' GROUP BY table ORDER BY sum(bytes_on_disk) DESC"`

- [ ] **Dashboard authentication on :8088**
  - HTML reports served unauthenticated on LAN
  - Add nginx reverse proxy with basic auth or restrict to known IPs

- [ ] **Automated backup of /opt/monitoring/ to Unraid NAS**
  - Daily rsync or nightly git push
  - Covers all config, scripts, rules, and documentation

- [ ] **Timer failure alerting**
  - Add OnFailure= systemd unit for HTML generation and ARP collector services
  - Alert if udm-arp-collector fails (Akvorado enrichment goes stale)

---

## BACKLOG — Nice to Have

- [ ] Per-device bandwidth alerts (device > X Mbps sustained for Y minutes)
- [ ] VLAN traffic baseline anomaly detection (Prometheus recording rules)
- [ ] VPS node_exporter direct scrape (currently SSH-pull only)
- [ ] Centralize ADMIN_IPS into shared config file across all patch scripts
- [ ] Per-host historical RSS/CPU sparklines in HTML dashboards
- [ ] Grafana alerts on Akvorado flow enrichment staleness
- [ ] Wazuh SOAR integration (automated response playbooks)
- [ ] MITRE ATT&CK mapping for all custom Wazuh rules
- [ ] Compliance framework mapping (CIS/NIST for leadership reporting)
- [ ] Secrets management (SSH keys currently in scripts — move to vault or environment)
