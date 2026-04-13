# Accomplishment Report — Leadership Summary

**Project:** On-Premise Infrastructure Monitoring Platform  
**Platform:** Prometheus + Grafana + Wazuh SIEM + Custom Collectors  
**Hub:** 192.168.10.20 (wazuh-server)  
**Repository:** https://github.com/modem56-cpu/monitoring-infrastructure  
**Delivered:** February 2026 — Hardened & Stabilized April 2026  

---

## Executive Summary

Designed, deployed, and stabilized a fully on-premise infrastructure monitoring platform covering 7 endpoints plus a UDM Pro gateway across Linux VMs, Windows, NAS/hypervisor, a remote VPS, and network infrastructure. The platform provides real-time visibility into system health, resource utilization, active user sessions, process activity, network flows, and Google Workspace — all accessible via Grafana dashboards and a lightweight web dashboard with no cloud dependency and no additional licensing cost.

In April 2026, a comprehensive hardening pass resolved 15+ operational issues including a 4-week node-exporter outage, stale VPS metrics collection, firewall misconfigurations, duplicate dashboard rendering, and SSH session detection failures — restoring full monitoring coverage across all endpoints. This was followed by a major expansion adding Wazuh SIEM integration, Grafana visualization, Alertmanager, Google Workspace monitoring, Akvorado flow analytics, UDM Pro instrumentation, and a JSON report generator.

---

## Key Deliverables

### 1. Unified Multi-Host Dashboard
- Single HTTP dashboard at `http://192.168.10.20:8088` covering all managed hosts
- 10 Grafana dashboards at `http://192.168.10.20:3000` providing deep-dive historical views
- Auto-refreshes every 3 minutes via systemd timers with race-condition-free ordering
- Consistent single-view rendering — eliminated duplicate/conflicting HTML generators
- No authentication required on internal network (appropriate for internal SOC use)

### 2. Per-Host Metrics Collected
| Metric Category | Details |
|-----------------|---------|
| CPU utilization | % busy, per-core via node_exporter |
| Memory & Swap | Total / used / cached / swap % (swap suppressed when N/A) |
| Disk I/O | Read/write rates (B/s) and lifetime totals |
| Network I/O | Current throughput + lifetime RX/TX totals + avg Mbps since boot |
| Filesystem | Root partition % used + Unraid mount points |
| Process table | Top 15 by CPU, top 15 by RSS — with username, PID, command name |
| Active SSH sessions | Live table: user, source IP, session count per host — admin IPs tagged |
| Docker containers | Running/total count + per-container metrics via cAdvisor |

### 3. Specialized Host Monitoring
- **Unraid NAS (10.10):** Array utilization (77.7%), per-disk device table with temperatures/SMART/utilization, cache pool and system cache usage, parity validity, WireGuard VPN peer status (active/stale/never), SMB share sessions and configured users, VM count
- **Windows endpoint (1.253):** CPU, memory, commit charge, network, filesystem C:, SSH/SMB session tables, top processes by CPU and RSS
- **VPS (31.170.165.94):** Full system metrics pulled securely via SSH over WireGuard VPN (10.253.2.22) using a dedicated `metrics` user with forced command — no inbound firewall rule changes required on VPS
- **Wazuh SIEM server (10.20):** Self-monitoring with Docker container inventory (16 services tracked), sys_sample system health card
- **fathom-vault (10.24):** node-exporter + sys_sample + sys_topproc, Wazuh agent 007
- **UDM Pro (10.1):** SNMP interface metrics (if_mib), blackbox probes (ICMP/TCP/HTTP), syslog ingestion into Wazuh with custom firewall decoder/rules

### 4. Infrastructure Hardening — April 11, 2026

#### Critical Fixes
| Issue | Impact | Root Cause | Resolution |
|-------|--------|------------|------------|
| node-exporter down for 4 weeks | 10.20 showing Up: 0, no metrics | Docker container crashed; native apt package conflicting on port 9100 | Disabled native service, restarted Docker container |
| Prometheus unable to scrape local host | All textfile metrics (sys_sample, tower_unraid, vps) absent from TSDB | Prometheus in Docker couldn't reach host IP 192.168.10.20; scrape target misconfigured | Changed target to Docker DNS `node-exporter:9100` with relabel |
| VPS metrics stale since March 22 | Dashboard showing 20-day-old data | SSH host key changed on VPS; `StrictHostKeyChecking=yes` caused silent auth hang | Refreshed known_hosts; cleaned ~9,000 orphaned temp files |
| vm-devops (5.131) unreachable | Up: 0, all metrics blank | UFW on 5.131 only allowed port 9100 from specific IP; Docker NAT traffic came from subnet | Broadened UFW rule to 192.168.10.0/24 |
| SSH sessions not detected on 10.20 | SSH table always empty | `who` command returns empty (utmp not written for current sessions) | Switched to `w -h -i` with full username resolution via `/etc/passwd` |

#### Duplicate View Elimination
| Problem | Cause | Fix |
|---------|-------|-----|
| Two/three alternating HTML views per host | Root crontab regenerating base HTML every minute | Removed crontab entries |
| 10.10 emoji-format view appearing | `prom_tower_html.sh` called from `prom_topproc_generate_all.sh` | Removed call; deleted obsolete script |
| 10.10 base HTML overwritten by refresh service | `prom_refresh_all_html.sh` regenerating tower_10.10 and tower_10.24 | Removed duplicate generation lines |
| Windows old-format view appearing | `prom_windows_html_192_168_1_253.sh` in `update_all_dashboards.sh` | Removed call; deleted obsolete script |
| Patches applied then overwritten | No ordering between two systemd timer services | Added `After=prom-html-dashboards.service` drop-in |
| `tower-dashboard.service` regenerating 10.10 | Obsolete standalone service still installed | Removed service and drop-in directory |

#### SSH Session Detection Fixes
| Issue | Resolution |
|-------|------------|
| 5.131 showing local console sessions (tty2, login screen) | Added remote-only filter (IP regex) to `tower_textfile_extras.sh` |
| 5.131 double-quoted Prometheus label values | Fixed `esc()` call — removed escaped quotes around variables |
| 10.10 had no SSH/sys_sample extras patch | Created `patch_reports_unraid_10_10_extras.sh` and added to patch chain |
| Windows SSH table format inconsistent with Linux | Updated `prom_win_html` to use same table format with "No remote SSH sessions detected" |
| Admin sessions cluttering SSH tables | Added `ADMIN_IPS` filter with `(admin)` tag across all extras scripts |

#### Additional Fixes
| Issue | Resolution |
|-------|------------|
| `sys-sample-prom.sh` couldn't detect Docker textfile mount | Added `/textfile_collector` to mount path detection |
| Unraid "(More parity/array/cache... parsing is fixed)" visible | Replaced with invisible HTML comment placeholder |
| Unraid device table missing after removing old generator | Rebuilt in `patch_reports_unraid.sh` with full device status/temp/SMART/utilization table |
| Swap showing "0 B of 0 B (— %)" on hosts with no swap | Suppressed swap line when total = 0 |
| "sys_sample metrics seen: —" on 10.10 | Suppressed when metric unavailable |
| Script permissions lost after edits | Created `/tmp/fix_all_perms.sh` master permission script |

### 5. Major Platform Expansion — April 12-13, 2026

1. **Fixed node-exporter crash and created sys-sample timer** — Resolved recurring node-exporter instability and established the sys-sample-prom systemd timer for reliable 15s metric collection
2. **Deployed WireGuard VPN + Wazuh agent on movement-strategy (31.170.165.94)** — Established wg2 tunnel (10.253.2.22, endpoint vpn.yoklyu.gives:51822), deployed Wazuh agent 006, SSH collector now routes over VPN
3. **Built Prometheus-to-Wazuh bridge (7 alert types, custom rules 100300-100307)** — prom-to-wazuh.sh runs every 60s, forwarding Prometheus alert state into Wazuh SIEM with custom decoder and rule set
4. **Deployed security enhancements (auditd, FIM, active response, vulnerability detection)** — auditd with 20+ rules on wazuh-server covering identity, SSH keys, privilege escalation, root commands, cron, systemd, Docker, WireGuard, and kernel modules; FIM on critical paths; firewall-drop active response on SSH brute force (rule 5763, 1hr block); vulnerability detection with 60m feed updates; SCA with CIS benchmarks
5. **Upgraded Prometheus: 30 alert rules, 19 recording rules, Alertmanager, 90-day retention** — Alert rules across blackbox.rules.yml, infrastructure.rules.yml, containers.rules.yml, akvorado.rules.yml; recording rules in recording.rules.yml; Alertmanager with webhook receiver; retention extended to 90 days with admin API enabled
6. **Integrated UDM Pro: SNMP metrics, syslog-to-Wazuh with custom decoder/rules, blackbox fix** — SNMP exporter scraping if_mib for all interfaces; blackbox probes (ICMP, TCP, HTTP with http_2xx_selfsigned); syslog ingestion on UDP 514; custom decoder udm_firewall.xml and rules 100400-100407
7. **Integrated Akvorado: 3 scrape targets, alerts, Wazuh bridge, Grafana dashboard** — Inlet, outlet, orchestrator scrape targets; 6 alert rules + 4 recording rules; akvorado-mesh-to-wazuh bridge (AkvoradoDown, AkvoradoNoFlows); 12-panel Grafana dashboard
8. **Integrated Google Workspace: login/admin/drive events, 50GB storage enforcement, org storage, shared drives** — Service account gam-project@gam-project-gf5mq.iam.gserviceaccount.com; gworkspace-collector timer (5min); login events, admin actions, drive events, external sharing, security alerts; 50GB storage enforcement with exemptions; org storage tracking (~2.84 TB / 3.67 TB, 77%); 28 shared drives scanned; custom Wazuh rules 100500-100508
9. **Deployed cAdvisor for per-container Docker monitoring + API health probes** — Per-container CPU, memory, network, I/O metrics; API health probes integrated into Docker Containers & APIs dashboard
10. **Built 10 Grafana dashboards covering entire infrastructure** — Fleet Overview, Node Exporter Full (31 panels), Windows Exporter (22 panels), Movement Strategy VPS, UDM Pro, Docker Containers & APIs, Akvorado Flow Pipeline (12 panels), Google Workspace, HTML Reports Hub, Export Reports
11. **Created JSON report generator for AI-powered analysis** — generate-report.py exports full platform state as JSON; auto-refreshes every 5min at http://192.168.10.20:8088/monitoring_report.json; covers node status, system metrics, top processes, network I/O, Docker, API health, UDM Pro, Akvorado, Google Workspace, SSH sessions, Wazuh agents
12. **Brought fathom-vault (10.24) online: node-exporter, sys_sample, sys_topproc, Wazuh agent** — Full monitoring coverage with agent 007, sys_sample + sys_topproc textfile collectors
13. **Disk cleanup: removed 53K+ .bak files, freed 3 GB** — Reclaimed storage on wazuh-server
14. **Fixed 24 firing alerts (ContainerHighMemory false positive, APIEndpointDown, NodeDown)** — Resolved false positives and actual issues to bring alert count to clean state
15. **Deployed VM Backup Monitoring on Unraid** — Custom vmbackup-prom.sh script monitors all VM backups via Prometheus textfile collector. Tracks backup age, disk size, XML/NVRAM presence, VM definition status. Alerts on: stale backups (>8 days), suspiciously small backups (<50MB), VMs with no backup, VMs removed from libvirt. Grafana dashboard + Wazuh rules + Fleet Overview integration.
16. **Investigated and documented fathom-vaultserver data loss incident** — Discovered VM disk was blank since March 4, 2026. All backups from March 15–April 5 captured empty disk (6.4 MB). Root cause: disk replaced with empty sparse placeholder before backup cycle. No bash_history evidence of who/when. Documented incident timeline, recovery steps attempted, and prevention measures deployed.
17. **Recovered fathom-vaultserver VM after accidental removal** — VM was accidentally undefined from Unraid during cleanup. Restored from backup XML + NVRAM, verified disk integrity, restarted VM. Reinstalled all monitoring (node-exporter, Wazuh agent, sys_sample, sys_topproc, SSH session collector) from scratch.
18. **Restored Wazuh manager after accidental agent install conflict** — Installing wazuh-agent on the manager host removed wazuh-manager package. Reinstalled manager, restored all custom rules (prometheus, UDM, Google Workspace, vmbackup), decoders, logcollector entries, and shared agent config. Agents re-registered with new IDs.

### 6. Version Control & Documentation
- Initialized git repository at `/opt/monitoring/`
- Connected to GitHub: `https://github.com/modem56-cpu/monitoring-infrastructure`
- Pushed all configuration files, scripts, rules, and targets
- Created `.gitignore` excluding sensitive files (SSH keys), runtime data (logs, reports, textfile_collector), and backup files
- Updated all documentation: README, ARCHITECTURE, WORKFLOW, SCRIPTS, TODO, ACCOMPLISHMENTS

---

## Platform Architecture (Summary)

```
Endpoints            →  Prometheus TSDB  →  Grafana (11 dashboards)
  + node_exporter         (Docker, 15s      + HTML Generator → HTTP :8088
  + windows_exporter       scrape, 90d      + JSON Report → :8088/monitoring_report.json
  + SSH pull (VPS)         retention)
  + SNMP (UDM Pro)                      →  Alertmanager → Webhook
  + cAdvisor                            →  prom-to-wazuh → Wazuh SIEM
  + Google Workspace
  + Akvorado                            →  Wazuh (6 agents, auditd, FIM,
  + VM Backup Monitor                       active response, vuln detection)
  + Custom textfile
    collectors
```

- **Zero cloud dependency** — all components run on `192.168.10.20`
- **Zero licensing cost** — Prometheus, Grafana, Wazuh, node_exporter, windows_exporter all OSS
- **Dockerized core** — Prometheus, Grafana, Alertmanager, node-exporter, blackbox, SNMP, cAdvisor in Docker Compose
- **Idempotent patching** — HTML comment markers ensure safe re-runs with no duplication
- **Sequential generation** — systemd ordering prevents race conditions between timers
- **Graceful degradation** — `|| true` on all patch steps; one script failure does not break others
- **Admin visibility** — SSH sessions from known admin IPs tagged rather than hidden
- **Defense in depth** — Prometheus alerts + Wazuh SIEM + auditd + FIM + active response + vulnerability detection

---

## Metrics at a Glance (Current — April 13, 2026)

| Stat | Value |
|------|-------|
| Hosts monitored | 7 active + UDM Pro gateway |
| Wazuh agents | 6 (000-005: wazuh-server, ubuntu-5.131, unraid-10.10, movement-strategy, devops-1.253, fathom-server) |
| Prometheus scrape targets | 23 (all UP) |
| Prometheus alerting rules | 36 (incl. 6 vmbackup rules) |
| Prometheus recording rules | 19 |
| Grafana dashboards | 11 (incl. VM Backups) |
| Systemd timers | 10 |
| Dashboard refresh interval | 3 minutes |
| Prometheus retention | 90 days |
| Dashboard consistency | Single view per host (race conditions eliminated) |
| SSH session tracking | Live per user/IP, admin-tagged, all 7 hosts |
| Unique metric series | ~18 sys_sample + ~100 sys_topproc per host |
| Unraid device monitoring | 7 active devices with temp/SMART/utilization |
| Unraid VM backup monitoring | 4 VMs tracked: age, size, health, definition status |
| VPS collection method | SSH forced command over WireGuard VPN, 30s timeout |
| UDM Pro monitoring | SNMP + blackbox + syslog to Wazuh |
| Google Workspace | Login/admin/drive events, 28 shared drives, 50GB enforcement → Wazuh |
| Akvorado | 3 scrape targets, 6 alert rules, 12-panel dashboard |
| VM backup monitoring | Hourly check: backup age, size, health, missing VMs |
| JSON report | Auto-refreshed every 5min for AI analysis |
| Git repository | github.com/modem56-cpu/monitoring-infrastructure |
| Automated since | February 2026 (hardened & expanded April 2026) |

## Incident Log

### Fathom-vaultserver Data Loss — March–April 2026
- **Impact:** Complete loss of fathom-vaultserver OS and application data
- **Root cause:** VM disk replaced with empty 200GB sparse placeholder on March 4, 2026. Cause unknown — no evidence in bash_history or logs.
- **Detection gap:** Backups ran weekly but faithfully backed up the empty disk (6.4 MB compressed). No monitoring existed to flag suspiciously small backups.
- **Resolution:** Rebuilt as standalone VM at 192.168.10.24 with full monitoring. Deployed vmbackup-prom.sh on Unraid to prevent recurrence.
- **Prevention:** Backup size monitoring now alerts on any VM backup under 50 MB. Dashboard shows backup health at a glance in Fleet Overview.
