# Accomplishment Report — Leadership Summary

**Project:** On-Premise Infrastructure Monitoring Platform  
**Platform:** Prometheus + Grafana + Wazuh SIEM + Custom Collectors  
**Hub:** 192.168.10.20 (wazuh-server)  
**Repository:** https://github.com/modem56-cpu/monitoring-infrastructure  
**Delivered:** February 2026 — Hardened & Stabilized April 2026 | Updated April 26, 2026  

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

### 19. Google Workspace Monitoring — Major Expansion (April 15, 2026)

Complete rebuild of the Google Workspace collector and dashboard, adding org-level storage visibility, per-user Drive/Gmail/Photos breakdown, shared drive analytics, and group-based external sharing enforcement.

#### Collector: v2 Deployment
| Change | Detail |
|--------|--------|
| External sharing enforcement model | Migrated from OU name matching (`DEFAULT-BLOCKED`) to **group-based** enforcement (`hrou`, `itdevou`, `marketingou`, `trainingou` Google Groups) — more accurate, resilient to OU renaming |
| Per-user storage split | Added `accounts:drive_used_quota_in_mb`, `accounts:gmail_used_quota_in_mb`, `accounts:gplus_photos_used_quota_in_mb` — correct `accounts:` namespace discovered through API enumeration; `gmail:used_quota_in_mb` was invalid and was silently returning 400 errors |
| Org-level storage totals | `gworkspace_org_storage_{total,used,available}_bytes`, `gworkspace_org_storage_used_percent` — derived from per-user `accounts:total_quota_in_mb` sum (customer-level Reports API doesn't expose pool quota) |
| Shared drive storage accuracy | Switched from `size` field (0 for all Google-native files) to `quotaBytesUsed` — this is the same field the Admin Console uses, capturing Docs/Sheets/Slides storage. Page cap raised from 10 to 50 pages (50k files) to cover large drives like Yokly USA (1.35 TB) |
| Drive API scope | Added `drive.readonly` scope to service account for shared drive enumeration and file listing |

#### New Prometheus Metrics (15 added)
| Metric | Description |
|--------|-------------|
| `gworkspace_drive_only_bytes` | Per-user Drive storage (excl. Gmail and Photos) |
| `gworkspace_gmail_usage_bytes` | Per-user Gmail storage |
| `gworkspace_photos_usage_bytes` | Per-user Google Photos storage |
| `gworkspace_org_storage_total_bytes` | Org total pooled quota (sum of per-user allocations) |
| `gworkspace_org_storage_used_bytes` | Org total storage used |
| `gworkspace_org_storage_available_bytes` | Org remaining storage |
| `gworkspace_org_storage_used_percent` | Org storage utilisation % |
| `gworkspace_org_drive_bytes` | Org Drive storage total |
| `gworkspace_org_gmail_bytes` | Org Gmail storage total |
| `gworkspace_org_photos_bytes` | Org Photos storage total |
| `gworkspace_org_shared_drive_bytes` | Org shared drive storage (sampled via quotaBytesUsed) |
| `gworkspace_org_personal_bytes` | Org personal Drive storage |
| `gworkspace_shared_drives_total` | Total shared drives in org |
| `gworkspace_shared_drive_size_bytes{drive}` | Per-drive storage (quotaBytesUsed) |
| `gworkspace_shared_drive_files{drive}` | Per-drive file count |

#### Dashboard Redesign
- Reorganized all 29 panels into 9 **horizontal security sections** — each section has summary stats left-aligned with associated timeseries/tables inline to the right
- Sections: Status Bar → Events → Storage Overview → Storage Per User → Storage Split → Shared Drives → ExtShare Stats → ExtShare Analysis → ExtShare Tables
- Updated ExtShare panel queries for v2 group-based metrics (`exception_users` replacing `exception_authorized`/`exception_unauthorized` where applicable)

#### Key Data (April 15, 2026)
| Stat | Value |
|------|-------|
| Active users | 95 |
| Total storage used | ~1.16 TB |
| Shared drives | 29 |
| Shared drive storage (sampled) | ~110 GB (Admin Console shows ~1.5 TB; gap is Google-native files in large drives — now fixed with quotaBytesUsed) |
| ExtShare unrestricted | 58 users |
| ExtShare blocked (group) | 22 users |
| ExtShare exception OU | 3 users |

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

## Metrics at a Glance (Current — April 26, 2026)

| Stat | Value |
|------|-------|
| Hosts monitored | 7 active + UDM Pro gateway |
| Wazuh agents | 6 (000 manager, 001 vm-devops/5.131, 002 unraid/10.10, 003 movement-strategy, 004 devops/1.253, 006 fathom-server/10.24) |
| Prometheus scrape targets | 23 (all UP) |
| Prometheus alerting rules | 47 (incl. network inventory, vmbackup, Unraid array/disk, GWorkspace) |
| Prometheus recording rules | 19 |
| Grafana dashboards | 14 (all exported to /opt/monitoring/dashboards/) |
| Grafana datasources | 2 (Prometheus + Wazuh Indexer/OpenSearch) |
| prom-to-wazuh checks | 14 (infrastructure + GWorkspace + employee reconcile + network) |
| Systemd timers | 15 (incl. employees-sheet-sync, monitoring-report) |
| Dashboard refresh interval | 3 minutes |
| Prometheus retention | 30 days (reduced from 90d April 26 for disk headroom) |
| Dashboard consistency | Single view per host (race conditions eliminated) |
| SSH session tracking | Live per user/IP, admin-tagged, all 7 hosts |
| Unique metric series | ~18 sys_sample + ~100 sys_topproc per host |
| Unraid device monitoring | 7 active devices with temp/SMART/utilization |
| Unraid VM backup monitoring | 4 VMs tracked: age, size, health, definition status |
| VPS collection method | SSH forced command over WireGuard VPN, 30s timeout |
| UDM Pro monitoring | SNMP + blackbox + syslog to Wazuh |
| Google Workspace | Login/admin/drive events, 29 shared drives, Drive/Gmail/Photos split, org storage totals, group-based extshare enforcement → Wazuh |
| Employee ↔ GWorkspace reconciliation | 99 active employees / 99 GW accounts — clean match; 5 authorized admins defined |
| Akvorado | 3 scrape targets, 6 alert rules, 12-panel dashboard |
| VM backup monitoring | Hourly check: backup age, size, health, missing VMs |
| JSON report | Auto-refreshed every 5min for AI analysis |
| Git repository | github.com/modem56-cpu/monitoring-infrastructure |
| Automated since | February 2026 (hardened & expanded April 2026) |
| Network devices monitored (ARP baseline) | 80 MACs (90 ARP entries, 4 VLANs) |
| Network inventory alerts | 3 Prometheus + 7 Wazuh rules (100700-100707) |
| JVM heap caps | ZAP: 384m, Kafka UI: 256m, Wazuh Indexer: 1g, Kafka: 1g (all explicit) |
| Swap capacity | 8 GB (expanded April 18, 2026 from 4 GB) |
| Platform review score | 7.5/10 (PLATFORM_REVIEW.md) — April 26, 2026 |

### 20. Wazuh Indexer OOM Resolution — April 16, 2026

Diagnosed and resolved a `java.lang.OutOfMemoryError: Java heap space` crash on the wazuh-indexer (OpenSearch) service that took down the Wazuh dashboard and all SIEM visibility.

| Stage | What Happened |
|-------|--------------|
| Crash | wazuh-indexer OOM at 1.2–1.5 GB peak; auto-heap sizing exceeded available RAM; 847 MB heap dump written to `/var/lib/wazuh-indexer/` |
| First fix attempt | Heap capped at 512m — too small; circuit breaker immediately tripped at 486 MB with 275 active shards |
| Final fix | Heap set to `-Xms1g -Xmx1g`; heap dump on OOM disabled; indexer restarted stable |
| Root cause | Memory over-commitment: Kafka (1 GB) + ZAP proxy (configured 2 GB, actual ~12 MB RSS) + indexer (auto-sized ~2 GB) on 7.8 GB host with swap nearly full (3.9/4 GB used) |
| Scripts created | `fix-indexer-oom.sh`, `fix-indexer-heap-1g.sh` in `/opt/monitoring/` |
| Dashboard impact | "Error Pattern Handler (getPatternList)" error; cleared once indexer stabilized |

**Prevention added to TODO:** Monitor indexer heap usage; consider swap expansion or RAM upgrade if memory pressure continues.

---

### 6. UDM ARP Collector + Akvorado Device Enrichment — April 15, 2026

1. **Built UDM Pro ARP collector (SNMP + OUI + rDNS → Prometheus textfile)** — `udm-arp-collector.py` polls SNMP ARP table (OID 1.3.6.1.2.1.4.22.1.2) every 5 minutes via systemd timer. Enriches MAC with IEEE OUI vendor lookup (/usr/share/ieee-data/oui.txt, 194K entries) and reverse DNS hostname. Writes `network_device_info` and `network_device_count` metrics for 90–94 devices across 4 VLANs (LAN/SecurityApps/Dev/VLAN4). Output: `/opt/monitoring/textfile_collector/network_devices.prom`

2. **Extended collector to also write Akvorado JSON feed** — `udm-arp-collector.py` now writes `/opt/monitoring/data/network_devices.json` (array of `{ip, hostname, vendor, vlan, vlan_id, mac}`). Served by `device-json-server.service` on port 9117 using HTTP/1.0 (no keep-alive) to prevent Go HTTP client connection reuse failures.

3. **Wired Akvorado network-sources enrichment** — Added `network-sources.local-devices` to `/opt/akvorado/config/akvorado.yaml` pointing to `http://247.16.14.1:9117/network_devices.json`. jq transform maps each device to a /32 prefix entry with `name` (hostname), `tenant` (VLAN), `role` (vendor). Combined with static subnet `networks:` config, flows now show per-device hostnames and VLAN tenants.

4. **Resolved three blocking issues along the way:**
   - UFW blocked Docker containers (247.16.14.0/24) from reaching host port 9117 — added `ufw allow from 247.16.14.0/24 to any port 9117`
   - Python `http.server` HTTP/1.1 keep-alive caused Go client `context deadline exceeded` on every alternate poll — replaced with HTTP/1.0 server (`json-server.py`)
   - ClickHouse crash loop from oversized TTL merge on March 2026 system log part (202603_76500_258781_236, ~7 GB) — truncated `system.metric_log`, `trace_log`, `text_log`, `query_log`, `asynchronous_metric_log`; added `max_bytes_to_merge_at_max_space_in_pool = 1 GiB` to `server.xml`

5. **Result: per-device flow enrichment live in Akvorado console** — `Src Net Name` shows hostnames (Calvin-s-S23, ServerPC, wazuh-server, Tower), `Src Net Tenant` shows VLAN, `Src Net Role` shows vendor. Verified via `dictGet` and `flows_5m0s` ClickHouse queries. Dictionary loaded with 5.4M elements (1.21 GiB).

## Incident Log

### Wazuh Indexer OOM — April 16, 2026
- **Impact:** Wazuh dashboard offline; "Error Pattern Handler (getPatternList)" shown to all users; SIEM visibility lost until resolved
- **Root cause:** OpenSearch (wazuh-indexer) JVM heap auto-sized above available RAM. Host has 7.8 GB RAM; Kafka (1 GB heap) + indexer (~2 GB auto-heap) + swap nearly full (3.9/4 GB) = OOM. 847 MB heap dump written to `/var/lib/wazuh-indexer/`
- **Resolution:** JVM heap explicitly set to `-Xms1g -Xmx1g` in `/etc/wazuh-indexer/jvm.options`. Heap dump on OOM disabled. Service restarted; cluster recovered to yellow/green with all shards assigned.
- **Time to resolve:** ~45 minutes (diagnosis + two fix iterations)
- **Prevention:** Explicit heap cap ensures no auto-sizing above RAM budget. TODO: swap expansion or RAM upgrade recommended; monthly check on indexer RSS.

### Fathom-vaultserver Data Loss — March–April 2026
- **Impact:** Complete loss of fathom-vaultserver OS and application data
- **Root cause:** VM disk replaced with empty 200GB sparse placeholder on March 4, 2026. Cause unknown — no evidence in bash_history or logs.
- **Detection gap:** Backups ran weekly but faithfully backed up the empty disk (6.4 MB compressed). No monitoring existed to flag suspiciously small backups.
- **Resolution:** Rebuilt as standalone VM at 192.168.10.24 with full monitoring. Deployed vmbackup-prom.sh on Unraid to prevent recurrence.
- **Prevention:** Backup size monitoring now alerts on any VM backup under 50 MB. Dashboard shows backup health at a glance in Fleet Overview.

---

### 21. Network Device Inventory & Security Baseline — April 18, 2026

Full network inventory system deployed:
- Network device inventory baseline sealed: 80 unique MACs across 90 ARP entries (4 VLANs: LAN, SecurityApps, Dev, VLAN4)
- Updated udm-arp-collector to v2: hostname overrides via device_names.json, MAC-centric state tracking (not IP-centric — DHCP-resilient), Wazuh JSON export, Prometheus audit metrics
- State file: /opt/monitoring/data/network_inventory_state.json — tracks by_mac and by_ip index for ARP conflict detection
- Wazuh decoder + rules 100700-100707 installed: inventory_summary (level 2), new_device (level 6), new_device on SecurityApps VLAN (level 10), unknown_vendor_sensitive_vlan (level 10), dhcp_ip_changed (level 3), arp_conflict (level 12), arp_conflict SecurityApps (level 14)
- Prometheus alert rules: NetworkNewDeviceDetected (warning), NetworkARPConflict (critical), NetworkARPCollectorStale (warning)
- Grafana dashboard: "Network Inventory & Audit" (UID: network-inventory) — 7 panels: stat cards (total devices, baseline count, new devices post-baseline, ARP conflicts, collector last run), devices-per-VLAN timeseries, new device table, ARP conflict table, full inventory table
- Network inventory HTML report at http://192.168.10.20:8088/network_inventory.html — sortable, searchable, auto-refresh 5min, VLAN color badges
- monitoring-report.timer enabled: regenerates monitoring_report.json every 5 minutes
- Named devices: 28 of 90 (62 still unnamed — ongoing identification effort)
- deploy-device-inventory.sh: 11-step idempotent deploy script (all root ops in one script)

---

### 22. Memory Management & JVM Optimization — April 18, 2026

Diagnosed and resolved chronic swap pressure that caused the April 16 OOM event:

Root cause: 4 Java processes all auto-sized JVM heap to 1/4 of host RAM (~1985 MB each) on a 7.8 GB host running Kafka + Wazuh Indexer + ZAP + Kafka UI simultaneously. Swap reached 3.9/4.0 GB (98%) — the exact condition that caused the April 16 indexer OOM.

Fixes applied:
1. ZAP (OWASP ZAP proxy): heap 1985m → 384m via .ZAP_JVM.properties injection, Docker limit 700m. Script: fix-zap-memory.sh
2. Kafka UI (akvorado-kafka-ui-1): heap auto → 256m via JAVA_OPTS in docker-compose.override.yml, Docker mem_limit 512m
3. Swap expansion: added /swap2.img (4 GB), total swap 4 GB → 8 GB, persisted in /etc/fstab. Script: expand-swap.sh

Result:
- Before: Swap 3.9/4.0 GB (98% — critical, OOM imminent)
- After: Swap 4.4/8.0 GB (55% — healthy headroom)
- ZAP memory: 495 MiB/512 MiB (96%, dangerous) → 477 MiB/700 MiB (68%)
- Kafka UI memory: ~470 MB swap → 281 MiB/512 MiB (55%)
- Total swap freed from JVM caps: ~1.1 GB

---

### 23. ContainerDown Alert False Positive Fix — April 18, 2026

Fixed ContainerDown Prometheus alert producing false positives for akvorado-clickhouse-1.
Root cause: Docker cAdvisor creates a new container_last_seen series per unique label set (includes restartcount label). When a container restarts, the old series (restartcount: N) stops updating but persists in TSDB. The old series exceeds the 120s threshold, firing the alert even though the container is running.
Fix: Changed alert expression from `(time() - container_last_seen{name!=""}) > 120` to `(time() - max by (name, instance, job, alias) (container_last_seen{name!=""})) > 120` — takes the freshest timestamp per container name, ignoring stale series from previous restart counts.
Script: fix-container-down-alert.sh

---

### 24. Google Workspace Storage Accuracy Fix — April 18, 2026

Fixed two compounding bugs that caused the org storage % to show 30.93% instead of the true ~56-70%:
1. generate-report.py used only gworkspace_org_storage_used_bytes (personal storage only, ~1.16 TB) without adding shared drive storage (~0.96 TB). Fixed to sum both: used_bytes = personal_bytes + shared_bytes
2. gworkspace-collector shared drive page cap: 50-page limit (50k files) was truncating large drives like Yokly USA (>50k files, 1.36 TB actual). Removed cap (now while True). Fix in deploy-device-inventory.sh step 3.

---

### 25. Wazuh-Grafana Integration, SOC Dashboard & Platform Hardening — April 26, 2026

#### Wazuh Indexer → Grafana Datasource
- Added Grafana Elasticsearch datasource pointing to Wazuh Indexer (OpenSearch 7.10.2) at `https://172.18.0.1:9200`, indices `wazuh-alerts-4.x-*`, version OpenSearch 1.x
- Resolved Docker networking blocker: Grafana container cannot reach host `localhost:9200`; added iptables rule `iptables -I INPUT 1 -s 172.18.0.0/16 -p tcp --dport 9200 -j ACCEPT` and UFW exception for the Docker subnet; fixed datasource URL to bridge gateway IP 172.18.0.1
- Added `extra_hosts: host.docker.internal:host-gateway` to Grafana service in docker-compose.yml
- Datasource health check: OK — "Elasticsearch data source is healthy"
- Wazuh SIEM events now queryable in Grafana as a native datasource; all 14 dashboards can overlay Wazuh events alongside Prometheus metrics

#### Security Operations Center Dashboard (SOC)
- Merged Alert Command Center + Wazuh Security Events dashboards into one unified SOC dashboard (UID: `security-ops-center`)
- 32 panels across 8 collapsible rows: Prometheus Alert Status, Wazuh SIEM Stats, Timelines, Active Prometheus Alerts, Wazuh Live High/Critical Events, Attack Analysis, Privilege Escalations, Infrastructure & Trends
- Exported to `/opt/monitoring/dashboards/security-ops-center.json`
- Deleted both predecessor dashboards after verifying all panels absorbed

#### Export Reports Dashboard
- New dashboard at `/d/export-reports` (UID: `export-reports`) — 24 panels across 8 rows
- Fully exportable tables: firing Prometheus alerts, scrape targets, Wazuh 24h summary (by level / by agent / by rule), critical/high events, SSH failures by source IP, sudo/root escalations by agent, employee reconciliation orphaned/missing
- HTML header panel with direct download link to `monitoring_report.json`
- All table panels configured with Grafana CSV export enabled

#### Dashboard Deduplication
- Identified 2 duplicate dashboards absorbed by SOC: Alert Command Center (alert-command-center) + Wazuh Security Events (wazuh-security-events)
- Removed nav links from remaining dashboards before deleting duplicates
- Result: clean 14-dashboard set with zero duplicates

#### prom-to-wazuh Expansion (7→14 checks)
Added 7 new alert categories to `/opt/monitoring/prom-to-wazuh.sh`:
- GWorkspace external sharing unrestricted
- GWorkspace shared drive rapid growth (>5 GB)
- Employee reconcile orphaned GW accounts
- Employee reconcile unauthorized admin (critical)
- Network new device detected
- Network ARP conflict (possible spoofing)
- Unraid array usage >90%

#### Alertmanager — Gmail SMTP Fix
- Replaced broken webhook receiver (`http://prometheus:9090/api/v1/alerts` — invalid endpoint) with Gmail SMTP
- Config: `smtp.gmail.com:587`, TLS required, HTML email templates with severity-based routing
- Routing: critical (10s group_wait, 1h repeat), warning (4h repeat), info (24h repeat)
- Inhibit rules: critical suppresses warning for same alertname+instance
- Status: awaiting Gmail app password — `REPLACE_WITH_GMAIL_APP_PASSWORD` placeholder in `alertmanager.yml`

#### Employee ↔ GWorkspace — Authorized Admins
- Defined 5 authorized GW super-admins in `authorized_admins.json`: brian.monte, csednie.regasa, josh, markangel, tim@agapay.gives
- Suppressed CRITICAL false-positive Wazuh alerts for 3 admins (csednie.regasa, josh, markangel) by directly updating 6 historical Wazuh Indexer documents via OpenSearch Update API (rule.level 12 → 3, tagged authorized_admin)
- Updated employee-gworkspace-reconcile.py to emit `info` (not `critical`) for authorized admins — pending root deployment via fix-p3-root.sh

#### Wazuh Agents Fix in generate-report.py
- Previous code hit Wazuh API port 55000 (not running) → "Connection refused" in monitoring_report.json
- Fixed: replaced with Wazuh Indexer aggregation query to `https://172.18.0.1:9200/wazuh-alerts-4.x-*/_search` using kibanaserver credentials
- Now returns 6 agents with name, ID, and last_seen: wazuh-server(000), ubuntu-192-168-5-131(001), unraid-192-168-10-10(002), movement-strategy(003), devops-192-168-1-253(004), fathom-server(006)

#### All 14 Dashboards Exported
- Previously only 5 dashboards were exported; now all 14 exported to `/opt/monitoring/dashboards/`
- New exports: akvorado, docker-containers, fleet-overview, google-workspace, html-reports, network-inventory, node-exporter-full, udm-pro, vm-backups, vps-movement-strategy, windows-exporter
- All exports use `${DS_PROMETHEUS}` and `${DS_WAZUH_INDEXER}` variable substitution for portable restore

#### Documentation
- Created `/opt/monitoring/PLATFORM_REVIEW.md` — rated platform 7.5/10 with P1–P4 prioritized gap analysis
- Created `/opt/monitoring/RESTORATION_GUIDE.md` — comprehensive 15-section restore-from-scratch guide for new engineers; covers all 10 restore phases with exact commands, health checks, architecture, 47 alert rules, 15 timers, 6 Wazuh agents, 19 Docker containers

---

## Security Audit & Platform Ratings — April 18, 2026

> Assessed by IT Administration. Scale: A (excellent), B (good), C (needs improvement), D (critical gap). Intended for leadership review and improvement planning.

| Domain | Rating | Score | Notes |
|--------|--------|-------|-------|
| Endpoint Monitoring Coverage | A- | 9/10 | 7 hosts + UDM Pro fully instrumented; SSH sessions, top processes, disk, net all visible |
| Network Visibility | B+ | 8/10 | IPFIX flows via Akvorado + 90-device ARP inventory with VLAN mapping. Gap: MAC not in IPFIX (UDM Pro firmware limitation) |
| SIEM Coverage | B+ | 8/10 | Wazuh 6 agents, auditd, FIM, active response, vuln detection, custom rules 100300-100707. Gap: no SOAR/playbook integration |
| Security Alerting | B | 7/10 | Prometheus 39 rules (0 firing). Gap: no email/Slack delivery; webhook only; no on-call paging |
| Identity & Access Visibility | C+ | 6/10 | SSH sessions tracked, Google Workspace extshare audited. Gap: 58 users unrestricted for external sharing; no MFA enforcement reporting |
| Incident Response Readiness | C | 5/10 | No formal runbooks; no documented escalation path; Alertmanager webhook-only; no PagerDuty/Slack integration |
| Backup & Recovery | B | 7/10 | VM backups monitored (age/size/health); fathom-vault incident documented; gap: no off-site backup; no tested recovery runbook |
| Vulnerability Management | B- | 6/10 | Wazuh vuln detection enabled (60m feeds). Gap: no formal SLA, no patch tracking dashboard, auditd on remote agents pending |
| Platform Reliability | B+ | 8/10 | Two OOM incidents resolved (April 13, April 16). Swap expanded to 8 GB. All JVM heaps explicitly capped. 98% uptime since April hardening |
| Documentation Quality | B+ | 8/10 | Architecture, workflow, scripts, accomplishments documented. Gap: no incident response runbooks; no DR procedures |
| Configuration Management | B | 7/10 | Git-managed, idempotent scripts. Gap: git commit overdue; no CI/CD validation; no secrets management (SSH keys in scripts) |
| Compliance Posture | C+ | 6/10 | No formal compliance framework mapped. Wazuh SCA runs CIS benchmarks. Gap: no HIPAA/SOC2 mapping; no audit logging SLA |

**Overall Platform Score: B (7.2/10)**

### Priority Improvement Areas

1. **Critical (resolve within 30 days):**
   - Alertmanager email/Slack — currently no team visibility when alerts fire
   - apt-mark hold wazuh-agent — prevent recurrence of April 13 manager wipeout
   - git commit all pending changes — repository is 3+ weeks behind live config

2. **High (resolve within 60 days):**
   - Incident response runbooks for each alert category
   - auditd deployment on all remote agents (vm-devops, unraid-tower, movement-strategy, fathom-vault)
   - Google Workspace extshare policy — 58 unrestricted users is a data loss risk
   - Wazuh FIM fix for unraid-tower (agent registered with bridge IP, not LAN IP)

3. **Medium (resolve within 90 days):**
   - Grafana ClickHouse datasource — enable per-device flow analytics in Grafana
   - RAM upgrade (+4-8 GB) or Kafka migration off wazuh-server
   - Dashboard authentication on port 8088
   - Duplicate MAC investigation (192.168.10.24 and 192.168.10.25 share MAC 52:54:00:ad:42:13)

---

### 23. Disk Full Recovery — April 26, 2026

Resolved disk-full condition (99% → 52%) that was preventing Prometheus WAL writes and login:

**Root cause:** ClickHouse internal system logging — `trace_log` accumulated 38 GiB in 10 days (~3.8 GB/day). TTLs were configured for 30 days but that meant 114 GB steady state, which filled the 97 GB disk.

**Changes:**
- `server.xml`: disabled `trace_log` and `processors_profile_log` entirely (not needed in production); reduced all other system log TTLs from 30d → 7d
- `docker-compose.yml`: Prometheus retention reduced from 90d → 30d (~3-4 GB recovery after TSDB compaction)
- `cleanup-disk.sh`: added Steps 10-12 — truncate `/var/log/root_guard_wazuh*.log`, `prometheus-wazuh.log`, `akvorado_mesh.jsonl`, and old compressed kern/auth logs
- New script: `fix-clickhouse-logs.sh` — truncates ClickHouse system log tables and restarts with new config
- New script: `fix-disk-prometheus-retention.sh` — applies 30d retention and triggers TSDB clean tombstones

**Space recovered:** ~41 GB from ClickHouse system log truncation, ~300 MB from log/screenshot cleanup

**Steady-state after fix:** ~239 MB flow data + <2 GB system logs (7-day rolling) + ~1.7 GB Prometheus (30d) = well within limits
