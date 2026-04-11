# Accomplishment Report — Leadership Summary

**Project:** On-Premise Infrastructure Monitoring Platform  
**Platform:** Prometheus + node_exporter + Custom HTML Dashboards  
**Hub:** 192.168.10.20 (wazuh-server)  
**Repository:** https://github.com/modem56-cpu/monitoring-infrastructure  
**Delivered:** February 2026 — Hardened & Stabilized April 2026  

---

## Executive Summary

Designed, deployed, and stabilized a fully on-premise infrastructure monitoring platform covering 6 endpoints across Linux VMs, Windows, NAS/hypervisor, and a remote VPS. The platform provides real-time visibility into system health, resource utilization, active user sessions, and process activity — all accessible via a lightweight web dashboard with no cloud dependency and no additional licensing cost.

In April 2026, a comprehensive hardening pass resolved 15+ operational issues including a 4-week node-exporter outage, stale VPS metrics collection, firewall misconfigurations, duplicate dashboard rendering, and SSH session detection failures — restoring full monitoring coverage across all endpoints.

---

## Key Deliverables

### 1. Unified Multi-Host Dashboard
- Single HTTP dashboard at `http://192.168.10.20:8088` covering all managed hosts
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
| Docker containers | Running/total count + container name list |

### 3. Specialized Host Monitoring
- **Unraid NAS (10.10):** Array utilization (77.7%), per-disk device table with temperatures/SMART/utilization, cache pool and system cache usage, parity validity, WireGuard VPN peer status (active/stale/never), SMB share sessions and configured users, VM count
- **Windows endpoint (1.253):** CPU, memory, commit charge, network, filesystem C:, SSH/SMB session tables, top processes by CPU and RSS
- **VPS (31.170.165.94):** Full system metrics pulled securely via SSH using a dedicated `metrics` user with forced command — no inbound firewall rule changes required on VPS
- **Wazuh SIEM server (10.20):** Self-monitoring with Docker container inventory (16 services tracked), sys_sample system health card

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

### 5. Version Control & Documentation
- Initialized git repository at `/opt/monitoring/`
- Connected to GitHub: `https://github.com/modem56-cpu/monitoring-infrastructure`
- Pushed all configuration files, scripts, rules, and targets
- Created `.gitignore` excluding sensitive files (SSH keys), runtime data (logs, reports, textfile_collector), and backup files
- Updated all documentation: README, ARCHITECTURE, WORKFLOW, SCRIPTS, TODO, ACCOMPLISHMENTS

---

## Platform Architecture (Summary)

```
Endpoints (node_exporter)  →  Prometheus TSDB  →  HTML Generator  →  HTTP :8088
     + Custom textfile         (Docker, 15s       (patch chain,
       collectors               scrape)            idempotent,
     + SSH pull (VPS)                              race-free)
```

- **Zero cloud dependency** — all components run on `192.168.10.20`
- **Zero licensing cost** — Prometheus, node_exporter, windows_exporter all OSS
- **Dockerized core** — node-exporter, Prometheus, blackbox-exporter, Grafana in Docker Compose
- **Idempotent patching** — HTML comment markers ensure safe re-runs with no duplication
- **Sequential generation** — systemd ordering prevents race conditions between timers
- **Graceful degradation** — `|| true` on all patch steps; one script failure does not break others
- **Admin visibility** — SSH sessions from known admin IPs tagged rather than hidden

---

## Metrics at a Glance (Current — April 11, 2026)

| Stat | Value |
|------|-------|
| Hosts monitored | 5 active (10.20, 10.10, 5.131, 1.253, VPS), 1 offline (10.24) |
| Prometheus scrape targets | 14 (node, windows, blackbox, prometheus self) |
| Dashboard refresh interval | 3 minutes |
| Dashboard consistency | Single view per host (race conditions eliminated) |
| SSH session tracking | Live per user/IP, admin-tagged, all hosts |
| Unique metric series | ~18 sys_sample + ~100 sys_topproc per host |
| Unraid device monitoring | 7 active devices with temp/SMART/utilization |
| VPS collection method | SSH forced command, 30s timeout, strict host key |
| Git repository | github.com/modem56-cpu/monitoring-infrastructure |
| Automated since | February 2026 (hardened April 2026) |
