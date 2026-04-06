# Accomplishment Report — Leadership Summary

**Project:** On-Premise Infrastructure Monitoring Platform  
**Platform:** Prometheus + node_exporter + Custom HTML Dashboards  
**Hub:** 192.168.10.20 (wazuh-server)  
**Delivered:** April 2026  

---

## Executive Summary

Designed, deployed, and stabilized a fully on-premise infrastructure monitoring platform covering 6 endpoints across Linux VMs, Windows, NAS/hypervisor, and a remote VPS. The platform provides real-time visibility into system health, resource utilization, active user sessions, and process activity — all accessible via a lightweight web dashboard with no cloud dependency and no additional licensing cost.

---

## Key Deliverables

### 1. Unified Multi-Host Dashboard
- Single HTTP dashboard at `http://192.168.10.20:8088` covering all managed hosts
- Auto-refreshes every 3 minutes via systemd timers
- No authentication required on internal network (appropriate for internal SOC use)

### 2. Per-Host Metrics Collected
| Metric Category | Details |
|-----------------|---------|
| CPU utilization | % busy, per-core via node_exporter |
| Memory & Swap | Total / used / cached / swap % |
| Disk I/O | Read/write rates (B/s) and lifetime totals |
| Network I/O | Current throughput + lifetime RX/TX totals + avg Mbps since boot |
| Filesystem | Root partition % used |
| Process table | Top 15 by CPU, top 15 by RSS — with username, PID, command name |
| Active SSH sessions | Live table: user, source IP, session count per host |

### 3. Specialized Host Monitoring
- **Unraid NAS (10.10):** Array parity validity, cache pool utilization, per-disk temperatures and utilization, WireGuard VPN peer status (active/stale/never), SMB share sessions and configured users
- **Windows endpoint (1.253):** WMI-based CPU, memory, disk, network via windows_exporter
- **VPS (31.170.165.94):** Metrics pulled securely via SSH using a dedicated `metrics` user with forced command — no inbound firewall rule changes required on VPS
- **Wazuh SIEM server (10.20):** Self-monitoring with Docker container inventory (15 services tracked)

### 4. Security & Reliability Hardening (April 2026)
- **Fixed critical pipeline hang:** SSH collection to VPS had no timeout, causing systemd services to stay in `activating` state indefinitely — timers could not re-arm. Added `timeout 30s` on SSH and `timeout 15s` on ssh-keyscan. Pipeline now completes in under 60 seconds per cycle.
- **Fixed file targeting mismatch:** HTML patch scripts were injecting metrics into `vm_dashboard_` files while the dashboard served `tower_` files — users saw no metrics for 10.20 and 5.131. Corrected all target paths.
- **Fixed process command resolution:** Textfile collectors export `comm` label; scripts queried `cmd` label — all process command cells were blank. Updated all three host extras scripts.
- **Removed ISO N/A false positives:** Hardcoded "ISO N/A" replaced with conditional suppression — line omitted entirely when no ISO metric exists.
- **Eliminated duplicate CPU table:** Two scripts independently injected CPU tables into the same files. Removed overlap; each host now has exactly one CPU table.
- **Suppressed zero-swap display:** Hosts with no swap configured no longer show `0 B of 0 B (—%)`.
- **Fixed 10.24 filesystem metric name:** Collector exports `sys_sample_fs_root_percent`; script queried `sys_sample_rootfs_used_percent` — resulted in blank filesystem row. Added correct metric name to query chain.

---

## Platform Architecture (Summary)

```
Endpoints (node_exporter)  →  Prometheus TSDB  →  HTML Generator  →  HTTP :8088
     + Custom textfile              (3-min             (patch chain
       collectors                   scrape)             idempotent)
```

- **Zero cloud dependency** — all components run on `192.168.10.20`
- **Zero licensing cost** — Prometheus, node_exporter, windows_exporter all OSS
- **Idempotent patching** — HTML comment markers ensure safe re-runs with no duplication
- **Graceful degradation** — `|| true` on all patch steps; one script failure does not break others

---

## Metrics at a Glance (Current)

| Stat | Value |
|------|-------|
| Hosts monitored | 6 active, 1 pending (VPS node_exporter) |
| Prometheus scrape targets | 14 (node, windows, blackbox, prometheus self) |
| Dashboard refresh interval | 3 minutes |
| Unique metric series | ~18 sys_sample + ~15×sys_topproc per host |
| SSH session tracking | Live, per user/IP |
| Automated since | February 2026 (hardened April 2026) |
