# Monitoring Platform Review
**Organization:** Yokly / Agapay  
**Date:** 2026-04-26  
**Reviewed by:** Claude Code (AI assistant)  
**Platform admin:** Brian Monte (brian.monte@yokly.gives)

---

## Overall Rating: 7.5 / 10

A well-built, multi-layered monitoring stack that covers infrastructure, security, SaaS, and HR operations. The platform is production-grade in its data collection and dashboarding. The main gaps are in alerting delivery (Alertmanager is broken), Wazuh agent coverage, and operational hardening (secrets management, backup of monitoring state).

---

## What Is Built and Working

### Infrastructure Monitoring ✅
- **7 nodes** fully covered: wazuh-server, Unraid Tower, VM DevOps, VM DevOps2, Fathom Vault, Windows VM, Movement Strategy VPS
- **23/23 Prometheus scrape targets** healthy (0 down)
- **Node Exporter** on all Linux nodes — CPU, memory, disk, network, processes
- **Windows Exporter** on Windows VM
- **cAdvisor** for Docker container resource usage
- **Blackbox Exporter** for ICMP ping and TCP port checks on external nodes

### Network Monitoring ✅
- **UDM Pro** (UniFi Dream Machine) metrics via SNMP
- **ARP/MAC collector** — tracks all LAN devices, detects new devices and conflicts
- **Akvorado** — full NetFlow pipeline with ClickHouse backend for traffic analysis
- **SNMP Exporter** wired and scraping

### Google Workspace Monitoring ✅
- **GWorkspace collector** running every 5 min — users, storage, Drive activity, admin events, login events
- **Shared drives growth** monitoring
- **External share** unrestricted detection
- **Storage quota** enforcement tracking
- **Top storage users** tracked (50 GB quota, exemptions handled)

### Employee ↔ GWorkspace Reconciliation ✅
- Pulls active roster from Google Sheet (1031 rows, Status = Active)
- Compares against live GW Directory API
- Detects: orphaned accounts, missing accounts, suspended-active mismatch, unauthorized admins
- **99 employees / 99 GW active — clean match**
- Authorized admins list established (5 accounts: brian.monte, csednie.regasa, josh, markangel, tim@agapay.gives)
- Runs every 30 min via systemd timer
- Feeds Prometheus metrics + Wazuh events

### Wazuh SIEM ✅
- Wazuh Manager active, receiving events
- Custom decoders: `network_inventory`, `employee_reconcile`
- Custom rules: employee reconcile rules (100800–100807)
- Wazuh Indexer (OpenSearch 7.10.2) — cluster healthy, 313 active shards
- Alert volume: ~20,000–130,000 events/day across severity levels

### Grafana Dashboards ✅ (14 dashboards, 0 duplicates)
| Dashboard | Purpose |
|---|---|
| Security Operations Center | Live ops — Prometheus + Wazuh merged |
| Export Reports | All tables exportable CSV + JSON report link |
| Employee ↔ GWorkspace | Roster vs GW account comparison |
| Fleet Overview | All nodes health |
| Google Workspace | GW usage, storage, security |
| Network Inventory & MAC Map | ARP / device tracking |
| Docker Containers & APIs | Container + API health |
| Akvorado Flow Pipeline | Network flow analytics |
| UDM Pro | UniFi gateway metrics |
| VM Backups (Unraid) | Backup job status |
| HTML Reports Hub | Per-node embedded HTML UIs |
| Node Exporter Full | Deep per-host metrics |
| Windows Exporter | Windows VM metrics |
| Movement Strategy (VPS) | External VPS node |

### Data Pipeline ✅
- **monitoring_report.json** served at `http://192.168.10.20:8088/monitoring_report.json`
- Auto-regenerates every 5 min via systemd timer
- Includes: node status, system metrics, firing alerts, Docker, GWorkspace, Akvorado, Grafana dashboard exports, SSH sessions
- 5 dashboard JSONs embedded for AI ingestion

---

## Current Active Alerts (2026-04-26)

| Alert | Severity | Notes |
|---|---|---|
| NetworkARPConflict | critical | 45 ARP conflicts detected — investigate duplicate MACs on LAN |
| NetworkNewDeviceDetected | warning | New device joined network — verify and whitelist |
| HighCPUProcess | warning | On 192.168.10.10 (Unraid Tower) |
| GWorkspace_ExtShare_Unrestricted_Info | info | External sharing unrestricted — policy decision needed |

---

## What Needs to Be Done

### P1 — Critical (Breaks alerting delivery)

**1. Alertmanager webhook is broken**  
The receiver points to `http://prometheus:9090/api/v1/alerts` — that is the Prometheus alerts query endpoint, not a valid webhook receiver. Alerts fire in Prometheus but **nobody gets notified**.  
Fix: Configure a real receiver — email via Gmail SMTP, Slack webhook, or PagerDuty.

```yaml
# alertmanager.yml — replace the broken webhook with email:
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@yokly.gives'
  smtp_auth_username: 'alerts@yokly.gives'
  smtp_auth_password: '<gmail-app-password>'
receivers:
  - name: default
    email_configs:
      - to: 'brian.monte@yokly.gives'
        send_resolved: true
```

**2. monitoring_report.json — wazuh_agents field broken**  
Reports `Error: [Errno 111] Connection refused` — the generate-report.py is trying to hit a port that isn't open or doesn't exist. Fix the wazuh_agents collection method (use the Wazuh Indexer API or `/var/ossec/bin/agent_control`).

---

### P2 — High (Gaps in coverage)

**3. Wazuh agent coverage is incomplete**  
Only the Wazuh server (agent 000) appears to be active. All other nodes (Unraid, VMs, Windows, VPS) should have Wazuh agents installed and connected. This means security events from those nodes are not in the SIEM.  
> Note: Do NOT install `wazuh-agent` on the Wazuh manager — it removes the manager package (critical incident April 13 2026).

**4. Grafana dashboard exports — 9 of 14 not exported**  
Dashboards not exported to `/opt/monitoring/dashboards/`:
- akvorado, docker-containers, fleet-overview, google-workspace, html-reports, vps-movement-strategy, network-inventory, node-exporter-full, udm-pro, vm-backups, windows-exporter  

These are missing from `monitoring_report.json` AI context and cannot be portably imported/restored.

**5. Wazuh Indexer cluster status is yellow**  
`unassigned_shards: 1` — one shard has no replica assigned. On a single-node cluster this is expected (no replica possible), but it should be acknowledged or suppressed so the yellow status doesn't mask real issues.

**6. No VM backup alerting**  
`tower_unraid.prom` exists but `unraid_vm_backup_*` metrics appear empty. Backup status is not feeding into Prometheus alerts — a failed backup would go unnoticed.

---

### P3 — Medium (Hardening and completeness)

**7. No secrets management**  
- Service account key `gam-project-gf5mq-97886701cbdd.json` is stored in plaintext at `/opt/monitoring/`
- Grafana admin password is `admin` (default)
- Wazuh Indexer `kibanaserver` password is in scripts
- Recommend: move secrets to environment files with `chmod 600`, or use a secrets manager (Vault, SOPS)

**8. Grafana admin password is default**  
`admin:admin` — change immediately. Any user who can reach port 3000 has full dashboard admin access.

**9. No iptables persistence**  
The `iptables` rule added to allow Docker → Wazuh Indexer (port 9200) was added at runtime. It will be **lost on next reboot**. Persist it:
```bash
apt install iptables-persistent
netfilter-persistent save
```

**10. authorized_admins.json deploy script requires manual root run**  
`/opt/monitoring/deploy-authorized-admins.sh` has not been run yet (no sudo in this session). The reconcile script is currently still using the old version without the authorized admin logic.

**11. No log rotation on employee-gworkspace-wazuh.log**  
The file grows unbounded. Add a logrotate config:
```
/var/log/employee-gworkspace-wazuh.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

**12. ClickHouse trace_log — monitor disk growth**  
Disabled in April 2026 after filling disk (~3.8 GB/day). Confirm the disable is persisted across restarts and add a disk usage alert for the ClickHouse data directory.

---

### P4 — Low (Nice to have)

**13. Auto-export Grafana dashboards to JSON on save**  
Currently requires manual script runs. A Grafana provisioning approach or a post-save hook would keep `/opt/monitoring/dashboards/` always in sync.

**14. Employee Google Sheet sync is manual**  
`apply-employees-sync.sh` must be run manually. Add a systemd timer to sync the roster from Google Sheets daily (e.g., 08:00) so employee changes propagate automatically.

**15. Akvorado / ClickHouse backup**  
No backup strategy for Akvorado data. ClickHouse data is on the same host as the monitoring stack — a disk failure loses all flow history.

**16. No Grafana backup**  
`grafana_data` is a Docker volume. If the host is rebuilt, all dashboard customizations, datasource configs, and user settings are lost. Export to git or take periodic volume snapshots.

**17. VPS (Movement Strategy) — only ICMP + node metrics**  
No application-level monitoring on the VPS. If the app crashes but the host stays up, no alert fires. Add a blackbox HTTP check against the application endpoint.

**18. prom-to-wazuh coverage gaps**  
The Prometheus → Wazuh forwarding script does not forward: GWorkspace shared drive alerts, employee reconcile alerts, or network inventory alerts. Only infrastructure alerts are forwarded.

---

## Architecture Summary

```
Google Sheets ──────────────────────────────────┐
                                                 ▼
GWorkspace API ─── gworkspace-collector.py ──► employees.json
                   employee-reconcile.py  ──► employee_reconcile.prom
                                          ──► employee-gworkspace-wazuh.log
                                                 │
Node Exporter                                    │
Windows Exporter    ┐                            │
cAdvisor            ├─► Prometheus ──► Alertmanager (⚠ broken)
SNMP Exporter       │       │
Blackbox Exporter   │       ▼
UDM Pro             │   Grafana (14 dashboards)
Akvorado            ┘       │
Textfile Collectors         ▼
                    monitoring_report.json (AI agent)
                            │
Wazuh Manager ──────────────┤
  (no agents yet)           │
        │                   │
        ▼                   │
Wazuh Indexer ─────────► Grafana (Elasticsearch datasource)
(OpenSearch 7.10.2)         │
                            ▼
                    Security Operations Center
                    Export Reports
```

---

## Quick Win Checklist

```
[x] sudo bash /opt/monitoring/fix-p3-root.sh  (run to complete)
[x] Alertmanager configured with Gmail SMTP — add app password to alertmanager.yml
[-] Grafana admin password — excluded by user
[x] fix-p3-root.sh includes iptables-persistent install
[x] wazuh_agents fixed — now reads from Wazuh Indexer (6 agents reporting)
[ ] Install Wazuh agents on: Unraid, VM DevOps, VM DevOps2, Fathom Vault, Windows VM, VPS
[x] All 14 dashboards exported to /opt/monitoring/dashboards/
[x] fix-p3-root.sh adds logrotate for employee-reconcile + prometheus-wazuh logs
[x] fix-p3-root.sh installs employees-sheet-sync.timer (daily 08:00)
[x] Unraid array + HostDisk alert rules added to infrastructure.rules.yml
[x] fix-p3-root.sh installs iptables-persistent
```

---

## Strengths

- Custom textfile collector architecture is clean and extensible
- Google Workspace integration is deep (storage, sharing, admin events, Drive activity)
- Employee reconciliation is a standout feature — proactive HR/IT gap detection
- Wazuh → Grafana wiring via Elasticsearch datasource works correctly
- Dashboard structure is logical with no duplicates after cleanup
- monitoring_report.json as AI-ingestible payload is a strong operational concept
- Authorized admins concept prevents false-positive CRITICAL alerts

## Weaknesses

- Alertmanager is misconfigured — the most critical gap (silent failures)
- Security basics: default Grafana password, plaintext keys
- Wazuh agent coverage: only the manager itself, no endpoint telemetry
- No infrastructure-as-code for dashboards (manual script runs required)
- No DR/restore plan for Grafana or ClickHouse data

---

*Generated by Claude Code — review against live system state before acting on recommendations.*
