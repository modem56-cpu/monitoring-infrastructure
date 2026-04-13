# System Architecture

## High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                     MONITORING HUB: 192.168.10.20 (wazuh-server)                │
│                                                                                  │
│  Prometheus :9090  │  Grafana :3000  │  Alertmanager :9093  │  HTTP :8088        │
│  Wazuh Manager     │  cAdvisor :8080 │  SNMP Exporter       │  Blackbox Exporter │
└──────────────────────┬───────────────────────────────────────────────────────────┘
                       │ scrape every 15s
        ┌──────────────┼──────────────────────────────────────────────────┐
        │              │              │              │          │          │
   ┌────┴────┐   ┌─────┴────┐  ┌─────┴────┐  ┌────┴─────┐  ┌┴────────┐ │
   │10.10    │   │10.20     │  │10.24     │  │5.131     │  │1.253    │ │
   │Unraid   │   │Wazuh-svr │  │fathom-   │  │vm-devops │  │win11-vm │ │
   │Tower    │   │(Docker)  │  │vault     │  │          │  │WinExp   │ │
   │:9100    │   │:9100     │  │:9100     │  │:9100     │  │:9182    │ │
   │Agent005 │   │Agent000  │  │Agent007  │  │Agent004  │  │Agent003 │ │
   └─────────┘   └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
                                                                        │
   ┌──────────────────────┐    ┌──────────────────────────────┐         │
   │31.170.165.94         │    │192.168.10.1                  │         │
   │movement-strategy VPS │    │UDM Pro (Gateway/Firewall)    │         │
   │VPN: 10.253.2.22      │    │SNMP (if_mib) + Blackbox      │         │
   │SSH collector          │    │Syslog → Wazuh (UDP 514)      │         │
   │Agent006              │    │                              │         │
   └──────────────────────┘    └──────────────────────────────┘         │
                                                                        │
   ┌──────────────────────┐    ┌──────────────────────────────┐         │
   │Google Workspace      │    │Akvorado Flow Pipeline        │         │
   │SA: gam-project@...   │    │Inlet + Outlet + Orchestrator │         │
   │Login/Admin/Drive     │    │Flow rates, Kafka, ClickHouse │         │
   │Storage enforcement   │    │                              │         │
   └──────────────────────┘    └──────────────────────────────┘         │
```

## Docker Stack (docker-compose.yml)

| Container | Port | Network | Purpose |
|-----------|------|---------|---------|
| prometheus | 9090 (localhost) | monitoring, akvorado_default | TSDB, 90-day retention, admin API enabled |
| grafana | 3000 (LAN) | monitoring | 10 dashboards, HTML sanitization disabled |
| alertmanager | 9093 (localhost) | monitoring | Webhook receiver |
| node-exporter | internal only | monitoring | Host metrics + textfile collector |
| blackbox-exporter | 9115 | monitoring | ICMP, TCP, HTTP (incl. http_2xx_selfsigned) |
| snmp-exporter | 9116 | monitoring | UDM Pro SNMP (if_mib) |
| cadvisor | 8080 | monitoring | Per-container Docker metrics |

## Docker Networking

Prometheus and node-exporter run in Docker on the `monitoring_monitoring` bridge network.
Prometheus is also connected to `akvorado_default` for scraping Akvorado services.
Prometheus scrapes node-exporter via Docker DNS (`node-exporter:9100`), with a relabel
to preserve `instance="192.168.10.20:9100"` in metrics. External hosts (10.10, 5.131, 1.253)
are scraped via their LAN IPs through the Docker bridge gateway.

## Layers

### Collection Layer
- **node_exporter** (Docker on 10.20, native on other Linux hosts) -- standard OS metrics
- **windows_exporter** on win11-vm (port 9182) -- WMI-based metrics
- **sys-sample-prom.sh** -- custom textfile collector: CPU/mem/net/disk summary as `sys_sample_*` metrics
- **sys-topproc-prom.sh** -- custom textfile collector: top processes as `sys_topproc_*` metrics
- **tower_ssh_sessions_local.sh** -- textfile: active SSH sessions per user/source (uses `w -h -i` with full username resolution via `/etc/passwd`)
- **tower_textfile_extras.sh** (remote hosts) -- Docker, SSH, WireGuard, SMB metrics
- **collect_vm_ms_ssh.sh** -- SSH pull from VPS 31.170.165.94 via WireGuard VPN (10.253.2.22)
- **snmp-exporter** -- UDM Pro interface metrics via SNMP (if_mib)
- **blackbox-exporter** -- ICMP, TCP, HTTP probes (UDM uses http_2xx_selfsigned)
- **cadvisor** -- per-container CPU, memory, network, I/O metrics
- **gworkspace-collector** -- Google Workspace login/admin/drive events, storage, shared drives
- **akvorado scrape targets** -- inlet, outlet, orchestrator metrics
- **WireGuard textfile** -- WireGuard peer status (10.10 only)
- **SMB textfile** -- SMB share sessions (10.10 only)

### Storage Layer
- **Prometheus TSDB** -- local time-series storage, 90-day retention, Docker volume `prometheus_data`
- **Textfile directory** -- `/opt/monitoring/textfile_collector/*.prom` (mounted read-only into node-exporter container at `/textfile_collector`)

### Alerting Layer
- **30 alerting rules** across: `blackbox.rules.yml`, `infrastructure.rules.yml`, `containers.rules.yml`, `akvorado.rules.yml`
- **19 recording rules** in `recording.rules.yml`
- **Alertmanager** -- webhook receiver for alert routing
- **prom-to-wazuh.sh** -- bridges Prometheus alerts to Wazuh SIEM (7 alert types, every 60s)
- **akvorado-mesh-to-wazuh** -- bridges Akvorado alerts to Wazuh (every 5min)

### SIEM Layer (Wazuh)
- **6 active agents** (000 manager, 003 win11-vm, 004 vm-devops, 005 unraid-tower, 006 movement-strategy, 007 fathom-vault)
- **Custom decoders**: udm_firewall.xml (UDM Pro iptables logs)
- **Custom rules**: prometheus_monitoring.xml (100300-100307), udm_firewall.xml (100400-100407), google_workspace.xml (100500-100508)
- **auditd**: 20+ rules (identity, SSH keys, priv-esc, root commands, cron, systemd, Docker, WireGuard, kernel modules)
- **FIM**: /root/.ssh, crontabs, /etc/wireguard, docker-compose.yml, prometheus.yml
- **Active Response**: firewall-drop on SSH brute force (rule 5763, 1hr block)
- **Vulnerability Detection**: enabled (60m feed updates)
- **SCA**: enabled (12h interval, CIS benchmarks)
- **UDM Pro syslog**: UDP 514 from 192.168.10.1

### Visualization Layer
- **Grafana** -- 10 dashboards covering fleet overview, per-node deep-dive, Windows, VPS, UDM Pro, Docker/APIs, Akvorado, Google Workspace, HTML reports hub, export reports
- **HTML dashboards** -- auto-generated every 3 minutes, served on :8088
- **JSON report** -- `/opt/monitoring/generate-report.py`, auto-refreshed every 5min at :8088/monitoring_report.json

### Generation Layer (HTML)
- Two systemd oneshot services triggered every 3 minutes
- `prom-html-dashboards.service` runs first (base tower HTML generation)
- `prom-refresh-html.service` runs after (vm_dashboard generation + patches via `After=prom-html-dashboards.service`)
- Both run `patch_reports_final.sh` in ExecStartPost which applies all extras patches
- Base HTML is small (3-5 KB); patches grow it to 6-12 KB with full metrics

### Serving Layer
- Python HTTP server on port 8088 serving `/opt/monitoring/reports/*.html`
- Static files with `Cache-Control: no-cache` headers injected by patch_reports_nocache.sh

## Prometheus Scrape Targets (23 total)

| Instance | Job | Type | Notes |
|----------|-----|------|-------|
| node-exporter:9100 | node_wazuh_server | node_exporter (Docker) | Relabeled to instance=192.168.10.20:9100 |
| 192.168.10.24:9100 | node_ubuntu_192_168_10_24 | node_exporter | fathom-vault |
| 192.168.5.131:9100 | node_vm_devops_192_168_5_131 | node_exporter | UFW allows 192.168.10.0/24 |
| 192.168.10.10:9100 | node_unraid_192_168_10_10 | node_exporter | |
| 192.168.1.253:9182 | windows_192_168_1_253 | windows_exporter | |
| 31.170.165.94:9100 | node_hostinger_31_170_165_94 | node_exporter | DOWN (firewall); SSH-pull active |
| 192.168.10.1 | bb_icmp | blackbox | ICMP ping |
| 192.168.10.1:443 | bb_tcp | blackbox | TCP connect |
| 192.168.10.1:443 | bb_http | blackbox | HTTP (http_2xx_selfsigned) |
| prometheus:9090 | prometheus | self | |
| cadvisor:8080 | cadvisor | cadvisor | Per-container metrics |
| snmp (192.168.10.1) | snmp | snmp_exporter | UDM Pro if_mib |
| akvorado-inlet | akvorado | akvorado | Flow inlet |
| akvorado-outlet | akvorado | akvorado | Flow outlet |
| akvorado-orchestrator | akvorado | akvorado | Orchestrator |
| (+ additional blackbox/API health probe targets) | | | |

## Grafana Dashboards (10)

| # | Dashboard | Path | Description |
|---|-----------|------|-------------|
| 1 | Fleet Overview | /d/fleet-overview | All nodes, CPU/mem/disk bars, Docker, APIs, WAN, SSH, Google Workspace |
| 2 | Node Exporter Full | /d/node-exporter-full | 31-panel Linux deep-dive |
| 3 | Windows Exporter | /d/windows-exporter | 22-panel Windows dashboard |
| 4 | Movement Strategy VPS | /d/vps-movement-strategy | SSH-collected metrics |
| 5 | UDM Pro | /d/udm-pro | All SNMP interfaces, traffic, status |
| 6 | Docker Containers & APIs | /d/docker-containers | cAdvisor + API health probes |
| 7 | Akvorado Flow Pipeline | /d/akvorado | Inlet/outlet/orchestrator, flow rates, Kafka, ClickHouse (12 panels) |
| 8 | Google Workspace | /d/google-workspace | Users, storage breakdown, shared drives, events, 50GB enforcement |
| 9 | HTML Reports Hub | /d/html-reports | Embedded HTML dashboards with collapsible rows |
| 10 | Export Reports | /d/export-reports | JSON download for AI analysis |

## Google Workspace Integration

| Setting | Value |
|---------|-------|
| Service Account | gam-project@gam-project-gf5mq.iam.gserviceaccount.com |
| Admin | brian.monte@yokly.gives |
| Collection interval | 5min (gworkspace-collector timer) |
| Data collected | Login events, admin actions, drive events, external sharing, 50GB storage enforcement, security alerts |
| Org storage | ~2.84 TB of 3.67 TB (77%), includes 1.47 TB shared drives |
| 50GB exempt users | dan@agapay, calvin@yokly, it_dept@yokly, dm@yokly, tim@agapay, eddie@agapay |
| Shared drives scanned | 28 |

## WireGuard VPN

- movement-strategy has wg2 tunnel (10.253.2.22), endpoint vpn.yoklyu.gives:51822
- SSH collector connects via VPN IP

## Akvorado Integration

| Component | Details |
|-----------|---------|
| Scrape targets | 3 (inlet, outlet, orchestrator) |
| Alert rules | 6 in akvorado.rules.yml |
| Recording rules | 4 in recording.rules.yml |
| Wazuh bridge | akvorado-mesh-to-wazuh (AkvoradoDown, AkvoradoNoFlows) |
| Grafana dashboard | /d/akvorado (12 panels) |

## HTML File Types

| Prefix | Example | Generator | Content |
|--------|---------|-----------|---------|
| `tower_` | tower_192_168_10_20_9100.html | prom_tower_dashboard_html.sh + extras patches | Primary dashboard: sys_sample, SSH, Top CPU/RSS, Docker, Unraid |
| `vm_dashboard_` | vm_dashboard_192_168_10_20_9100.html | prom_vm_dashboard_html.sh | Rich grid format (secondary) |
| `win_` | win_192_168_1_253_9182.html | prom_win_html_192_168_1_253_9182.sh | Windows: system stats, SSH/SMB, processes |
| `vps_` | vps_31_170_165_94.html | prom_vps_html_31_170_165_94.sh | VPS: full metrics from SSH-collected data |

## SSH Session Detection

- **10.20**: `tower_ssh_sessions_local.sh` uses `w -h -i` (not `who`, which has utmp issues) with full username resolution from `/etc/passwd`
- **Remote hosts**: `tower_textfile_extras.sh` on each host generates `tower_ssh_sessions_user_src` metrics; 5.131 filters to remote-only (IP-based src)
- **Admin tagging**: Sessions from known admin IPs (10.253.2.2) are tagged with `(admin)` in the SSH table display
- **Non-interactive SSH**: Collection scripts (`collect_vm_ms_ssh.sh`) use `ssh -T` with `BatchMode` and do not appear as sessions
