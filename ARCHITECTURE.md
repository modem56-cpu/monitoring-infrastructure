# System Architecture

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MONITORING HUB: 192.168.10.20 (wazuh-server)         │
│              Prometheus :9090 (Docker) │ HTTP Server :8088               │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │ scrape every 15s
        ┌──────────────┼──────────────────────────────────────┐
        │              │              │              │          │
   ┌────┴────┐   ┌─────┴────┐  ┌─────┴────┐  ┌────┴─────┐  ┌┴──────────┐
   │10.10    │   │10.20     │  │10.24     │  │5.131     │  │1.253      │
   │Unraid   │   │Wazuh-svr │  │fathom-   │  │vm-devops │  │Windows    │
   │Tower    │   │(Docker)  │  │vault     │  │          │  │WinExporter│
   │:9100    │   │:9100     │  │:9100     │  │:9100     │  │:9182      │
   └─────────┘   └──────────┘  └──────────┘  └──────────┘  └───────────┘
                                                              31.170.165.94
                                                              VPS (SSH pull)
```

## Docker Networking

Prometheus and node-exporter run in Docker on the `monitoring_monitoring` bridge network.
Prometheus scrapes node-exporter via Docker DNS (`node-exporter:9100`), with a relabel
to preserve `instance="192.168.10.20:9100"` in metrics. External hosts (10.10, 5.131, 1.253)
are scraped via their LAN IPs through the Docker bridge gateway.

## Layers

### Collection Layer
- **node_exporter** (Docker on 10.20, native on other Linux hosts) — standard OS metrics
- **windows_exporter** on Windows host (port 9182) — WMI-based metrics
- **sys-sample-prom.sh** — custom textfile collector: CPU/mem/net/disk summary as `sys_sample_*` metrics
- **sys-topproc-prom.sh** — custom textfile collector: top processes as `sys_topproc_*` metrics
- **tower_ssh_sessions_local.sh** — textfile: active SSH sessions per user/source (uses `w -h -i` with full username resolution via `/etc/passwd`)
- **tower_textfile_extras.sh** (remote hosts) — Docker, SSH, WireGuard, SMB metrics
- **collect_vm_ms_ssh.sh** — SSH pull from VPS 31.170.165.94 using dedicated `metrics` user with forced command
- **WireGuard textfile** — WireGuard peer status (10.10 only)
- **SMB textfile** — SMB share sessions (10.10 only)

### Storage Layer
- **Prometheus TSDB** — local time-series storage, 15-day default retention, Docker volume `prometheus_data`
- **Textfile directory** — `/opt/monitoring/textfile_collector/*.prom` (mounted read-only into node-exporter container at `/textfile_collector`)

### Generation Layer
- Two systemd oneshot services triggered every 3 minutes
- `prom-html-dashboards.service` runs first (base tower HTML generation)
- `prom-refresh-html.service` runs after (vm_dashboard generation + patches via `After=prom-html-dashboards.service`)
- Both run `patch_reports_final.sh` in ExecStartPost which applies all extras patches
- Base HTML is small (3-5 KB); patches grow it to 6-12 KB with full metrics

### Serving Layer
- Python HTTP server on port 8088 serving `/opt/monitoring/reports/*.html`
- Static files with `Cache-Control: no-cache` headers injected by patch_reports_nocache.sh

## Prometheus Scrape Targets

| Instance | Job | Type | Notes |
|----------|-----|------|-------|
| node-exporter:9100 | node_wazuh_server | node_exporter (Docker) | Relabeled to instance=192.168.10.20:9100 |
| 192.168.10.24:9100 | node_ubuntu_192_168_10_24 | node_exporter | Currently DOWN (VM off) |
| 192.168.5.131:9100 | node_vm_devops_192_168_5_131 | node_exporter | UFW allows 192.168.10.0/24 |
| 192.168.10.10:9100 | node_unraid_192_168_10_10 | node_exporter | |
| 192.168.1.253:9182 | windows_192_168_1_253 | windows_exporter | |
| 31.170.165.94:9100 | node_hostinger_31_170_165_94 | node_exporter | DOWN (firewall); SSH-pull active |
| 192.168.10.1 | bb_icmp | blackbox | ICMP ping |
| 192.168.10.1:443 | bb_tcp | blackbox | TCP connect |
| prometheus:9090 | prometheus | self | |

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
