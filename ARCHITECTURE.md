# System Architecture

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MONITORING HUB: 192.168.10.20 (wazuh-server)         │
│                         Prometheus :9090  │  HTTP Server :8088           │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │ scrape :9100 every 15s
        ┌──────────────┼──────────────────────────────────────┐
        │              │              │              │          │
   ┌────┴────┐   ┌─────┴────┐  ┌─────┴────┐  ┌────┴─────┐  ┌┴──────────┐
   │10.10    │   │10.20     │  │10.24     │  │5.131     │  │1.253      │
   │Unraid   │   │Wazuh-svr │  │fathom-   │  │vm-devops │  │Windows    │
   │Tower    │   │(self)    │  │vault     │  │          │  │WinExporter│
   │:9100    │   │:9100     │  │:9100     │  │:9100     │  │:9182      │
   └─────────┘   └──────────┘  └──────────┘  └──────────┘  └───────────┘
                                                              31.170.165.94
                                                              VPS (SSH pull)
```

## Layers

### Collection Layer
- **node_exporter** on each Linux host (port 9100) — standard OS metrics
- **windows_exporter** on Windows host (port 9182) — WMI-based metrics
- **sys-sample-prom.sh** — custom textfile collector: CPU/mem/net/disk summary as `sys_sample_*` metrics
- **sys-topproc-prom.sh** — custom textfile collector: top 15 processes as `sys_topproc_*` metrics
- **tower_ssh_sessions** — textfile: active SSH sessions per user/source as `tower_ssh_sessions_user_src`
- **collect_vm_ms_ssh.sh** — SSH pull from VPS 31.170.165.94 using dedicated `metrics` user with forced command
- **WireGuard textfile** — WireGuard peer status (10.10 only)
- **SMB textfile** — SMB share sessions (10.10 only)

### Storage Layer
- **Prometheus TSDB** — local time-series storage, 15-day default retention
- **Textfile directory** — `/opt/monitoring/textfile_collector/*.prom` (scraped by node_exporter)

### Generation Layer
- Two systemd oneshot services triggered every 3 minutes
- Each generates base HTML then applies patches via ExecStartPost chain
- Base HTML is small (3-5 KB); patches grow it to 4-9 KB with full metrics

### Serving Layer
- HTTP server on port 8088 serving `/opt/monitoring/reports/*.html`
- Static files with `Cache-Control: no-cache` headers injected by patch_reports_nocache.sh

## Prometheus Scrape Targets

| Instance | Job | Type |
|----------|-----|------|
| 192.168.10.20:9100 | node_wazuh_server | node_exporter |
| 192.168.10.24:9100 | node_ubuntu_192_168_10_24 | node_exporter |
| 192.168.5.131:9100 | node_vm_devops_192_168_5_131 | node_exporter |
| 192.168.10.10:9100 | node_unraid_192_168_10_10 | node_exporter |
| 192.168.1.253:9182 | windows_192_168_1_253 | windows_exporter |
| 31.170.165.94:9100 | node_hostinger_31_170_165_94 | node_exporter (DOWN) |
| 192.168.10.1 | bb_icmp | blackbox |
| 192.168.10.1:443 | bb_tcp | blackbox |
| prometheus:9090 | prometheus | self |

## HTML File Types

| Prefix | Example | Generator | Size |
|--------|---------|-----------|------|
| `tower_` | tower_192_168_10_20_9100.html | prom_tower_dashboard_html.sh | 4-9 KB |
| `vm_dashboard_` | vm_dashboard_192_168_10_20_9100.html | prom_vm_dashboard_html.sh | 32-34 KB |
| `win_` | win_192_168_1_253_9182.html | prom_win_html_192_168_1_253_9182.sh | ~6 KB |
| `vps_` | vps_31_170_165_94.html | prom_vps_html_31_170_165_94.sh | ~6 KB |

> **Note:** Users view `tower_` files for all Linux hosts. `vm_dashboard_` files are also maintained but not the primary view.
