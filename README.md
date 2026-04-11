# Prometheus Monitoring Platform

On-premise infrastructure monitoring using Prometheus, node_exporter, custom textfile collectors, and auto-generated HTML dashboards.

**Hub:** `192.168.10.20` (wazuh-server)  
**Dashboard:** `http://192.168.10.20:8088/`  
**Refresh interval:** 3 minutes (systemd timers)  
**Repository:** `https://github.com/modem56-cpu/monitoring-infrastructure`

---

## Monitored Endpoints

| Host | IP | Role | Exporter | Health |
|------|----|------|----------|--------|
| wazuh-server | 192.168.10.20 | SIEM / Monitoring Hub | node_exporter :9100 (Docker) | UP |
| fathom-vault-server | 192.168.10.24 | Ubuntu VM | node_exporter :9100 | DOWN (VM off) |
| vm-devops | 192.168.5.131 | Ubuntu DevOps VM | node_exporter :9100 | UP |
| unraid-tower | 192.168.10.10 | NAS / Hypervisor | node_exporter :9100 | UP |
| Windows Workstation | 192.168.1.253 | Windows Endpoint | windows_exporter :9182 | UP |
| VPS | 31.170.165.94 | Hostinger VPS | SSH pull (metrics user) | UP |
| Router | 192.168.10.1 | Gateway | blackbox ICMP/HTTP/TCP | UP |

---

## Repository Structure

```
monitoring-infrastructure/
├── README.md                  # This file
├── ARCHITECTURE.md            # System architecture and data flow
├── WORKFLOW.md                # ASCII workflow diagram
├── SCRIPTS.md                 # Script inventory and responsibilities
├── ACCOMPLISHMENTS.md         # Leadership accomplishment report
├── TODO.md                    # Next steps and roadmap
├── wazuh-siem-integration.md  # Wazuh SIEM integration plan
├── prometheus.yml             # Prometheus configuration
├── docker-compose.yml         # Docker stack (node-exporter, prometheus, blackbox, grafana)
├── blackbox.yml               # Blackbox exporter config
├── rules/                     # Prometheus alerting rules
├── targets/                   # Prometheus file_sd targets
├── bin/                       # Collection, generation, and utility scripts
├── backup/                    # Configuration backups
└── *.sh                       # Root-level generation and patch scripts
```

---

## Quick Reference

### Dashboard URLs

| Host | URL |
|------|-----|
| wazuh-server (10.20) | `http://192.168.10.20:8088/tower_192_168_10_20_9100.html` |
| fathom-vault (10.24) | `http://192.168.10.20:8088/tower_192_168_10_24_9100.html` |
| vm-devops (5.131) | `http://192.168.10.20:8088/tower_192_168_5_131_9100.html` |
| Unraid Tower (10.10) | `http://192.168.10.20:8088/tower_192_168_10_10_9100.html` |
| Windows (1.253) | `http://192.168.10.20:8088/win_192_168_1_253_9182.html` |
| VPS (165.94) | `http://192.168.10.20:8088/vps_31_170_165_94.html` |

### Key Paths

| Resource | Path |
|----------|------|
| HTML reports | `/opt/monitoring/reports/` |
| Patch scripts | `/usr/local/bin/patch_reports_*.sh` |
| Collection scripts | `/opt/monitoring/bin/` |
| Textfile metrics | `/opt/monitoring/textfile_collector/` |
| SSH keys (VPS) | `/opt/monitoring/sshkeys/` |
| Prometheus config | `/opt/monitoring/prometheus.yml` (mounted into Docker) |
| Docker Compose | `/opt/monitoring/docker-compose.yml` |

### Docker Stack

All core services run via Docker Compose on `192.168.10.20`:

| Container | Port | Purpose |
|-----------|------|---------|
| `node-exporter` | 9100 | Local host metrics + textfile collector |
| `prometheus` | 9090 (localhost) | TSDB + scraping |
| `blackbox-exporter` | 9115 | ICMP/TCP/HTTP probes |
| `grafana` | 3000 (localhost) | Historical dashboards |
