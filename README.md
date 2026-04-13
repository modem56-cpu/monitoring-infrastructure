# Prometheus Monitoring Platform

On-premise infrastructure monitoring using Prometheus, Grafana, Wazuh SIEM, node_exporter, custom textfile collectors, and auto-generated HTML dashboards.

**Hub:** `192.168.10.20` (wazuh-server)  
**Grafana:** `http://192.168.10.20:3000`  
**HTML Dashboard:** `http://192.168.10.20:8088/`  
**JSON Report:** `http://192.168.10.20:8088/monitoring_report.json`  
**Refresh interval:** 3 minutes (systemd timers)  
**Repository:** `https://github.com/modem56-cpu/monitoring-infrastructure`

---

## Monitored Endpoints

| Host | IP | Role | Exporter | Wazuh Agent | Health |
|------|----|------|----------|-------------|--------|
| wazuh-server | 192.168.10.20 | SIEM / Monitoring Hub | node_exporter :9100 (Docker) + sys_sample | 000 (manager) | UP |
| unraid-tower | 192.168.10.10 | NAS / Hypervisor | node_exporter :9100 (native) | 005 | UP |
| vm-devops | 192.168.5.131 | Ubuntu DevOps VM | node_exporter :9100 (native) | 004 | UP |
| win11-vm | 192.168.1.253 | Windows Endpoint | windows_exporter :9182 | 003 | UP |
| movement-strategy | 31.170.165.94 / VPN 10.253.2.22 | Hostinger VPS | SSH collector (vps_* metrics) | 006 | UP |
| fathom-vault | 192.168.10.24 | Ubuntu VM | node_exporter + sys_sample + sys_topproc | 007 | UP |
| UDM Pro | 192.168.10.1 | Gateway / Firewall | SNMP (if_mib) + blackbox + syslog->Wazuh | syslog only | UP |

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
├── docker-compose.yml         # Docker stack
├── alertmanager.yml           # Alertmanager configuration
├── blackbox.yml               # Blackbox exporter config
├── rules/                     # Prometheus alerting & recording rules
├── targets/                   # Prometheus file_sd targets
├── bin/                       # Collection, generation, and utility scripts
├── backup/                    # Configuration backups
└── *.sh                       # Root-level generation and patch scripts
```

---

## Quick Reference

### Grafana Dashboards

| Dashboard | URL |
|-----------|-----|
| Fleet Overview | `http://192.168.10.20:3000/d/fleet-overview` |
| Node Exporter Full | `http://192.168.10.20:3000/d/node-exporter-full` |
| Windows Exporter | `http://192.168.10.20:3000/d/windows-exporter` |
| Movement Strategy VPS | `http://192.168.10.20:3000/d/vps-movement-strategy` |
| UDM Pro | `http://192.168.10.20:3000/d/udm-pro` |
| Docker Containers & APIs | `http://192.168.10.20:3000/d/docker-containers` |
| Akvorado Flow Pipeline | `http://192.168.10.20:3000/d/akvorado` |
| Google Workspace | `http://192.168.10.20:3000/d/google-workspace` |
| HTML Reports Hub | `http://192.168.10.20:3000/d/html-reports` |
| Export Reports | `http://192.168.10.20:3000/d/export-reports` |

### HTML Dashboard URLs

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
| Alerting rules | `/opt/monitoring/rules/` |
| Recording rules | `/opt/monitoring/rules/recording.rules.yml` |
| JSON report generator | `/opt/monitoring/generate-report.py` |

### Docker Stack

All core services run via Docker Compose on `192.168.10.20`:

| Container | Port | Purpose |
|-----------|------|---------|
| `prometheus` | 9090 (localhost) | TSDB + scraping (90-day retention, admin API enabled) |
| `grafana` | 3000 (LAN) | Historical dashboards (10 dashboards) |
| `alertmanager` | 9093 (localhost) | Alert routing (webhook receiver) |
| `node-exporter` | internal only | Local host metrics + textfile collector |
| `blackbox-exporter` | 9115 | ICMP/TCP/HTTP probes (incl. http_2xx_selfsigned for UDM) |
| `snmp-exporter` | 9116 | UDM Pro SNMP metrics |
| `cadvisor` | 8080 | Per-container Docker metrics |

Networks: `monitoring` + `akvorado_default`

### Prometheus Stats

| Stat | Value |
|------|-------|
| Scrape targets | 23 (22 up, 1 down when fathom offline) |
| Alerting rules | 30 across blackbox, infrastructure, containers, akvorado |
| Recording rules | 19 in recording.rules.yml |
| Retention | 90 days |

### Wazuh SIEM

| Component | Details |
|-----------|---------|
| Active agents | 6 (000, 003, 004, 005, 006, 007) |
| Custom decoders | udm_firewall.xml |
| Custom rules | prometheus_monitoring.xml (100300-100307), udm_firewall.xml (100400-100407), google_workspace.xml (100500-100508) |
| auditd rules | 20+ (identity, SSH keys, priv-esc, root commands, cron, systemd, Docker, WireGuard, kernel modules) |
| FIM paths | /root/.ssh, crontabs, /etc/wireguard, docker-compose.yml, prometheus.yml |
| Active Response | firewall-drop on SSH brute force (rule 5763, 1hr block) |
| Vulnerability Detection | Enabled (60m feed updates) |
| SCA | Enabled (12h interval, CIS benchmarks) |
| UDM Pro syslog | UDP 514 from 192.168.10.1 |
| Prom->Wazuh bridge | prom-to-wazuh.sh every 60s, 7 alert types |

### Systemd Timers (10)

| Timer | Interval | Purpose |
|-------|----------|---------|
| sys-sample-prom | 15s | System sample metrics |
| sys-topproc | 60s | Top process metrics |
| prom-to-wazuh | 60s | Prometheus->Wazuh bridge |
| prom-html-dashboards | 3min | Base HTML dashboard generation |
| prom-refresh-html | 3min | VM dashboard + patches |
| topproc-generate | 60s | Top process HTML generation |
| gworkspace-collector | 5min | Google Workspace metrics |
| monitoring-report | 5min | JSON report generation |
| akvorado-mesh-to-wazuh | 5min | Akvorado->Wazuh bridge |
