# Yokly/Agapay Infrastructure Monitoring Platform

**Last updated: April 18, 2026**

On-premise + cloud monitoring using Prometheus, Grafana, Wazuh SIEM, Akvorado network flow analysis, custom textfile collectors, and auto-generated HTML dashboards. Managed by Brian Monte (IT Admin).

**Hub:** `192.168.10.20` (wazuh-server, Ubuntu 24.04, 8 GB RAM, 4 CPU)  
**Grafana:** `http://192.168.10.20:3000`  
**Akvorado Console:** `http://192.168.10.20:8082`  
**HTML Dashboard:** `http://192.168.10.20:8088/`  
**JSON Report:** `http://192.168.10.20:8088/monitoring_report.json`  
**Refresh interval:** 3–5 minutes (systemd timers)  
**Repository:** `https://github.com/modem56-cpu/monitoring-infrastructure`

---

## Monitored Infrastructure

| Host | IP | Role | Exporter | Wazuh Agent | Status |
|------|----|------|----------|-------------|--------|
| wazuh-server | 192.168.10.20 | SIEM / Monitoring Hub | node_exporter :9100 (Docker) + sys_sample | 000 (manager) | UP |
| vm-devops | 192.168.5.131 | Ubuntu DevOps VM | node_exporter :9100 (native) | 001 | UP |
| unraid-tower | 192.168.10.10 | NAS / Hypervisor | node_exporter :9100 (native) | 002 | UP |
| movement-strategy | 31.170.165.94 / VPN 10.253.2.22 | Hostinger VPS | SSH collector (vps_* metrics) | 003 | UP |
| win11-vm | 192.168.1.253 | Windows Endpoint | windows_exporter :9182 | 004 | UP |
| fathom-vault | 192.168.10.24 | Ubuntu VM | node_exporter + sys_sample + sys_topproc | 005 | UP |
| UDM Pro | 192.168.10.1 | Gateway / Firewall | SNMP (if_mib) + blackbox + syslog→Wazuh + ARP→Akvorado | syslog only | UP |
| Google Workspace | cloud | SaaS (Yokly/Agapay) | gworkspace-collector v2 (API) | — | UP |

**Network Inventory (via UDM ARP Collector v2):** 90 ARP entries, 80 MAC baseline, 4 VLANs (LAN, SecurityApps, Dev, VLAN4) — new devices trigger Wazuh alerts.

---

## Platform Components

### Prometheus Monitoring
- **23 scrape targets** — 7 hosts + SNMP + blackbox + cAdvisor + Akvorado + self
- **39 alerting rules** across `blackbox.rules.yml`, `infrastructure.rules.yml`, `containers.rules.yml`, `akvorado.rules.yml`, `vmbackup.rules.yml`, `network.rules.yml`
- **19 recording rules** in `recording.rules.yml`
- **90-day retention**, admin API enabled

### Grafana Dashboards (12)

| Dashboard | URL | Description |
|-----------|-----|-------------|
| Fleet Overview | `/d/fleet-overview` | All nodes, CPU/mem/disk, Docker, APIs, WAN, SSH, Google Workspace |
| Node Exporter Full | `/d/node-exporter-full` | 31-panel Linux deep-dive |
| Windows Exporter | `/d/windows-exporter` | 22-panel Windows dashboard |
| Movement Strategy VPS | `/d/vps-movement-strategy` | SSH-collected VPS metrics |
| UDM Pro | `/d/udm-pro` | SNMP interfaces, traffic, status |
| Docker Containers & APIs | `/d/docker-containers` | cAdvisor + API health probes |
| Akvorado Flow Pipeline | `/d/akvorado` | Inlet/outlet/orchestrator, flow rates, Kafka, ClickHouse (12 panels) |
| Google Workspace | `/d/google-workspace` | Users, storage, shared drives, events, 50GB enforcement |
| VM Backups | `/d/vm-backups` | Unraid VM backup age, size, health, definition status |
| Network Inventory & Audit | `/d/network-inventory` | ARP devices, MAC baseline, new device alerts, ARP conflicts |
| HTML Reports Hub | `/d/html-reports` | Embedded HTML dashboards |
| Export Reports | `/d/export-reports` | JSON download for AI analysis |

### Akvorado Network Flow Analysis

| Component | Details |
|-----------|---------|
| Console | `http://192.168.10.20:8082` — flow search, top talkers, protocol analysis |
| Flow sources | UDM Pro (IPFIX :4739, NetFlow :2055, sFlow :6343) |
| Pipeline | UDM Pro → Inlet → Kafka → ClickHouse (flows_5m0s, flows_1h0m0s) |
| Network enrichment | Static subnets (LAN/SecurityApps/Dev/VLAN4) + per-device /32 from UDM ARP |
| Device enrichment | 93 devices: hostname (rDNS), VLAN tenant, vendor (OUI) |
| Dictionary | 5.4M entries in ClickHouse `default.networks` (1.21 GiB) |
| Console fields | Src/Dst Net Name (hostname), Src/Dst Net Tenant (VLAN), Src/Dst Net Role (vendor) |

### Network Device Inventory
- **90 ARP devices** across 4 VLANs (LAN, SecurityApps, Dev, VLAN4)
- **80 MAC baseline** established April 18, 2026 — new devices trigger Wazuh alerts
- **ARP conflict detection** — same IP → different MAC triggers level 12 (potential ARP spoofing)
- HTML inventory at `http://192.168.10.20:8088/network_inventory.html`
- Grafana dashboard: Network Inventory & Audit (UID: network-inventory)

### Wazuh SIEM

| Component | Details |
|-----------|---------|
| Active agents | 6 (000 manager, 001 vm-devops, 002 unraid-tower, 003 movement-strategy, 004 win11-vm, 005 fathom-vault) |
| Custom rules | 100300–100307 (Prometheus), 100400–100407 (UDM), 100500–100508 (Google Workspace), 100700–100707 (Network Inventory) |
| auditd | 20+ rules: identity, SSH keys, priv-esc, root, cron, systemd, Docker, WireGuard, kernel |
| FIM | /root/.ssh, crontabs, /etc/wireguard, docker-compose.yml, prometheus.yml |
| Active Response | firewall-drop on SSH brute force (rule 5763, 1hr block) |
| Bridges | prom-to-wazuh.sh (60s, 7 alert types), akvorado-mesh-to-wazuh (5min) |
| Vulnerability Detection | Enabled, 60m feed updates |
| SCA | CIS benchmarks, 12h interval |

### Google Workspace Integration (v2)

| Setting | Value |
|---------|-------|
| Collector version | v2 (group-based extshare enforcement, April 15 2026) |
| Org | Yokly / Agapay (91 active users, 95 total) |
| APIs | Admin Reports v1, Directory v1, Alert Center v1beta1, Drive v3 |
| Org storage | ~1.16 TB used |
| Shared drives | 29 drives |
| 50GB enforcement | Active; exemptions for 6 users |
| ExtShare model | Group-based BLOCKED (hrou, itdevou, marketingou, trainingou) + exception OU |
| ExtShare state (Apr 15) | 58 unrestricted, 22 blocked, 3 exception OU |

---

## Repository Structure

```
monitoring-infrastructure/
├── README.md                    # This file — quick reference
├── ARCHITECTURE.md              # System architecture and data flow
├── WORKFLOW.md                  # End-to-end data flow diagrams
├── SCRIPTS.md                   # Script inventory
├── ACCOMPLISHMENTS.md           # Leadership accomplishment report
├── TODO.md                      # Roadmap and pending items
├── wazuh-siem-integration.md    # Wazuh SIEM integration notes
├── prometheus.yml               # Prometheus configuration
├── docker-compose.yml           # Docker stack
├── alertmanager.yml             # Alertmanager configuration
├── blackbox.yml                 # Blackbox exporter config
├── rules/                       # Prometheus alerting & recording rules
├── targets/                     # Prometheus file_sd targets
├── bin/                         # Collection, generation, utility scripts
│   ├── udm-arp-collector.py     # UDM ARP → Prometheus + Akvorado JSON
│   ├── json-server.py           # HTTP/1.0 server for Akvorado network-sources
│   ├── gworkspace-collector-v2.py
│   └── ...
├── data/                        # Live data files (network_devices.json)
├── textfile_collector/          # Prometheus textfile metrics (*.prom)
├── reports/                     # Generated HTML dashboards
└── *.sh / *.py                  # Deploy and utility scripts
```

---

## Key Paths

| Resource | Path |
|----------|------|
| Prometheus config | `/opt/monitoring/prometheus.yml` |
| Docker Compose | `/opt/monitoring/docker-compose.yml` |
| Alerting rules | `/opt/monitoring/rules/` |
| Collection scripts | `/opt/monitoring/bin/` |
| Textfile metrics | `/opt/monitoring/textfile_collector/` |
| Network devices JSON | `/opt/monitoring/data/network_devices.json` |
| HTML reports | `/opt/monitoring/reports/` |
| Akvorado config | `/opt/akvorado/config/akvorado.yaml` |
| ClickHouse server.xml | `/opt/akvorado/docker/clickhouse/server.xml` |
| Wazuh custom rules | `/var/ossec/etc/rules/` |
| Wazuh custom decoders | `/var/ossec/etc/decoders/` |

---

## Systemd Timers (11)

| Timer | Interval | Purpose |
|-------|----------|---------|
| sys-sample-prom | 15s | System sample metrics (CPU/mem/net/disk) |
| sys-topproc | 60s | Top process metrics |
| prom-to-wazuh | 60s | Prometheus → Wazuh SIEM bridge |
| topproc-generate | 60s | Top process HTML generation |
| prom-html-dashboards | 3min | Base HTML dashboard generation |
| prom-refresh-html | 3min | VM dashboard + patch chain |
| gworkspace-collector | 5min | Google Workspace metrics collection (v2) |
| monitoring-report | 5min | JSON report generation |
| akvorado-mesh-to-wazuh | 5min | Akvorado → Wazuh bridge |
| **udm-arp-collector** | **5min** | **UDM ARP → Prometheus textfile + Akvorado JSON** |
| device-json-server | always | Serves network_devices.json on :9117 for Akvorado |

---

## Docker Stack (core services on 192.168.10.20)

| Container | Port | Purpose |
|-----------|------|---------|
| `prometheus` | 9090 (localhost) | TSDB + scraping, 90-day retention |
| `grafana` | 3000 (LAN) | 12 dashboards |
| `alertmanager` | 9093 (localhost) | Alert routing (webhook receiver) |
| `node-exporter` | internal | Host metrics + textfile collector |
| `blackbox-exporter` | 9115 | ICMP/TCP/HTTP probes |
| `snmp-exporter` | 9116 | UDM Pro SNMP (if_mib) |
| `cadvisor` | 8080 | Per-container Docker metrics |
| `akvorado-inlet` | 4739/2055/6343 UDP | IPFIX/NetFlow/sFlow receiver |
| `akvorado-orchestrator` | 8080 (internal) | Config + network enrichment |
| `akvorado-console` | 8082 (LAN) | Flow analysis UI |
| `akvorado-clickhouse` | 9000 (internal) | Flow storage (5.4M network entries) |
| `akvorado-kafka` | 9092 (internal) | Flow message queue |
