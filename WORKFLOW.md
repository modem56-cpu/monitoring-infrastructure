# Operational Workflow

## Full End-to-End Data Flow

```
╔══════════════════════════════════════════════════════════════════╗
║              COLLECTION  (every 15s — Prometheus scrape)         ║
╚══════════════════════════════════════════════════════════════════╝

  wazuh-server (192.168.10.20) — Docker stack:
  ┌─────────────────────────────────────────────────┐
  │  prometheus (:9090)  — 23 scrape targets        │
  │  grafana (:3000)     — 10 dashboards            │
  │  alertmanager (:9093) — webhook receiver         │
  │  node-exporter (:9100, internal)                │
  │  blackbox-exporter   — ICMP/TCP/HTTP probes     │
  │  snmp-exporter       — UDM Pro SNMP (if_mib)    │
  │  cadvisor (:8080)    — per-container metrics     │
  │                                                 │
  │  mounts /opt/monitoring/textfile_collector:ro    │
  │  Prometheus scrapes via Docker DNS              │
  │  (node-exporter:9100 → relabel 192.168.10.20)  │
  │  Networks: monitoring + akvorado_default         │
  └─────────────────────────────────────────────────┘

  Each Linux host runs locally:
  ┌─────────────────────────────────────────┐
  │  sys-sample-prom.sh   → sys_sample.prom │
  │  sys-topproc-prom.sh  → sys_topproc.prom│
  │  tower_textfile_extras.sh (or local.sh) │
  │    → tower_ssh_sessions.prom            │
  │    → tower_extras.prom                  │
  └─────────────────────────────────────────┘
          │ node_exporter reads textfile dir
          ▼
  Prometheus scrapes :9100  →  TSDB storage (90-day retention)

  VPS (31.170.165.94) — SSH pull via WireGuard VPN:
  ┌───────────────────────────────────────────────┐
  │  collect_vm_ms_ssh.sh (timeout 30s)           │
  │    ssh metrics@10.253.2.22 (VPN, wg2 tunnel)  │
  │    → vps_31_170_165_94.prom                   │
  │    StrictHostKeyChecking=yes                   │
  │    known_hosts: /opt/monitoring/sshkeys/       │
  └───────────────────────────────────────────────┘

  Windows (192.168.1.253):
  ┌───────────────────────────────────────┐
  │  windows_exporter :9182               │
  │  + textfile: sys_topproc.prom         │
  │  + textfile: win_sessions.prom        │
  │  Prometheus scrapes → windows_* TSDB  │
  └───────────────────────────────────────┘

  UDM Pro (192.168.10.1):
  ┌───────────────────────────────────────────┐
  │  SNMP (if_mib) → snmp-exporter           │
  │  Blackbox: ICMP + TCP + HTTP              │
  │    (http_2xx_selfsigned for HTTPS)        │
  │  Syslog → Wazuh (UDP 514)                │
  │    Custom decoder: udm_firewall.xml       │
  │    Custom rules: 100400-100407            │
  └───────────────────────────────────────────┘

  Google Workspace (every 5min):
  ┌────────────────────────────────────────────────┐
  │  gworkspace-collector v2 timer                 │
  │    SA: gam-project@...gserviceaccount.com      │
  │    APIs: Admin Reports v1, Directory v1,       │
  │           Alert Center v1beta1, Drive v3       │
  │    → Login/admin/drive audit events            │
  │    → Per-user Drive/Gmail/Photos storage split │
  │       (accounts:drive_used_quota_in_mb,        │
  │        accounts:gmail_used_quota_in_mb,        │
  │        accounts:gplus_photos_used_quota_in_mb) │
  │    → Org totals: ~1.16 TB used / 95 users      │
  │    → External sharing (group-based v2):        │
  │       BLOCKED: hrou, itdevou, marketingou,     │
  │                trainingou groups               │
  │       EXCEPTION OU: SHARED-DRIVES-EXTERNAL     │
  │       State (Apr 15): 58 unrestricted,         │
  │                       22 blocked, 3 exception  │
  │    → 50GB storage enforcement alerts           │
  │    → 29 shared drives via quotaBytesUsed       │
  │    → Security alerts via Alert Center API      │
  └────────────────────────────────────────────────┘

  UDM ARP Collector (every 5 min — udm-arp-collector.timer):
  ┌────────────────────────────────────────────────────────┐
  │  udm-arp-collector.py                                  │
  │    SNMP ARP (OID 1.3.6.1.2.1.4.22.1.2)                │
  │    + OUI vendor (/usr/share/ieee-data/oui.txt, 194K)   │
  │    + rDNS hostname (socket.gethostbyaddr, 1s timeout)  │
  │    90–94 devices across 4 VLANs:                       │
  │      br0=LAN, br10=SecurityApps, br4=VLAN4, br5=Dev    │
  │                                                        │
  │  → network_devices.prom  (Prometheus textfile)         │
  │      network_device_info{ip,mac,vlan,vendor,hostname}  │
  │      network_device_count{vlan}                        │
  │                                                        │
  │  → network_devices.json  (Akvorado enrichment feed)    │
  │      [{ip, hostname, vendor, vlan, vlan_id, mac}]      │
  └────────────────────────────────────────────────────────┘
         │
         ▼  device-json-server.service (HTTP/1.0, :9117)
  ┌────────────────────────────────────────────────────────┐
  │  UFW allows 247.16.14.0/24 (akvorado bridge) → :9117   │
  │  HTTP/1.0 (no keep-alive) prevents Go client           │
  │  connection-reuse failures in orchestrator             │
  └────────────────────────────────────────────────────────┘

  Akvorado Flow Pipeline:
  ┌────────────────────────────────────────────────────────┐
  │  UDM Pro → IPFIX/NetFlow/sFlow → Inlet (:4739/:2055)  │
  │  → Kafka → ClickHouse (flows_5m0s, flows_1h0m0s)      │
  │                                                        │
  │  Orchestrator polls :9117 every 5 min:                 │
  │    jq: .[] | {prefix: (.ip+"/32"), name: hostname,     │
  │                tenant: .vlan, role: .vendor}            │
  │  + static subnets: 192.168.1.0/24→LAN, etc.           │
  │  → serves networks.csv (205 MB, 5.4M entries)          │
  │  → ClickHouse default.networks dictionary auto-reloads │
  │                                                        │
  │  Flow enrichment at INSERT time (new flows only):      │
  │    SrcNetName   = hostname  (e.g., Calvin-s-S23)       │
  │    SrcNetTenant = VLAN     (e.g., LAN, SecurityApps)   │
  │    SrcNetRole   = vendor   (e.g., ASUSTek)             │
  │                                                        │
  │  3 Prometheus scrape targets (inlet/outlet/orchestr.)  │
  │  6 alert rules + 4 recording rules                     │
  │  Wazuh bridge: AkvoradoDown, NoFlows (every 5min)      │
  │  Console: http://192.168.10.20:8082                    │
  └────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════╗
║              ALERTING & SIEM                                     ║
╚══════════════════════════════════════════════════════════════════╝

  Prometheus (30 alerting rules, 19 recording rules):
  ┌───────────────────────────────────────────────────────────────┐
  │  blackbox.rules.yml      — UDM/endpoint reachability          │
  │  infrastructure.rules.yml — node down, disk, memory, CPU      │
  │  containers.rules.yml    — Docker container health             │
  │  akvorado.rules.yml      — flow pipeline health                │
  │                                                               │
  │  → Alertmanager (:9093)  — webhook receiver                    │
  │  → prom-to-wazuh.sh (60s) — 7 alert types to Wazuh SIEM      │
  └───────────────────────────────────────────────────────────────┘

  Wazuh SIEM (6 agents: 000, 003, 004, 005, 006, 007):
  ┌───────────────────────────────────────────────────────────────┐
  │  Custom rules:                                                │
  │    prometheus_monitoring.xml  (100300-100307)                  │
  │    udm_firewall.xml          (100400-100407)                  │
  │    google_workspace.xml      (100500-100508)                  │
  │                                                               │
  │  auditd: 20+ rules (identity, SSH, priv-esc, Docker, etc.)   │
  │  FIM: SSH keys, crontabs, WireGuard, docker-compose, prom.yml │
  │  Active Response: firewall-drop on brute force (1hr block)    │
  │  Vulnerability Detection: 60m feed updates                    │
  │  SCA: CIS benchmarks, 12h interval                           │
  │  UDM Pro syslog: UDP 514, custom decoder/rules                │
  └───────────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════╗
║        GRAFANA DASHBOARDS (10)                                    ║
╚══════════════════════════════════════════════════════════════════╝

  http://192.168.10.20:3000

  ┌───────────────────────────────────────────────────────────────┐
  │  1. Fleet Overview (/d/fleet-overview)                        │
  │     All nodes, CPU/mem/disk bars, Docker, APIs, WAN, SSH,     │
  │     Google Workspace at-a-glance                              │
  │                                                               │
  │  2. Node Exporter Full (/d/node-exporter-full) — 31 panels   │
  │  3. Windows Exporter (/d/windows-exporter) — 22 panels       │
  │  4. Movement Strategy VPS (/d/vps-movement-strategy)          │
  │  5. UDM Pro (/d/udm-pro) — SNMP interfaces, traffic          │
  │  6. Docker Containers & APIs (/d/docker-containers)           │
  │     cAdvisor + API health probes                              │
  │  7. Akvorado Flow Pipeline (/d/akvorado) — 12 panels         │
  │     Inlet/outlet/orchestrator, flow rates, Kafka, ClickHouse  │
  │  8. Google Workspace (/d/google-workspace)                    │
  │     Users, storage, shared drives, events, 50GB enforcement   │
  │  9. HTML Reports Hub (/d/html-reports)                        │
  │     Embedded HTML dashboards with collapsible rows            │
  │ 10. Export Reports (/d/export-reports)                        │
  │     JSON download for AI analysis                             │
  └───────────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════╗
║        HTML GENERATION  (every 3 minutes — sequential)           ║
╚══════════════════════════════════════════════════════════════════╝

  TIMER A fires → prom-html-dashboards.service runs FIRST:

  ┌─────────────────────────────────────────────────────────────┐
  │  [ExecStart]  update_all_dashboards.sh                      │
  │    ├─ prom_tower_dashboard_html.sh ×4 targets               │
  │    │    (10.10, 10.20, 5.131, 10.24)                        │
  │    │    Queries Prometheus API → renders tower_*.html        │
  │    ├─ collect_vm_ms_ssh.sh → SSH pull VPS metrics            │
  │    └─ prom_vps_html → VPS HTML                              │
  │                                                             │
  │  [Post 10] patch_reports_nocache.sh  (cache headers)        │
  │  [Post 30] chmod/chown reports/                             │
  │  [Post 30] patch_reports_unraid.sh  (array/device table)    │
  │  [Post 40] patch_reports_final.sh  (full patch chain)       │
  └─────────────────────────────────────────────────────────────┘
                         │
                         ▼  After=prom-html-dashboards.service
  ┌─────────────────────────────────────────────────────────────┐
  │  TIMER B → prom-refresh-html.service runs SECOND:           │
  │                                                             │
  │  [ExecStart]  prom_refresh_all_html.sh                      │
  │    ├─ sys-topproc-prom.sh (refresh local textfile)          │
  │    ├─ prom_topproc_generate_all.sh (topproc HTML)           │
  │    └─ prom_vm_dashboard_html.sh ×2 (vm_dashboard files)     │
  │                                                             │
  │  [Post 40] fix_top_cpu_tables.sh                            │
  │  [Post 99] patch_reports_final.sh  (full patch chain)       │
  └─────────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════╗
║         patch_reports_final.sh  —  PATCH CHAIN                   ║
╚══════════════════════════════════════════════════════════════════╝

  Step 1   tower_ssh_sessions_local.sh
           └─ Uses w -h -i to detect remote SSH sessions on 10.20
              Full username resolution via /etc/passwd

  Step 2   patch_reports_wazuh_extras.sh  →  tower_192_168_10_20
           ├─ sys_sample card (CPU/mem/net/disk/filesystem)
           ├─ SSH sessions table (admin IPs tagged)
           └─ Top CPU processes table

  Step 3   prom_win_html_192_168_1_253_9182.sh
           └─ Full Windows HTML (system stats, SSH/SMB tables, processes)

  Step 4   collect_vm_ms_ssh.sh → prom_vps_html_31_170_165_94.sh
           └─ Refresh VPS metrics via SSH + regenerate HTML

  Step 5   patch_reports_ubuntu_5_131_extras.sh  →  tower_192_168_5_131
           └─ sys_sample + SSH table + Top CPU (same pattern)

  Step 6   patch_reports_ubuntu_10_24_extras.sh  →  tower_192_168_10_24
           └─ sys_sample + SSH table + Top CPU (no swap when 0)

  Step 7   patch_reports_unraid_10_10_extras.sh  →  tower_192_168_10_10
           └─ sys_sample + SSH table + Top CPU (no swap when 0)

  Step 8   patch_reports_unraid_details_10_10.sh  →  tower_192_168_10_10
           └─ Uptime, Docker/VM counts, filesystem, hardware info

  Step 9   patch_reports_unraid.sh  →  tower_192_168_10_10
           └─ Array device table (status/temp/SMART/utilization)
              Cache pool + system cache usage


╔══════════════════════════════════════════════════════════════════╗
║              JSON REPORT GENERATOR                                ║
╚══════════════════════════════════════════════════════════════════╝

  /opt/monitoring/generate-report.py (every 5min via monitoring-report timer)
  → http://192.168.10.20:8088/monitoring_report.json

  Contains: node status, system metrics, top processes, network I/O,
  Docker containers, API health, UDM Pro, Akvorado, Google Workspace,
  SSH sessions, Wazuh agents


╔══════════════════════════════════════════════════════════════════╗
║              SERVING                                             ║
╚══════════════════════════════════════════════════════════════════╝

  Browser  →  http://192.168.10.20:8088/tower_*.html
              Cache-Control: no-cache (always fresh)
              Files: /opt/monitoring/reports/

  Grafana  →  http://192.168.10.20:3000/d/<dashboard-id>


╔══════════════════════════════════════════════════════════════════╗
║              SYSTEMD TIMERS (10)                                  ║
╚══════════════════════════════════════════════════════════════════╝

  │ Timer                      │ Interval │ Purpose                            │
  │ sys-sample-prom            │ 15s      │ System sample metrics               │
  │ sys-topproc                │ 60s      │ Top process metrics                 │
  │ prom-to-wazuh              │ 60s      │ Prometheus → Wazuh bridge           │
  │ topproc-generate           │ 60s      │ Top process HTML                    │
  │ prom-html-dashboards       │ 3min     │ Base HTML generation                │
  │ prom-refresh-html          │ 3min     │ VM dashboard + patches              │
  │ gworkspace-collector       │ 5min     │ Google Workspace metrics (v2)       │
  │ monitoring-report          │ 5min     │ JSON report generation              │
  │ akvorado-mesh-to-wazuh     │ 5min     │ Akvorado → Wazuh bridge             │
  │ udm-arp-collector          │ 5min     │ UDM ARP → Prometheus + Akvorado JSON│


╔══════════════════════════════════════════════════════════════════╗
║              IDEMPOTENCY DESIGN                                   ║
╚══════════════════════════════════════════════════════════════════╝

  Each extras script:
  1. Reads current HTML file
  2. Removes any previous version of its own injected blocks (regex on markers)
  3. Finds insertion point: <div before "Top processes (by RSS)">
  4. Inserts fresh data block with HTML comment marker
  5. Writes file atomically

  Marker naming convention:
  <!-- SYS_SAMPLE_V{n}_{HOST} -->   versioned, host-scoped
  <!-- SSH_TABLE_V{n}_{HOST} -->    versioned, host-scoped
  <!-- TOP_CPU_V{n}_{HOST} -->      versioned, host-scoped

  Re-running any script any number of times is safe — no duplication.


╔══════════════════════════════════════════════════════════════════╗
║              RACE CONDITION PREVENTION                            ║
╚══════════════════════════════════════════════════════════════════╝

  Problem (fixed April 2026): Multiple generators overwrote patched HTML.
  Solution:
  1. prom-refresh-html.service has After=prom-html-dashboards.service
  2. Removed root crontab entries that regenerated tower HTML every minute
  3. Removed duplicate tower generators from prom_topproc_generate_all.sh
     and prom_refresh_all_html.sh (tower_10.10, tower_10.24)
  4. Removed obsolete tower-dashboard.service
  5. Only update_all_dashboards.sh generates tower_*.html base files
```
