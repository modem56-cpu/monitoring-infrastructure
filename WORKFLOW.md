# Operational Workflow

## Full End-to-End Data Flow

```
╔══════════════════════════════════════════════════════════════════╗
║              COLLECTION  (every 15s — Prometheus scrape)         ║
╚══════════════════════════════════════════════════════════════════╝

  Each Linux host runs:
  ┌─────────────────────────────────────────┐
  │  /opt/monitoring/bin/sys-sample-prom.sh │  → sys_sample_*.prom
  │  /opt/monitoring/bin/sys-topproc-prom.sh│  → sys_topproc_*.prom
  │  tower_ssh_sessions_local.sh            │  → tower_ssh_sessions_*.prom
  └─────────────────────────────────────────┘
          │ node_exporter reads textfile dir
          ▼
  Prometheus scrapes :9100  →  TSDB storage

  VPS (31.170.165.94) — SSH pull model:
  ┌───────────────────────────────────────────────┐
  │  collect_vm_ms_ssh.sh (timeout 30s)           │
  │    ssh metrics@31.170.165.94 (forced command) │
  │    → vps_31_170_165_94.prom                   │
  └───────────────────────────────────────────────┘

  Windows (192.168.1.253):
  ┌───────────────────────────────────────┐
  │  windows_exporter :9182               │
  │  Prometheus scrapes → windows_* TSDB  │
  └───────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════╗
║              HTML GENERATION  (every 3 minutes)                  ║
╚══════════════════════════════════════════════════════════════════╝

  ┌─────────────────────────────────────────────────────────────┐
  │  TIMER A: prom-html-dashboards.timer                        │
  │                                                             │
  │  [ExecStart]  update_all_dashboards.sh                      │
  │    └─ prom_tower_dashboard_html.sh  ×4 targets              │
  │         Queries Prometheus API → renders tower_*.html       │
  │         Sections: header, SSH count, Top RSS, Docker list   │
  │         Output: ~3-5 KB bare HTML                           │
  │                                                             │
  │  [Post 10] patch_reports_nocache.sh  (cache headers)        │
  │  [Post 20] patch_reports_nocache.sh  (duplicate, harmless)  │
  │  [Post 30] chmod 0755 reports/ ; chown wazuh-admin          │
  │  [Post 30] patch_reports_unraid.sh  (Unraid array/temps)    │
  │  [Post 40] patch_reports_final.sh ──────────────────────┐   │
  └─────────────────────────────────────────────────────────┼───┘
                                                            │
  ┌─────────────────────────────────────────────────────────┼───┐
  │  TIMER B: prom-refresh-html.timer                       │   │
  │                                                         │   │
  │  [ExecStart]  prom_refresh_all_html.sh                  │   │
  │    └─ prom_vm_dashboard_html.sh ×2                      │   │
  │         → vm_dashboard_192_168_10_20_9100.html          │   │
  │         → vm_dashboard_192_168_5_131_9100.html          │   │
  │                                                         │   │
  │  [Post 40] fix_top_cpu_tables.sh                        │   │
  │    targets: 10.24, 10.10                                │   │
  │    injects: <!-- TOP_CPU_TABLE_V2 --> block             │   │
  │                                                         │   │
  │  [Post 99] patch_reports_final.sh ──────────────────────┘   │
  └─────────────────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════╗
║         patch_reports_final.sh  —  PATCH CHAIN                   ║
╚══════════════════════════════════════════════════════════════════╝

  Step 1  tower_ssh_sessions_local.sh
          └─ Updates SSH session textfile metrics for 10.20

  Step 2  patch_reports_wazuh_extras.sh  →  tower_192_168_10_20
          ├─ De-dup: remove old <!-- SYS_SAMPLE_V2_WAZUH --> blocks
          ├─ De-dup: remove old <!-- TOP_CPU_TABLE_V2 --> blocks
          ├─ Query Prometheus for sys_sample_* + node_* fallbacks
          ├─ Query tower_ssh_sessions_user_src{target="192.168.10.20"}
          ├─ Query sys_topproc_cpu_percent / rss_kb (comm label)
          └─ Inject before Top Processes by RSS:
               <!-- SYS_SAMPLE_V2_WAZUH --> card
               <!-- SSH_TABLE_V2_WAZUH --> card
               <!-- TOP_CPU_V1_WAZUH --> card

  Step 3  prom_win_html_192_168_1_253_9182.sh
          └─ Full HTML regen from Prometheus → win_192_168_1_253_9182.html

  Step 4  collect_vm_ms_ssh.sh  (timeout: ssh-keyscan 15s, ssh 30s)
          └─ SSH to metrics@31.170.165.94
             forced command returns Prom exposition → vps_*.prom

  Step 5  prom_vps_html_31_170_165_94.sh
          └─ Full HTML regen → vps_31_170_165_94.html

  Step 6  patch_reports_ubuntu_5_131_extras.sh  →  tower_192_168_5_131
          └─ Same pattern as Step 2 (markers: UBUNTU_5_131)

  Step 7  patch_reports_ubuntu_10_24_extras.sh  →  tower_192_168_10_24
          ├─ Same pattern (markers: UBUNTU_10_24)
          ├─ No swap line when swap_total = 0
          ├─ first_nonzero() for disk read totals
          └─ root_pct queries sys_sample_fs_root_percent as fallback

  Step 8  patch_reports_unraid_details_10_10.sh  →  tower_192_168_10_10
          └─ Injects Unraid array/cache/disk detail block

  Step 9  patch_reports_unraid.sh  →  tower_192_168_10_10
          └─ Refreshes Unraid parity/temp/util data


╔══════════════════════════════════════════════════════════════════╗
║              SERVING                                             ║
╚══════════════════════════════════════════════════════════════════╝

  Browser  →  http://192.168.10.20:8088/tower_*.html
              Cache-Control: no-cache (always fresh)
              Files: /opt/monitoring/reports/


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
```
