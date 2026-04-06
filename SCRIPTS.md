# Script Inventory

## Systemd Services & Timers

| Unit | Interval | Purpose |
|------|----------|---------|
| `prom-html-dashboards.timer` | 3 min | Triggers tower_ HTML base generation |
| `prom-html-dashboards.service` | oneshot | Runs update_all_dashboards.sh + patch chain |
| `prom-refresh-html.timer` | 3 min | Triggers vm_dashboard_ HTML generation |
| `prom-refresh-html.service` | oneshot | Runs prom_refresh_all_html.sh + patch chain |

## ExecStartPost Drop-ins

### prom-html-dashboards.service.d/
| File | Script | Action |
|------|--------|--------|
| `10-nocache.conf` | patch_reports_nocache.sh | Inject Cache-Control headers |
| `20-nocache.conf` | patch_reports_nocache.sh | (duplicate) |
| `30-perms.conf` | inline chmod/chown | Fix file permissions on reports/ |
| `30-unraid.conf` | patch_reports_unraid.sh | Unraid array/temp data |
| `40-final.conf` | patch_reports_final.sh | Full extras patch chain |

### prom-refresh-html.service.d/
| File | Script | Action |
|------|--------|--------|
| `40-topcpu.conf` | fix_top_cpu_tables.sh | CPU table for 10.24, 10.10 |
| `99-final.conf` | patch_reports_final.sh | Full extras patch chain |

## Generation Scripts (`/opt/monitoring/bin/`)

| Script | Output | Description |
|--------|--------|-------------|
| `update_all_dashboards.sh` | tower_*.html ×4 | Calls prom_tower_dashboard_html.sh for each target |
| `prom_tower_dashboard_html.sh` | tower_*.html | Base tower HTML from Prometheus API |
| `prom_refresh_all_html.sh` | vm_dashboard_*.html | Generates rich vm_dashboard format |
| `prom_vm_dashboard_html.sh` | vm_dashboard_*.html | Rich HTML with grids (32-34 KB) |
| `prom_win_html_192_168_1_253_9182.sh` | win_1_253.html | Full Windows HTML regen |
| `prom_vps_html_31_170_165_94.sh` | vps_165_94.html | Full VPS HTML regen |
| `collect_vm_ms_ssh.sh` | vps_*.prom | SSH pull from VPS metrics user |
| `sys-sample-prom.sh` | sys_sample_*.prom | CPU/mem/net/disk textfile collector |
| `sys-topproc-prom.sh` | sys_topproc_*.prom | Top-15 process textfile collector |

## Patch Scripts (`/usr/local/bin/`)

| Script | Target File | Injects |
|--------|-------------|---------|
| `patch_reports_final.sh` | (orchestrator) | Calls all extras scripts in order |
| `patch_reports_wazuh_extras.sh` | tower_192_168_10_20 | sys_sample + SSH table + Top CPU |
| `patch_reports_ubuntu_5_131_extras.sh` | tower_192_168_5_131 | sys_sample + SSH table + Top CPU |
| `patch_reports_ubuntu_10_24_extras.sh` | tower_192_168_10_24 | sys_sample + SSH table + Top CPU |
| `patch_reports_unraid.sh` | tower_192_168_10_10 | Unraid array/cache/temp data |
| `patch_reports_unraid_details_10_10.sh` | tower_192_168_10_10 | Unraid detail block |
| `patch_reports_nocache.sh` | all *.html | Cache-Control no-cache headers |
| `fix_top_cpu_tables.sh` | tower_10_24, tower_10_10 | Top CPU table (dedup-safe) |

## Metric Naming Conventions

| Prefix | Source | Description |
|--------|--------|-------------|
| `sys_sample_` | textfile (sys-sample-prom.sh) | System snapshot metrics |
| `sys_topproc_` | textfile (sys-topproc-prom.sh) | Per-process CPU/mem/RSS |
| `tower_ssh_sessions_` | textfile | Active SSH sessions per user/IP |
| `node_` | node_exporter | Standard Linux OS metrics |
| `windows_` | windows_exporter | Windows WMI metrics |
| `wg_` | textfile | WireGuard peer metrics |

## HTML Comment Markers (Idempotency)

| Marker | Host | Section |
|--------|------|---------|
| `<!-- SYS_SAMPLE_V2_WAZUH -->` | 10.20 | System sample card |
| `<!-- SSH_TABLE_V2_WAZUH -->` | 10.20 | SSH sessions table |
| `<!-- TOP_CPU_V1_WAZUH -->` | 10.20 | Top CPU processes |
| `<!-- SYS_SAMPLE_V2_UBUNTU_5_131 -->` | 5.131 | System sample card |
| `<!-- SSH_TABLE_V2_UBUNTU_5_131 -->` | 5.131 | SSH sessions table |
| `<!-- TOP_CPU_V1_UBUNTU_5_131 -->` | 5.131 | Top CPU processes |
| `<!-- SYS_SAMPLE_V2_UBUNTU_10_24 -->` | 10.24 | System sample card |
| `<!-- SSH_TABLE_V2_UBUNTU_10_24 -->` | 10.24 | SSH sessions table |
| `<!-- TOP_CPU_V1_UBUNTU_10_24 -->` | 10.24 | Top CPU processes |
| `<!-- TOP_CPU_TABLE_V2 -->` | 10.24, 10.10 | CPU table (fix_top_cpu_tables) |
