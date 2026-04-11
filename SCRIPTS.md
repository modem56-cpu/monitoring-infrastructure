# Script Inventory

## Systemd Services & Timers

| Unit | Interval | Purpose |
|------|----------|---------|
| `prom-html-dashboards.timer` | 3 min | Triggers tower_ HTML base generation |
| `prom-html-dashboards.service` | oneshot | Runs update_all_dashboards.sh + patch chain |
| `prom-refresh-html.timer` | 3 min | Triggers vm_dashboard_ HTML generation |
| `prom-refresh-html.service` | oneshot | Runs prom_refresh_all_html.sh + patch chain (After=prom-html-dashboards) |

## ExecStartPost Drop-ins

### prom-html-dashboards.service.d/
| File | Script | Action |
|------|--------|--------|
| `10-nocache.conf` | patch_reports_nocache.sh | Inject Cache-Control headers |
| `20-nocache.conf` | patch_reports_nocache.sh | (duplicate, harmless) |
| `30-perms.conf` | inline chmod/chown | Fix file permissions on reports/ |
| `30-unraid.conf` | patch_reports_unraid.sh | Unraid array/device table |
| `40-final.conf` | patch_reports_final.sh | Full extras patch chain |

### prom-refresh-html.service.d/
| File | Script | Action |
|------|--------|--------|
| `00-ordering.conf` | (unit config) | After=prom-html-dashboards.service |
| `40-topcpu.conf` | fix_top_cpu_tables.sh | CPU table for 10.24, 10.10 |
| `99-final.conf` | patch_reports_final.sh | Full extras patch chain |

## Generation Scripts (`/opt/monitoring/bin/`)

| Script | Output | Description |
|--------|--------|-------------|
| `update_all_dashboards.sh` | tower_*.html x4 | Calls prom_tower_dashboard_html.sh for 10.10, 10.20, 5.131, 10.24 + VPS collection |
| `prom_tower_dashboard_html.sh` | tower_*.html | Base tower HTML from Prometheus API |
| `prom_tower_dashboard_html.base.sh` | (internal) | Core HTML generator called by wrapper |
| `prom_vm_dashboard_html.sh` | vm_dashboard_*.html | Rich HTML with grids (32-34 KB) |
| `prom_win_html_192_168_1_253_9182.sh` | win_*.html | Full Windows HTML with SSH/SMB tables |
| `prom_vps_html_31_170_165_94.sh` | vps_*.html | Full VPS HTML from SSH-collected metrics |
| `collect_vm_ms_ssh.sh` | vps_*.prom | SSH pull from VPS metrics user (timeout 30s) |
| `sys-sample-prom.sh` | sys_sample.prom | CPU/mem/net/disk textfile collector (auto-detects Docker textfile mount) |
| `sys-topproc-prom.sh` | sys_topproc.prom | Top process textfile collector |

## Patch Scripts (`/usr/local/bin/`)

| Script | Target File | Injects |
|--------|-------------|---------|
| `patch_reports_final.sh` | (orchestrator) | Calls all extras scripts in order |
| `patch_reports_wazuh_extras.sh` | tower_192_168_10_20 | sys_sample + SSH table (admin-tagged) + Top CPU |
| `patch_reports_ubuntu_5_131_extras.sh` | tower_192_168_5_131 | sys_sample + SSH table (admin-tagged) + Top CPU |
| `patch_reports_ubuntu_10_24_extras.sh` | tower_192_168_10_24 | sys_sample + SSH table (admin-tagged) + Top CPU |
| `patch_reports_unraid_10_10_extras.sh` | tower_192_168_10_10 | sys_sample + SSH table (admin-tagged) + Top CPU |
| `patch_reports_unraid.sh` | tower_192_168_10_10 | Unraid array/device table with temps/SMART/utilization |
| `patch_reports_unraid_details_10_10.sh` | tower_192_168_10_10 | Unraid uptime/Docker/VMs/HW info |
| `patch_reports_nocache.sh` | all *.html | Cache-Control no-cache headers |
| `fix_top_cpu_tables.sh` | tower_10_24, tower_10_10 | Top CPU table (dedup-safe) |
| `tower_ssh_sessions_local.sh` | tower_ssh_sessions.prom | SSH session textfile (w -h -i, full username, remote-only) |

## Removed Scripts (April 2026)

| Script | Reason |
|--------|--------|
| `prom_tower_html.sh` | Duplicate view A generator (emoji format) for 10.10 |
| `prom_windows_html_192_168_1_253.sh` | Duplicate view A generator for Windows |
| `tower-dashboard.service` | Obsolete systemd service for 10.10 |

## Metric Naming Conventions

| Prefix | Source | Description |
|--------|--------|-------------|
| `sys_sample_` | textfile (sys-sample-prom.sh) | System snapshot metrics |
| `sys_topproc_` | textfile (sys-topproc-prom.sh) | Per-process CPU/mem/RSS |
| `tower_ssh_sessions_` | textfile | Active SSH sessions per user/IP |
| `tower_unraid_` | textfile (tower_unraid.prom) | Unraid array/parity/device metrics |
| `vps_` | textfile (collect_vm_ms_ssh.sh) | VPS metrics via SSH pull |
| `node_` | node_exporter | Standard Linux OS metrics |
| `windows_` | windows_exporter | Windows WMI metrics |
| `win_ssh_` / `win_smb_` | textfile (Windows) | Windows SSH/SMB session counts |

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
| `<!-- SYS_SAMPLE_V2_UNRAID_10_10 -->` | 10.10 | System sample card |
| `<!-- SSH_TABLE_V2_UNRAID_10_10 -->` | 10.10 | SSH sessions table |
| `<!-- TOP_CPU_V1_UNRAID_10_10 -->` | 10.10 | Top CPU processes |
| `<!-- TOP_CPU_TABLE_V2 -->` | 10.24, 10.10 | CPU table (fix_top_cpu_tables) |
| `<!-- UNRAID_DETAILS_PLACEHOLDER -->` | 10.10 | Replaced by Unraid device table |
| `<!-- UNRAID_PROMFILE_DETAILS_V1 -->` | 10.10 | Unraid prom file details tag |

## Admin IP Filtering

All extras scripts define `ADMIN_IPS = {"10.253.2.2"}`. Sessions from admin IPs are displayed with an `(admin)` tag in the SSH sessions table rather than hidden. To add more admin IPs, update the `ADMIN_IPS` set in each extras script.
