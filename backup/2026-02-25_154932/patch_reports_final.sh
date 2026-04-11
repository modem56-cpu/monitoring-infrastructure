#!/usr/bin/env bash
set -euo pipefail

# Update ssh-session metrics for wazuh host
if [ -x /usr/local/bin/tower_ssh_sessions_local.sh ]; then
  /usr/local/bin/tower_ssh_sessions_local.sh || true
fi

# Patch wazuh tower page: sys_sample + ssh table + top cpu
if [ -x /usr/local/bin/patch_reports_wazuh_extras.sh ]; then
  /usr/local/bin/patch_reports_wazuh_extras.sh || true
fi

# Windows page: always regenerate using the new layout
if [ -x /opt/monitoring/bin/prom_win_html_192_168_1_253_9182.sh ]; then
  /opt/monitoring/bin/prom_win_html_192_168_1_253_9182.sh || true
fi

# VM-MS: refresh metrics + regenerate HTML
if [ -x /opt/monitoring/bin/collect_vm_ms_ssh.sh ]; then
  sudo -u wazuh-admin /opt/monitoring/bin/collect_vm_ms_ssh.sh || true
  sudo chmod 0644 /opt/monitoring/textfile_collector/vps_31_170_165_94.prom 2>/dev/null || true
fi
if [ -x /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh ]; then
  /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh || true
fi

# --- Ubuntu VM (192.168.5.131): sys_sample + ssh table + top cpu ---
if [ -x /usr/local/bin/patch_reports_ubuntu_5_131_extras.sh ]; then
  /usr/local/bin/patch_reports_ubuntu_5_131_extras.sh || true
fi

# --- Ubuntu VM (192.168.5.131): sys_sample + ssh table + top cpu ---
if [ -x /usr/local/bin/patch_reports_ubuntu_5_131_extras.sh ]; then
  /usr/local/bin/patch_reports_ubuntu_5_131_extras.sh || true
fi

# Unraid details patch (10.10)
[ -x /usr/local/bin/patch_reports_unraid_details_10_10.sh ] && /usr/local/bin/patch_reports_unraid_details_10_10.sh || true
