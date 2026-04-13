#!/usr/bin/env bash
set -euo pipefail

echo "=== Step 1: Update SSH collector to use VPN IP ==="
sed -i 's|HOST="31.170.165.94"|HOST="${VPS_HOST:-10.253.2.22}"|' /opt/monitoring/bin/collect_vm_ms_ssh.sh
grep 'HOST=' /opt/monitoring/bin/collect_vm_ms_ssh.sh | head -1

echo "=== Step 2: Update VPS dashboard generator ==="
# Update TARGET and output filename references
sed -i 's|TARGET="31.170.165.94"|TARGET="10.253.2.22"|' /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh
sed -i 's|ALIAS="VM-MS"|ALIAS="movement-strategy"|' /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh
sed -i 's|OUT="/opt/monitoring/reports/vps_31_170_165_94.html"|OUT="/opt/monitoring/reports/vps_movement_strategy.html"|' /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh
# Also fix the inner Python vars
sed -i 's|TARGET="31.170.165.94"|TARGET="10.253.2.22"|' /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh
sed -i 's|ALIAS="VM-MS"|ALIAS="movement-strategy"|' /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh
sed -i 's|OUT="/opt/monitoring/reports/vps_31_170_165_94.html"|OUT="/opt/monitoring/reports/vps_movement_strategy.html"|' /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh

# Rename the script
cp /opt/monitoring/bin/prom_vps_html_31_170_165_94.sh /opt/monitoring/bin/prom_vps_html_movement_strategy.sh
chmod +x /opt/monitoring/bin/prom_vps_html_movement_strategy.sh

echo "=== Step 3: Update textfile prom output filename ==="
# The collector writes to vps_31_170_165_94.prom — update to new name
sed -i 's|OUT="$OUTDIR/vps_${HOST//./_}.prom"|OUT="$OUTDIR/vps_movement_strategy.prom"|' /opt/monitoring/bin/collect_vm_ms_ssh.sh
sed -i 's|TMP="$(mktemp "$OUTDIR/.vps_${HOST//./_}.prom.tmp.XXXXXX")"|TMP="$(mktemp "$OUTDIR/.vps_movement_strategy.prom.tmp.XXXXXX")"|' /opt/monitoring/bin/collect_vm_ms_ssh.sh

echo "=== Step 4: Update refresh scripts ==="
# Update patch_reports_final.sh if it references the old script
if [ -f /usr/local/bin/patch_reports_final.sh ]; then
  sed -i 's|prom_vps_html_31_170_165_94.sh|prom_vps_html_movement_strategy.sh|' /usr/local/bin/patch_reports_final.sh
  echo "  Updated patch_reports_final.sh"
fi

echo "=== Step 5: Update prom_refresh_all_html.sh ==="
if grep -q "31.170.165.94" /opt/monitoring/prom_refresh_all_html.sh 2>/dev/null; then
  sed -i 's|prom_vps_html_31_170_165_94.sh|prom_vps_html_movement_strategy.sh|' /opt/monitoring/prom_refresh_all_html.sh
  echo "  Updated prom_refresh_all_html.sh"
fi

echo "=== Step 6: Reload Prometheus config ==="
docker restart prometheus

echo "=== Step 7: Create symlink for old URL compatibility ==="
ln -sf vps_movement_strategy.html /opt/monitoring/reports/vps_31_170_165_94.html 2>/dev/null || true

echo ""
echo "=== Done ==="
echo "  Collector SSH target: 10.253.2.22 (VPN)"
echo "  Prometheus scrape: 10.253.2.22:9100"
echo "  Dashboard: /opt/monitoring/reports/vps_movement_strategy.html"
echo "  Old URL symlinked for compatibility"
