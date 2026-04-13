#!/usr/bin/env bash
sed -i 's|TARGET="10.253.2.22"|TARGET="31.170.165.94"|g' /opt/monitoring/bin/prom_vps_html_movement_strategy.sh
echo "Fixed TARGET to 31.170.165.94 (matches metric labels)"
grep 'TARGET\|ALIAS\|OUT=' /opt/monitoring/bin/prom_vps_html_movement_strategy.sh | head -6
