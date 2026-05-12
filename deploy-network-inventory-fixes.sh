#!/usr/bin/env bash
# Fix network inventory false alerts — NetworkARPConflict + NetworkNewDeviceDetected
# Also: add trap to collect_vm_ms_ssh.sh to clean up temp files on failure
# Must run as root
# Changes:
#   1. Deploy udm-arp-collector-v2.py to bin/ (adds --set-baseline, last_24h metric)
#   2. Run --set-baseline: mark all 216 known devices as baseline, clear stale conflict log
#   3. Update alert rules: NetworkARPConflict → last_24h metric; NetworkNewDeviceDetected → requires baseline > 0
#   4. Fix collect_vm_ms_ssh.sh to trap EXIT and delete temp file on failure
#   5. Reload Prometheus
set -euo pipefail

echo "=== Network Inventory False Alert Fix ==="
echo ""

# 1. Deploy updated collector
echo "--- Step 1: Deploy udm-arp-collector-v2.py ---"
cp /opt/monitoring/udm-arp-collector-v2.py /opt/monitoring/bin/udm-arp-collector.py
chmod 755 /opt/monitoring/bin/udm-arp-collector.py
echo "  Deployed to bin/"

# 2. Set baseline (marks all 216 known MACs as baseline, clears stale conflict log)
echo ""
echo "--- Step 2: Set baseline ---"
python3 /opt/monitoring/bin/udm-arp-collector.py --set-baseline

# 3. Update alert rules
echo ""
echo "--- Step 3: Update network_inventory alert rules ---"
cat > /opt/monitoring/rules/network_inventory.rules.yml << 'RULES_EOF'
groups:
  - name: network_inventory
    rules:

      # ── New device detected after baseline ───────────────────────────────
      # Only fires when a real baseline exists (network_inventory_baseline_total > 0).
      # Without a baseline, all devices appear as "discovered" — this guards against
      # false alerts on fresh state or after a state file reset.
      - alert: NetworkNewDeviceDetected
        expr: network_inventory_discovered_total > 0 and network_inventory_baseline_total > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} new device(s) detected since baseline"
          description: >
            One or more devices with MACs not in the approved baseline have
            appeared on the network. Check Grafana Network Inventory dashboard
            or Wazuh for details. Re-run --set-baseline script once authorized.

      # ── ARP conflict (possible spoofing) ─────────────────────────────────
      # Uses _last_24h metric (not cumulative total) to avoid firing on historical
      # DHCP churn / MAC randomization events that accumulated before baseline was set.
      - alert: NetworkARPConflict
        expr: network_inventory_arp_conflicts_last_24h > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "{{ $value }} ARP conflict(s) in last 24h"
          description: >
            An IP address mapped to a different MAC within the last 24 hours.
            This may indicate ARP spoofing, a device swap, or DHCP confusion.
            Note: "unknown" vendor MACs are often mobile devices with MAC randomization.
            Check Grafana Network Inventory dashboard ARP Conflicts panel.

      # ── ARP collector not running ─────────────────────────────────────────
      - alert: NetworkARPCollectorStale
        expr: (time() - network_arp_collector_last_run) > 600
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Network ARP collector has not run in {{ $value | humanizeDuration }}"
          description: >
            The udm-arp-collector.timer has not produced fresh data.
            Network inventory and Akvorado enrichment may be stale.
            Check: systemctl status udm-arp-collector.timer
RULES_EOF
echo "  Rules updated"

# 4. Reload Prometheus
echo ""
echo "--- Step 4: Reload Prometheus ---"
if systemctl is-active --quiet prometheus 2>/dev/null; then
    kill -HUP "$(systemctl show -p MainPID prometheus | cut -d= -f2)" 2>/dev/null \
        || curl -s -X POST http://localhost:9090/-/reload
    echo "  Prometheus reloaded"
else
    curl -s -X POST http://localhost:9090/-/reload && echo "  Prometheus reloaded via API"
fi

# 4b. Fix collect_vm_ms_ssh.sh: add trap to delete temp file on failure
echo ""
echo "--- Step 4b: Fix collect_vm_ms_ssh.sh temp file leak ---"
# Add 'trap "rm -f \\"$TMP\\"" EXIT' right after TMP= line
if ! grep -q 'trap.*rm.*TMP' /opt/monitoring/bin/collect_vm_ms_ssh.sh; then
    sed -i '/^TMP=.*mktemp/a trap "rm -f \\"$TMP\\"" EXIT' /opt/monitoring/bin/collect_vm_ms_ssh.sh
    echo "  Added EXIT trap to collect_vm_ms_ssh.sh"
else
    echo "  Trap already present — skipping"
fi

echo ""
echo "=== Done ==="
echo ""
echo "Verify:"
echo "  1. Check baseline count:  curl -s 'http://localhost:9090/api/v1/query?query=network_inventory_baseline_total'"
echo "  2. Check conflicts_24h:   curl -s 'http://localhost:9090/api/v1/query?query=network_inventory_arp_conflicts_last_24h'"
echo "  3. NetworkARPConflict should clear within 5 minutes"
echo "  4. NetworkNewDeviceDetected should clear immediately (baseline now set)"
