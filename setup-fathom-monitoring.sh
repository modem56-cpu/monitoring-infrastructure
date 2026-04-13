#!/usr/bin/env bash
set -euo pipefail
#
# Run on fathom-vault (192.168.10.24) as root/sudo
# Sets up sys_sample + sys_topproc textfile collectors for node-exporter
#

TEXTDIR="/var/lib/prometheus/node-exporter"
mkdir -p "$TEXTDIR"

echo "=== Step 1: Configure node-exporter textfile collector ==="
# Check if textfile dir is already configured
if grep -q "collector.textfile" /etc/default/prometheus-node-exporter 2>/dev/null; then
  echo "  Already configured"
else
  echo 'ARGS="--collector.textfile.directory=/var/lib/prometheus/node-exporter --collector.processes"' > /etc/default/prometheus-node-exporter
  systemctl restart prometheus-node-exporter
  echo "  Configured textfile collector at $TEXTDIR"
fi

echo ""
echo "=== Step 2: Install sys-sample-prom.sh ==="
cat > /usr/local/bin/sys-sample-prom.sh << 'SYSEOF'
#!/usr/bin/env bash
set -euo pipefail
TEXTDIR="${TEXTDIR:-/var/lib/prometheus/node-exporter}"
OUT="$TEXTDIR/sys_sample.prom"
TMP="$(mktemp "$TEXTDIR/sys_sample.prom.XXXXXX")"
nan(){ echo "NaN"; }

# CPU busy% (1s delta)
read -r _ u1 n1 s1 i1 io1 irq1 sirq1 st1 _ < /proc/stat
t1=$((u1+n1+s1+i1+io1+irq1+sirq1+st1)); idle1=$((i1+io1))
sleep 1
read -r _ u2 n2 s2 i2 io2 irq2 sirq2 st2 _ < /proc/stat
t2=$((u2+n2+s2+i2+io2+irq2+sirq2+st2)); idle2=$((i2+io2))
dt=$((t2-t1)); didle=$((idle2-idle1))
if [ "$dt" -gt 0 ]; then
  cpu_busy="$(awk -v dt="$dt" -v didle="$didle" 'BEGIN{printf "%.2f", (1-(didle/dt))*100}')"
else
  cpu_busy="$(nan)"
fi

# Memory/Swap
mem_total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
mem_avail_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
mem_cached_kb="$(awk '/^Cached:/ {print $2}' /proc/meminfo)"
swap_total_kb="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
swap_free_kb="$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)"
mem_used_bytes="$(( (mem_total_kb - mem_avail_kb) * 1024 ))"
mem_total_bytes="$(( mem_total_kb * 1024 ))"
mem_cache_bytes="$(( mem_cached_kb * 1024 ))"
swap_total_bytes="$(( swap_total_kb * 1024 ))"
swap_used_bytes="$(( (swap_total_kb - swap_free_kb) * 1024 ))"

# Root FS
root_pct="$(df / | awk 'NR==2{gsub(/%/,""); print $5}')"

# Network (primary interface)
iface="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
if [ -n "$iface" ]; then
  rx1=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)
  tx1=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo 0)
  sleep 1
  rx2=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)
  tx2=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo 0)
  net_rx_bps=$((rx2 - rx1))
  net_tx_bps=$((tx2 - tx1))
  net_rx_total=$rx2
  net_tx_total=$tx2
else
  net_rx_bps=0; net_tx_bps=0; net_rx_total=0; net_tx_total=0
fi

# Write metrics
{
echo "# TYPE sys_sample_cpu_busy_percent gauge"
echo "sys_sample_cpu_busy_percent $cpu_busy"
echo "# TYPE sys_sample_mem_used_bytes gauge"
echo "sys_sample_mem_used_bytes $mem_used_bytes"
echo "# TYPE sys_sample_mem_total_bytes gauge"
echo "sys_sample_mem_total_bytes $mem_total_bytes"
echo "# TYPE sys_sample_mem_cache_bytes gauge"
echo "sys_sample_mem_cache_bytes $mem_cache_bytes"
echo "# TYPE sys_sample_swap_used_bytes gauge"
echo "sys_sample_swap_used_bytes $swap_used_bytes"
echo "# TYPE sys_sample_swap_total_bytes gauge"
echo "sys_sample_swap_total_bytes $swap_total_bytes"
echo "# TYPE sys_sample_rootfs_used_percent gauge"
echo "sys_sample_rootfs_used_percent $root_pct"
echo "# TYPE sys_sample_net_rx_bps gauge"
echo "sys_sample_net_rx_bps $net_rx_bps"
echo "# TYPE sys_sample_net_tx_bps gauge"
echo "sys_sample_net_tx_bps $net_tx_bps"
echo "# TYPE sys_sample_net_rx_total_bytes gauge"
echo "sys_sample_net_rx_total_bytes $net_rx_total"
echo "# TYPE sys_sample_net_tx_total_bytes gauge"
echo "sys_sample_net_tx_total_bytes $net_tx_total"
echo "# TYPE sys_sample_metrics_seen gauge"
echo "sys_sample_metrics_seen 13"
} > "$TMP"
mv -f "$TMP" "$OUT"
chmod 0644 "$OUT"
SYSEOF
chmod +x /usr/local/bin/sys-sample-prom.sh

echo ""
echo "=== Step 3: Install sys-topproc-prom.sh ==="
cat > /usr/local/bin/sys-topproc-prom.sh << 'TOPEOF'
#!/usr/bin/env bash
set -euo pipefail
TEXTDIR="${TEXTDIR:-/var/lib/prometheus/node-exporter}"
OUT="$TEXTDIR/sys_topproc.prom"
TMP="$(mktemp "$TEXTDIR/sys_topproc.prom.XXXXXX")"

{
echo "# TYPE sys_topproc_pcpu_percent gauge"
echo "# TYPE sys_topproc_pmem_percent gauge"
echo "# TYPE sys_topproc_rss_kb gauge"
ps aux --sort=-%cpu | awk 'NR>1 && NR<=16 {
  user=$1; pid=$2; cpu=$3; mem=$4; rss=$6; cmd=$11
  gsub(/[^a-zA-Z0-9._\/-]/, "", cmd)
  sub(/.*\//, "", cmd)
  if (length(cmd) > 15) cmd = substr(cmd, 1, 15)
  rank = NR - 1
  printf "sys_topproc_pcpu_percent{user=\"%s\",pid=\"%s\",comm=\"%s\",rank=\"%d\"} %.1f\n", user, pid, cmd, rank, cpu
  printf "sys_topproc_pmem_percent{user=\"%s\",pid=\"%s\",comm=\"%s\",rank=\"%d\"} %.1f\n", user, pid, cmd, rank, mem
  printf "sys_topproc_rss_kb{user=\"%s\",pid=\"%s\",comm=\"%s\",rank=\"%d\"} %d\n", user, pid, cmd, rank, rss
}'
} > "$TMP"
mv -f "$TMP" "$OUT"
chmod 0644 "$OUT"
TOPEOF
chmod +x /usr/local/bin/sys-topproc-prom.sh

echo ""
echo "=== Step 4: Create systemd timers ==="
cat > /etc/systemd/system/sys-sample-prom.service << 'SVC'
[Unit]
Description=Generate sys_sample.prom
[Service]
Type=oneshot
Environment=TEXTDIR=/var/lib/prometheus/node-exporter
ExecStart=/usr/local/bin/sys-sample-prom.sh
SVC

cat > /etc/systemd/system/sys-sample-prom.timer << 'TMR'
[Unit]
Description=Run sys-sample every 15 seconds
[Timer]
OnBootSec=10s
OnUnitActiveSec=15s
AccuracySec=1s
[Install]
WantedBy=timers.target
TMR

cat > /etc/systemd/system/sys-topproc-prom.service << 'SVC2'
[Unit]
Description=Generate sys_topproc.prom
[Service]
Type=oneshot
Environment=TEXTDIR=/var/lib/prometheus/node-exporter
ExecStart=/usr/local/bin/sys-topproc-prom.sh
SVC2

cat > /etc/systemd/system/sys-topproc-prom.timer << 'TMR2'
[Unit]
Description=Run sys-topproc every 60 seconds
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
TMR2

systemctl daemon-reload
systemctl enable --now sys-sample-prom.timer sys-topproc-prom.timer

echo ""
echo "=== Step 5: Test ==="
/usr/local/bin/sys-sample-prom.sh
/usr/local/bin/sys-topproc-prom.sh
echo "  sys_sample:"
cat /var/lib/prometheus/node-exporter/sys_sample.prom | grep -v "^#"
echo ""
echo "  sys_topproc (first 5):"
cat /var/lib/prometheus/node-exporter/sys_topproc.prom | grep "pcpu" | head -5

echo ""
echo "=== Step 6: Verify node-exporter serves them ==="
sleep 2
curl -s http://localhost:9100/metrics | grep -c "sys_sample\|sys_topproc"
echo " metrics exposed"

echo ""
echo "=== Done ==="
echo "  Timers: sys-sample (15s), sys-topproc (60s)"
echo "  Textfile dir: $TEXTDIR"
