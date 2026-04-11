#!/usr/bin/env bash
set -euo pipefail
umask 022

# Allow override: TEXTDIR=/path/to/textfile_collector
TEXTDIR="${TEXTDIR:-$(docker inspect node-exporter --format '{{range .Mounts}}{{if or (eq .Destination "/textfile") (eq .Destination "/textfile_collector") (eq .Destination "/var/lib/node_exporter/textfile_collector")}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)}"
test -n "$TEXTDIR" || { echo "ERROR: could not detect node-exporter textfile collector dir. Run: docker inspect node-exporter --format '{{json .Mounts}}'"; exit 1; }

install -d -m 0755 "$TEXTDIR" 2>/dev/null || true

OUT="$TEXTDIR/sys_sample.prom"
TMP="$(mktemp "$TEXTDIR/sys_sample.prom.XXXXXX")"
STATE="/run/sys-sample-prom.state"
DSTATE="/run/sys-sample-prom.diskstate"

nan(){ echo "NaN"; }

# ---- CPU busy% (1s delta from /proc/stat) ----
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

# ---- Memory / Swap ----
mem_total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
mem_avail_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
mem_cached_kb="$(awk '/^Cached:/ {print $2}' /proc/meminfo)"
swap_total_kb="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
swap_free_kb="$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)"

mem_used_bytes="$(( (mem_total_kb - mem_avail_kb) * 1024 ))"
mem_total_bytes="$(( mem_total_kb * 1024 ))"
mem_cache_bytes="$(( mem_cached_kb * 1024 ))"
swap_used_bytes="$(( (swap_total_kb - swap_free_kb) * 1024 ))"
swap_total_bytes="$(( swap_total_kb * 1024 ))"

# ---- Net totals + rates ----
IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[ -n "${IFACE:-}" ] || IFACE="$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}')"

rx_bytes="$(cat "/sys/class/net/$IFACE/statistics/rx_bytes" 2>/dev/null || echo 0)"
tx_bytes="$(cat "/sys/class/net/$IFACE/statistics/tx_bytes" 2>/dev/null || echo 0)"
uptime_s="$(awk '{printf "%.0f",$1}' /proc/uptime)"

rx_avg_mbps="$(awk -v b="$rx_bytes" -v u="$uptime_s" 'BEGIN{ if(u>0) printf "%.3f",(b*8)/(u*1000000); else print "NaN"}')"
tx_avg_mbps="$(awk -v b="$tx_bytes" -v u="$uptime_s" 'BEGIN{ if(u>0) printf "%.3f",(b*8)/(u*1000000); else print "NaN"}')"

rx_bps="$(nan)"; tx_bps="$(nan)"
now="$(date +%s)"
if [ -f "$STATE" ]; then
  read -r last_ts last_rx last_tx < "$STATE" || true
  if [ -n "${last_ts:-}" ] && [ "$now" -gt "$last_ts" ]; then
    dts=$((now-last_ts))
    drx=$((rx_bytes-last_rx))
    dtx=$((tx_bytes-last_tx))
    rx_bps="$(awk -v d="$drx" -v t="$dts" 'BEGIN{printf "%.0f", d/t}')"
    tx_bps="$(awk -v d="$dtx" -v t="$dts" 'BEGIN{printf "%.0f", d/t}')"
  fi
fi
printf "%s %s %s\n" "$now" "$rx_bytes" "$tx_bytes" > "$STATE"

# ---- Disk totals + rates ----
read_sectors=0; write_sectors=0
while read -r _ _ dev rcomp rmerge rsect ruse wcomp wmerge wsect wuse _; do
  case "$dev" in
    sd[a-z]|vd[a-z]|xvd[a-z]|nvme[0-9]n[0-9]) ;;
    *) continue ;;
  esac
  read_sectors=$((read_sectors + rsect))
  write_sectors=$((write_sectors + wsect))
done < /proc/diskstats

disk_read_total_bytes=$((read_sectors * 512))
disk_write_total_bytes=$((write_sectors * 512))

disk_read_bps="$(nan)"; disk_write_bps="$(nan)"
if [ -f "$DSTATE" ]; then
  read -r dlast_ts dlast_r dlast_w < "$DSTATE" || true
  if [ -n "${dlast_ts:-}" ] && [ "$now" -gt "$dlast_ts" ]; then
    dts=$((now-dlast_ts))
    dr=$((disk_read_total_bytes-dlast_r))
    dw=$((disk_write_total_bytes-dlast_w))
    disk_read_bps="$(awk -v d="$dr" -v t="$dts" 'BEGIN{printf "%.0f", d/t}')"
    disk_write_bps="$(awk -v d="$dw" -v t="$dts" 'BEGIN{printf "%.0f", d/t}')"
  fi
fi
printf "%s %s %s\n" "$now" "$disk_read_total_bytes" "$disk_write_total_bytes" > "$DSTATE"

# ---- Filesystem usage % ----
root_pct="$(df -P / | awk 'NR==2{gsub(/%/,"",$5); print $5+0}')"
iso_pct="$(nan)"
for p in /mnt/iso /iso /mnt/ISO; do
  if mountpoint -q "$p" 2>/dev/null; then
    iso_pct="$(df -P "$p" | awk 'NR==2{gsub(/%/,"",$5); print $5+0}')"
    break
  fi
done

# ---- Emit metrics ----
{
  echo '# TYPE sys_sample_cpu_busy_percent gauge'
  echo "sys_sample_cpu_busy_percent $cpu_busy"

  echo '# TYPE sys_sample_mem_used_bytes gauge'
  echo '# TYPE sys_sample_mem_total_bytes gauge'
  echo '# TYPE sys_sample_mem_cache_bytes gauge'
  echo "sys_sample_mem_used_bytes $mem_used_bytes"
  echo "sys_sample_mem_total_bytes $mem_total_bytes"
  echo "sys_sample_mem_cache_bytes $mem_cache_bytes"

  echo '# TYPE sys_sample_swap_used_bytes gauge'
  echo '# TYPE sys_sample_swap_total_bytes gauge'
  echo "sys_sample_swap_used_bytes $swap_used_bytes"
  echo "sys_sample_swap_total_bytes $swap_total_bytes"

  echo '# TYPE sys_sample_net_rx_bps gauge'
  echo '# TYPE sys_sample_net_tx_bps gauge'
  echo '# TYPE sys_sample_net_rx_total_bytes gauge'
  echo '# TYPE sys_sample_net_tx_total_bytes gauge'
  echo '# TYPE sys_sample_net_rx_avg_mbps gauge'
  echo '# TYPE sys_sample_net_tx_avg_mbps gauge'
  echo "sys_sample_net_rx_bps $rx_bps"
  echo "sys_sample_net_tx_bps $tx_bps"
  echo "sys_sample_net_rx_total_bytes $rx_bytes"
  echo "sys_sample_net_tx_total_bytes $tx_bytes"
  echo "sys_sample_net_rx_avg_mbps $rx_avg_mbps"
  echo "sys_sample_net_tx_avg_mbps $tx_avg_mbps"

  echo '# TYPE sys_sample_disk_read_bps gauge'
  echo '# TYPE sys_sample_disk_write_bps gauge'
  echo '# TYPE sys_sample_disk_read_total_bytes gauge'
  echo '# TYPE sys_sample_disk_write_total_bytes gauge'
  echo "sys_sample_disk_read_bps $disk_read_bps"
  echo "sys_sample_disk_write_bps $disk_write_bps"
  echo "sys_sample_disk_read_total_bytes $disk_read_total_bytes"
  echo "sys_sample_disk_write_total_bytes $disk_write_total_bytes"

  echo '# TYPE sys_sample_fs_root_percent gauge'
  echo '# TYPE sys_sample_fs_iso_percent gauge'
  echo "sys_sample_fs_root_percent $root_pct"
  echo "sys_sample_fs_iso_percent $iso_pct"

  echo '# TYPE sys_sample_metrics_seen gauge'
  echo "sys_sample_metrics_seen 19"
} > "$TMP"

install -m 0644 "$TMP" "$OUT"
rm -f "$TMP"

echo "OK: wrote $OUT"
