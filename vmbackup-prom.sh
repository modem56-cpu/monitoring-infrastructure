#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/mnt/user/Backups/Domains}"
TEXTDIR="${TEXTDIR:-/mnt/user/appdata/node_exporter/textfile_collector}"
OUT="$TEXTDIR/vmbackup.prom"
TMP="$(mktemp "$TEXTDIR/.vmbackup.prom.tmp.XXXXXX")"
NOW=$(date +%s)

{
echo "# HELP vmbackup_backup_healthy Backup recent and non-trivial (1=yes)"
echo "# TYPE vmbackup_backup_healthy gauge"
echo "# HELP vmbackup_latest_age_seconds Age of most recent backup"
echo "# TYPE vmbackup_latest_age_seconds gauge"
echo "# HELP vmbackup_latest_disk_size_bytes Size of latest backup disk"
echo "# TYPE vmbackup_latest_disk_size_bytes gauge"
echo "# HELP vmbackup_vm_defined VM defined in libvirt (1=yes)"
echo "# TYPE vmbackup_vm_defined gauge"
echo "# HELP vmbackup_has_backup Backup directory exists (1=yes)"
echo "# TYPE vmbackup_has_backup gauge"
echo "# HELP vmbackup_vm_running VM currently running (1=yes)"
echo "# TYPE vmbackup_vm_running gauge"
echo "# HELP vmbackup_file_count Backup file count"
echo "# TYPE vmbackup_file_count gauge"
echo "# HELP vmbackup_total_vms Total defined VMs"
echo "# TYPE vmbackup_total_vms gauge"
echo "# HELP vmbackup_total_backed_up VMs with backups"
echo "# TYPE vmbackup_total_backed_up gauge"
echo "# HELP vmbackup_total_healthy VMs with healthy backups"
echo "# TYPE vmbackup_total_healthy gauge"
echo "# HELP vmbackup_collector_up Script ran OK"
echo "# TYPE vmbackup_collector_up gauge"

DEFINED_VMS=$(virsh list --all --name 2>/dev/null | grep -v "^$" | sort)
DEFINED_COUNT=0; BACKED_UP=0; HEALTHY=0
ALL_VMS=""
for vm in $DEFINED_VMS; do ALL_VMS="$ALL_VMS $vm"; DEFINED_COUNT=$((DEFINED_COUNT+1)); done
if [ -d "$BACKUP_DIR" ]; then
  for d in "$BACKUP_DIR"/*/; do
    [ -d "$d" ] || continue
    vm=$(basename "$d"); [ "$vm" = "logs" ] && continue
    echo "$ALL_VMS" | grep -qw "$vm" || ALL_VMS="$ALL_VMS $vm"
  done
fi

for vm in $ALL_VMS; do
  if virsh dominfo "$vm" &>/dev/null; then
    echo "vmbackup_vm_defined{vm=\"$vm\"} 1"
    [ "$(virsh domstate "$vm" 2>/dev/null)" = "running" ] && echo "vmbackup_vm_running{vm=\"$vm\"} 1" || echo "vmbackup_vm_running{vm=\"$vm\"} 0"
  else
    echo "vmbackup_vm_defined{vm=\"$vm\"} 0"
    echo "vmbackup_vm_running{vm=\"$vm\"} 0"
  fi

  if [ -d "$BACKUP_DIR/$vm" ]; then
    echo "vmbackup_has_backup{vm=\"$vm\"} 1"
    latest=$(find "$BACKUP_DIR/$vm" -maxdepth 1 \( -name "*.zst" -o -name "*vdisk*.img" \) 2>/dev/null | sort | tail -1)
    if [ -n "$latest" ]; then
      age=$((NOW - $(stat -c %Y "$latest"))); size=$(stat -c %s "$latest")
      echo "vmbackup_latest_age_seconds{vm=\"$vm\"} $age"
      echo "vmbackup_latest_disk_size_bytes{vm=\"$vm\"} $size"
      BACKED_UP=$((BACKED_UP+1))
      if [ "$age" -lt 691200 ] && [ "$size" -gt 52428800 ]; then
        echo "vmbackup_backup_healthy{vm=\"$vm\"} 1"; HEALTHY=$((HEALTHY+1))
      else
        echo "vmbackup_backup_healthy{vm=\"$vm\"} 0"
      fi
    else
      echo "vmbackup_latest_age_seconds{vm=\"$vm\"} -1"
      echo "vmbackup_latest_disk_size_bytes{vm=\"$vm\"} 0"
      echo "vmbackup_backup_healthy{vm=\"$vm\"} 0"
    fi
    echo "vmbackup_file_count{vm=\"$vm\"} $(find "$BACKUP_DIR/$vm" -maxdepth 1 -type f 2>/dev/null | wc -l)"
  else
    echo "vmbackup_has_backup{vm=\"$vm\"} 0"
    echo "vmbackup_latest_age_seconds{vm=\"$vm\"} -1"
    echo "vmbackup_latest_disk_size_bytes{vm=\"$vm\"} 0"
    echo "vmbackup_backup_healthy{vm=\"$vm\"} 0"
    echo "vmbackup_file_count{vm=\"$vm\"} 0"
  fi
done

echo "vmbackup_total_vms $DEFINED_COUNT"
echo "vmbackup_total_backed_up $BACKED_UP"
echo "vmbackup_total_healthy $HEALTHY"
echo "vmbackup_collector_up 1"
} > "$TMP"
mv -f "$TMP" "$OUT"
chmod 0644 "$OUT"

echo "Done. Metrics written to $OUT"
cat "$OUT" | grep -v "^#"
