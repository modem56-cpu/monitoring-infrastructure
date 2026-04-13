#!/usr/bin/env bash
set -euo pipefail
#
# Run on Unraid (192.168.10.10) as root
# Monitors VM backups and writes Prometheus textfile metrics
#

TEXTDIR="/var/lib/prometheus/node-exporter"
BACKUP_DIR="/mnt/user/Backups/Domains"

echo "=== Step 1: Create backup monitor script ==="

cat > /usr/local/bin/vmbackup-prom.sh << 'MONITOR'
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/mnt/user/Backups/Domains}"
TEXTDIR="${TEXTDIR:-/var/lib/prometheus/node-exporter}"
OUT="$TEXTDIR/vmbackup.prom"
TMP="$(mktemp "$TEXTDIR/.vmbackup.prom.tmp.XXXXXX")"
NOW=$(date +%s)

{
echo "# HELP vmbackup_latest_age_seconds Age of most recent backup file in seconds"
echo "# TYPE vmbackup_latest_age_seconds gauge"
echo "# HELP vmbackup_latest_size_bytes Size of most recent backup disk image"
echo "# TYPE vmbackup_latest_size_bytes gauge"
echo "# HELP vmbackup_file_count Number of backup files for this VM"
echo "# TYPE vmbackup_file_count gauge"
echo "# HELP vmbackup_latest_disk_size_bytes Size of most recent .zst or .img backup"
echo "# TYPE vmbackup_latest_disk_size_bytes gauge"
echo "# HELP vmbackup_latest_xml_exists Whether XML config backup exists (1=yes)"
echo "# TYPE vmbackup_latest_xml_exists gauge"
echo "# HELP vmbackup_latest_nvram_exists Whether NVRAM backup exists (1=yes)"
echo "# TYPE vmbackup_latest_nvram_exists gauge"
echo "# HELP vmbackup_vm_defined Whether VM is currently defined in libvirt (1=yes)"
echo "# TYPE vmbackup_vm_defined gauge"
echo "# HELP vmbackup_vm_running Whether VM is currently running (1=yes)"
echo "# TYPE vmbackup_vm_running gauge"
echo "# HELP vmbackup_has_backup Whether backup directory exists for this VM (1=yes)"
echo "# TYPE vmbackup_has_backup gauge"
echo "# HELP vmbackup_backup_healthy Backup is recent (<8 days) and non-trivial size (>50MB) (1=yes)"
echo "# TYPE vmbackup_backup_healthy gauge"
echo "# HELP vmbackup_total_vms Total VMs defined in libvirt"
echo "# TYPE vmbackup_total_vms gauge"
echo "# HELP vmbackup_total_backed_up VMs with at least one backup"
echo "# TYPE vmbackup_total_backed_up gauge"
echo "# HELP vmbackup_total_healthy VMs with healthy backups"
echo "# TYPE vmbackup_total_healthy gauge"
echo "# HELP vmbackup_collector_up Backup monitor script ran successfully"
echo "# TYPE vmbackup_collector_up gauge"

# Get all defined VMs
DEFINED_VMS=$(virsh list --all --name 2>/dev/null | grep -v "^$" | sort)
DEFINED_COUNT=0
BACKED_UP=0
HEALTHY=0

# Track all VMs (defined + backed up)
ALL_VMS=""

for vm in $DEFINED_VMS; do
    ALL_VMS="$ALL_VMS $vm"
    DEFINED_COUNT=$((DEFINED_COUNT + 1))
done

# Also check backup dirs for VMs not currently defined
if [ -d "$BACKUP_DIR" ]; then
    for vm_dir in "$BACKUP_DIR"/*/; do
        [ -d "$vm_dir" ] || continue
        vm=$(basename "$vm_dir")
        [ "$vm" = "logs" ] && continue
        if ! echo "$ALL_VMS" | grep -qw "$vm"; then
            ALL_VMS="$ALL_VMS $vm"
        fi
    done
fi

for vm in $ALL_VMS; do
    # Check if defined in libvirt
    if virsh dominfo "$vm" &>/dev/null; then
        echo "vmbackup_vm_defined{vm=\"$vm\"} 1"
        state=$(virsh domstate "$vm" 2>/dev/null || echo "unknown")
        if [ "$state" = "running" ]; then
            echo "vmbackup_vm_running{vm=\"$vm\"} 1"
        else
            echo "vmbackup_vm_running{vm=\"$vm\"} 0"
        fi
    else
        echo "vmbackup_vm_defined{vm=\"$vm\"} 0"
        echo "vmbackup_vm_running{vm=\"$vm\"} 0"
    fi

    # Check backup directory
    if [ -d "$BACKUP_DIR/$vm" ]; then
        echo "vmbackup_has_backup{vm=\"$vm\"} 1"

        # Find latest disk backup (.zst or .img)
        latest_disk=$(find "$BACKUP_DIR/$vm" -maxdepth 1 \( -name "*.zst" -o -name "*vdisk*.img" \) 2>/dev/null | sort | tail -1)
        if [ -n "$latest_disk" ]; then
            disk_mtime=$(stat -c %Y "$latest_disk")
            disk_age=$((NOW - disk_mtime))
            disk_size=$(stat -c %s "$latest_disk")
            echo "vmbackup_latest_age_seconds{vm=\"$vm\"} $disk_age"
            echo "vmbackup_latest_disk_size_bytes{vm=\"$vm\"} $disk_size"
            BACKED_UP=$((BACKED_UP + 1))

            # Health check: age < 8 days AND size > 50MB
            if [ "$disk_age" -lt 691200 ] && [ "$disk_size" -gt 52428800 ]; then
                echo "vmbackup_backup_healthy{vm=\"$vm\"} 1"
                HEALTHY=$((HEALTHY + 1))
            else
                echo "vmbackup_backup_healthy{vm=\"$vm\"} 0"
            fi
        else
            echo "vmbackup_latest_age_seconds{vm=\"$vm\"} -1"
            echo "vmbackup_latest_disk_size_bytes{vm=\"$vm\"} 0"
            echo "vmbackup_backup_healthy{vm=\"$vm\"} 0"
        fi

        # Count total backup files
        file_count=$(find "$BACKUP_DIR/$vm" -maxdepth 1 -type f 2>/dev/null | wc -l)
        echo "vmbackup_file_count{vm=\"$vm\"} $file_count"

        # Check XML exists
        latest_xml=$(find "$BACKUP_DIR/$vm" -maxdepth 1 -name "*.xml" 2>/dev/null | sort | tail -1)
        if [ -n "$latest_xml" ]; then
            echo "vmbackup_latest_xml_exists{vm=\"$vm\"} 1"
        else
            echo "vmbackup_latest_xml_exists{vm=\"$vm\"} 0"
        fi

        # Check NVRAM exists
        latest_nvram=$(find "$BACKUP_DIR/$vm" -maxdepth 1 -name "*VARS*" -o -name "*nvram*" -o -name "*.fd" 2>/dev/null | sort | tail -1)
        if [ -n "$latest_nvram" ]; then
            echo "vmbackup_latest_nvram_exists{vm=\"$vm\"} 1"
        else
            echo "vmbackup_latest_nvram_exists{vm=\"$vm\"} 0"
        fi

        # Latest backup size (total of all latest files)
        total_latest=$(find "$BACKUP_DIR/$vm" -maxdepth 1 -type f -newer "$BACKUP_DIR/$vm" 2>/dev/null -exec stat -c %s {} + | awk '{s+=$1}END{print s+0}')
        echo "vmbackup_latest_size_bytes{vm=\"$vm\"} $total_latest"
    else
        echo "vmbackup_has_backup{vm=\"$vm\"} 0"
        echo "vmbackup_latest_age_seconds{vm=\"$vm\"} -1"
        echo "vmbackup_latest_disk_size_bytes{vm=\"$vm\"} 0"
        echo "vmbackup_latest_size_bytes{vm=\"$vm\"} 0"
        echo "vmbackup_file_count{vm=\"$vm\"} 0"
        echo "vmbackup_latest_xml_exists{vm=\"$vm\"} 0"
        echo "vmbackup_latest_nvram_exists{vm=\"$vm\"} 0"
        echo "vmbackup_backup_healthy{vm=\"$vm\"} 0"
    fi
done

echo "vmbackup_total_vms $DEFINED_COUNT"
echo "vmbackup_total_backed_up $BACKED_UP"
echo "vmbackup_total_healthy $HEALTHY"
echo "vmbackup_collector_up 1"

} > "$TMP"

mv -f "$TMP" "$OUT"
chmod 0644 "$OUT"
MONITOR

chmod +x /usr/local/bin/vmbackup-prom.sh

echo "=== Step 2: Create systemd timer ==="

# Check if systemd is available (Unraid uses init, not systemd)
if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
    cat > /etc/systemd/system/vmbackup-prom.service << 'SVC'
[Unit]
Description=VM backup monitoring for Prometheus
[Service]
Type=oneshot
Environment=TEXTDIR=/var/lib/prometheus/node-exporter
Environment=BACKUP_DIR=/mnt/user/Backups/Domains
ExecStart=/usr/local/bin/vmbackup-prom.sh
SVC

    cat > /etc/systemd/system/vmbackup-prom.timer << 'TMR'
[Unit]
Description=Run VM backup monitor every hour
[Timer]
OnBootSec=60s
OnUnitActiveSec=1h
[Install]
WantedBy=timers.target
TMR

    systemctl daemon-reload
    systemctl enable --now vmbackup-prom.timer
    echo "  Systemd timer created (every 1 hour)"
else
    # Unraid uses cron
    CRON_LINE="0 * * * * TEXTDIR=/var/lib/prometheus/node-exporter BACKUP_DIR=/mnt/user/Backups/Domains /usr/local/bin/vmbackup-prom.sh"
    if ! crontab -l 2>/dev/null | grep -q "vmbackup-prom"; then
        (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
        echo "  Cron job created (every hour)"
    else
        echo "  Cron job already exists"
    fi
fi

echo ""
echo "=== Step 3: Configure node-exporter textfile dir ==="
mkdir -p /var/lib/prometheus/node-exporter

# Check if node-exporter has textfile collector configured
if curl -s http://localhost:9100/metrics 2>/dev/null | grep -q "vmbackup"; then
    echo "  node-exporter already serves textfile metrics"
else
    echo "  Note: Ensure node-exporter has --collector.textfile.directory=/var/lib/prometheus/node-exporter"
    echo "  On Unraid, check the node-exporter plugin settings"
fi

echo ""
echo "=== Step 4: First run ==="
TEXTDIR=/var/lib/prometheus/node-exporter BACKUP_DIR=/mnt/user/Backups/Domains /usr/local/bin/vmbackup-prom.sh
echo ""
echo "  Output:"
cat /var/lib/prometheus/node-exporter/vmbackup.prom | grep -v "^#"

echo ""
echo "============================================"
echo "  Done!"
echo "============================================"
echo ""
echo "  Metrics exposed via node-exporter at :9100"
echo "  Key metrics:"
echo "    vmbackup_backup_healthy{vm=\"...\"} — 1=ok, 0=problem"
echo "    vmbackup_latest_disk_size_bytes{vm=\"...\"} — backup size"
echo "    vmbackup_latest_age_seconds{vm=\"...\"} — seconds since last backup"
echo "    vmbackup_vm_defined{vm=\"...\"} — 1=in libvirt, 0=missing"
echo "    vmbackup_has_backup{vm=\"...\"} — 1=backup dir exists"
