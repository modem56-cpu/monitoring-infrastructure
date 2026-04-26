#!/usr/bin/env bash
# Expand root LVM volume to 500GB total
# vda3 is the last partition so it can be grown online safely
set -euo pipefail

echo "=== Disk Expansion: root → 500GB ==="
echo ""
echo "Before:"
df -h /
echo ""
lsblk /dev/vda

echo ""
echo "=== Step 1: Grow vda3 partition to 500GB ==="
# growpart grows the partition to fill available space up to the target
# We resize vda3 to end at 500GB (1M + 2G + ~498G)
growpart /dev/vda 3 --free-percent 0 2>/dev/null || true
# Use parted to set exact size: 500GB total means vda3 ends at ~500GB
parted /dev/vda ---pretend-input-tty resizepart 3 500GB << 'PARTED'
Yes
PARTED
echo "  Partition vda3 resized"

echo ""
echo "=== Step 2: Resize the LVM physical volume ==="
pvresize /dev/vda3
echo "  PV resized"

echo ""
echo "=== Step 3: Extend the logical volume ==="
lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
echo "  LV extended"

echo ""
echo "=== Step 4: Grow the filesystem (online, no unmount needed) ==="
resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
echo "  Filesystem resized"

echo ""
echo "=== Done ==="
df -h /
lsblk /dev/vda
