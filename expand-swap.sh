#!/usr/bin/env bash
# expand-swap.sh
# Adds a second 4 GB swapfile to bring total swap from 4 GB to 8 GB.
# The server runs Wazuh Indexer (1 GB JVM) + Kafka (1 GB JVM) + ZAP (384 MB JVM)
# + Suricata + ClickHouse + Prometheus — total working set exceeds available RAM.
# This is a mitigation until RAM is upgraded.
# Run as root.
set -euo pipefail

SWAPFILE="/swap2.img"
SIZE_GB=4

if swapon --show | grep -q "$SWAPFILE"; then
  echo "  $SWAPFILE is already active."
  swapon --show
  exit 0
fi

if [ -f "$SWAPFILE" ]; then
  echo "  $SWAPFILE exists but is not active — activating..."
else
  echo "Creating ${SIZE_GB}G swapfile at $SWAPFILE..."
  fallocate -l ${SIZE_GB}G "$SWAPFILE"
  chmod 600 "$SWAPFILE"
  mkswap "$SWAPFILE"
fi

echo "Activating $SWAPFILE..."
swapon "$SWAPFILE"

echo ""
echo "Persisting in /etc/fstab..."
if grep -q "$SWAPFILE" /etc/fstab; then
  echo "  Already in /etc/fstab."
else
  echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  echo "  Added to /etc/fstab."
fi

echo ""
echo "Current swap:"
swapon --show
free -h
