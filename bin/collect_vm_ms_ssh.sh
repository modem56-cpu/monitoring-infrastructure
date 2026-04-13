#!/usr/bin/env bash
set -euo pipefail

HOST="${VPS_HOST:-10.253.2.22}"
USER="metrics"
KEY="/opt/monitoring/sshkeys/vm_ms_metrics_ed25519"
KNOWN="/opt/monitoring/sshkeys/known_hosts"

OUTDIR="/opt/monitoring/textfile_collector"
OUT="$OUTDIR/vps_movement_strategy.prom"
TMP="$(mktemp "$OUTDIR/.vps_movement_strategy.prom.tmp.XXXXXX")"

mkdir -p "$OUTDIR"
touch "$KNOWN"
chmod 0644 "$KNOWN" || true

# ensure host key exists (safe to re-run)
timeout 15 ssh-keyscan -H "$HOST" >> "$KNOWN" 2>/dev/null || true

# forced command prints Prom exposition to stdout
timeout 30 ssh -T -i "$KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=8 \
  -o ServerAliveInterval=10 \
  -o ServerAliveCountMax=2 \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN" \
  -o LogLevel=ERROR \
  "${USER}@${HOST}" > "$TMP"

printf "\n" >> "$TMP"
grep -q '^vps_ssh_up' "$TMP"

mv -f "$TMP" "$OUT"
chmod 0644 "$OUT" || true
