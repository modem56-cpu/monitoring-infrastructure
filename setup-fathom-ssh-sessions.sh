#!/usr/bin/env bash
set -euo pipefail
#
# Run on fathom-vault (192.168.10.24) with sudo
# Installs SSH session collector for node-exporter textfile
#

TEXTDIR="/var/lib/prometheus/node-exporter"

echo "=== Installing SSH session collector ==="

cat > /usr/local/bin/ssh-sessions-prom.sh << 'SSHEOF'
#!/usr/bin/env bash
set -euo pipefail

TARGET="192.168.10.24"
TEXTDIR="${TEXTDIR:-/var/lib/prometheus/node-exporter}"
OUT="$TEXTDIR/ssh_sessions.prom"
TMP="$(mktemp "$TEXTDIR/.ssh_sessions.prom.tmp.XXXXXX")"

python3 - << 'PY' > "$TMP"
import subprocess, os

TARGET = "192.168.10.24"
HOST = os.popen("hostname -f 2>/dev/null || hostname").read().strip()

def esc(s):
    return (s or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")

# Parse w -h -i for remote sessions
try:
    out = subprocess.check_output(["w", "-h", "-i"], text=True, stderr=subprocess.DEVNULL)
except Exception:
    out = ""

sessions = {}
for line in out.strip().splitlines():
    parts = line.split()
    if len(parts) < 3:
        continue
    user = parts[0]
    src = parts[2]
    # Skip local sessions (tty, :0, etc)
    if not src or src.startswith(":") or src == "-" or "." not in src:
        continue
    key = (user, src)
    sessions[key] = sessions.get(key, 0) + 1

total = sum(sessions.values())

lines = []
lines.append(f'# HELP tower_ssh_sessions_remote_total Remote SSH sessions total')
lines.append(f'# TYPE tower_ssh_sessions_remote_total gauge')
lines.append(f'tower_ssh_sessions_remote_total{{target="{TARGET}",host="{esc(HOST)}"}} {total}')
lines.append(f'# HELP tower_ssh_sessions_user_src Remote SSH sessions by user and source')
lines.append(f'# TYPE tower_ssh_sessions_user_src gauge')

for (user, src), count in sessions.items():
    lines.append(f'tower_ssh_sessions_user_src{{target="{TARGET}",host="{esc(HOST)}",user="{esc(user)}",src="{esc(src)}"}} {count}')

print("\n".join(lines))
PY

mv -f "$TMP" "$OUT"
chmod 0644 "$OUT"
SSHEOF
chmod +x /usr/local/bin/ssh-sessions-prom.sh

echo "=== Creating timer ==="
cat > /etc/systemd/system/ssh-sessions-prom.service << 'SVC'
[Unit]
Description=Collect SSH sessions for Prometheus
[Service]
Type=oneshot
Environment=TEXTDIR=/var/lib/prometheus/node-exporter
ExecStart=/usr/local/bin/ssh-sessions-prom.sh
SVC

cat > /etc/systemd/system/ssh-sessions-prom.timer << 'TMR'
[Unit]
Description=Run SSH session collector every 30 seconds
[Timer]
OnBootSec=10s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now ssh-sessions-prom.timer

echo "=== Test ==="
/usr/local/bin/ssh-sessions-prom.sh
cat /var/lib/prometheus/node-exporter/ssh_sessions.prom

echo ""
echo "=== Done ==="
