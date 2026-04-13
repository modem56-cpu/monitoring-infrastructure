#!/usr/bin/env bash
set -euo pipefail

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

# Use 'who' — more reliable format: user tty date (ip)
try:
    out = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
except Exception:
    out = ""

sessions = {}
for line in out.strip().splitlines():
    parts = line.split()
    if len(parts) < 3:
        continue
    user = parts[0]
    # Find IP in parentheses at end: (10.253.2.2)
    src = ""
    if "(" in line and ")" in line:
        src = line[line.rindex("(")+1:line.rindex(")")]
    if not src or src.startswith(":") or "." not in src:
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

# Test it
/usr/local/bin/ssh-sessions-prom.sh
cat /var/lib/prometheus/node-exporter/ssh_sessions.prom
