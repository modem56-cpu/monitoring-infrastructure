#!/usr/bin/env bash
set -euo pipefail

# Allow SSH ONLY from these sources
ALLOWED=(
  "10.253.2.2/32"
  "31.170.165.94/32"
  "192.168.1.0/24"
  "192.168.10.0/24"
  "192.168.5.0/24"
)

# Extra safety: allow the IP of your current SSH session (prevents lockout)
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  CUR_IP="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
  ALLOWED+=("${CUR_IP}/32")
fi

# 1) Keep existing connections working
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2) Allow loopback
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null \
  || iptables -I INPUT 2 -i lo -j ACCEPT

# 3) Allow SSH from allowlisted IPs/subnets
pos=3
for src in "${ALLOWED[@]}"; do
  [[ -z "$src" ]] && continue
  iptables -C INPUT -p tcp -s "$src" --dport 22 -j ACCEPT 2>/dev/null \
    || iptables -I INPUT "$pos" -p tcp -s "$src" --dport 22 -j ACCEPT
  pos=$((pos+1))
done

# 4) Drop SSH from everyone else (ONLY port 22)
iptables -C INPUT -p tcp --dport 22 -j DROP 2>/dev/null \
  || iptables -A INPUT -p tcp --dport 22 -j DROP

echo "OK: SSH allowlist applied (only tcp/22)."
echo
iptables -L INPUT -n --line-numbers | sed -n '1,120p'
