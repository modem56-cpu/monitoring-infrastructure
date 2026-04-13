#!/usr/bin/env bash
set -euo pipefail

echo "=== Fix 1: ContainerHighMemory alert (false positive — no memory limits) ==="
# Change rule to only alert when a limit is actually set
sed -i 's|expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!=""}) \* 100 > 90|expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!="",container_spec_memory_limit_bytes!="0"}) * 100 > 90 and container_spec_memory_limit_bytes{name!=""} > 0|' /opt/monitoring/rules/containers.rules.yml

# Actually simpler — rewrite the rule properly
python3 << 'PY'
import re
path = "/opt/monitoring/rules/containers.rules.yml"
with open(path) as f:
    content = f.read()

# Fix ContainerHighMemory
old = '''  - alert: ContainerHighMemory
    expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!=""}) * 100 > 90
    for: 5m'''
new = '''  - alert: ContainerHighMemory
    expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!=""}) * 100 > 90 and container_spec_memory_limit_bytes{name!=""} > 0
    for: 5m'''

if old in content:
    content = content.replace(old, new)
    with open(path, 'w') as f:
        f.write(content)
    print("  Fixed ContainerHighMemory rule")
else:
    # Try alternate fix
    content = re.sub(
        r'expr: \(container_memory_usage_bytes.*?\) \* 100 > 90',
        'expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!=""}) * 100 > 90 and container_spec_memory_limit_bytes{name!=""} > 0',
        content
    )
    with open(path, 'w') as f:
        f.write(content)
    print("  Fixed ContainerHighMemory rule (alternate)")
PY

echo ""
echo "=== Fix 2: APIEndpointDown — fix Akvorado traefik URL ==="
# Change the probe URL to the correct endpoint
sed -i "s|http://akvorado-traefik-1:8080/api/overview|http://akvorado-akvorado-console-1:8080/api/v0/console/configuration|" /opt/monitoring/prometheus.yml
echo "  Fixed Akvorado API probe URL"

echo ""
echo "=== Fix 3: Remove fathom-vault from NodeDown (known offline) ==="
# Remove 10.24 from prometheus targets to stop the alert
python3 << 'PY'
path = "/opt/monitoring/prometheus.yml"
with open(path) as f:
    content = f.read()

# Comment out or remove fathom-vault target
old = '''  - job_name: node_ubuntu_192_168_10_24
    static_configs:
      - targets: ["192.168.10.24:9100"]
        labels:
          alias: "fathom-vault-server"

'''
if old in content:
    content = content.replace(old, '  # fathom-vault (10.24) — offline, excluded\n\n')
    with open(path, 'w') as f:
        f.write(content)
    print("  Removed fathom-vault from scrape targets")
else:
    print("  Could not find fathom-vault target block")
PY

echo ""
echo "=== Fix 4: Remove stale snmp-exporter duplicate container ==="
docker rm -f serene_herschel 2>/dev/null && echo "  Removed orphan container serene_herschel" || echo "  No orphan to remove"

echo ""
echo "=== Restart Prometheus ==="
docker restart prometheus 2>&1

echo ""
echo "=== Verify ==="
sleep 3
curl -s 'http://127.0.0.1:9090/api/v1/alerts' | python3 -c "
import sys,json
d=json.load(sys.stdin)
firing=[a for a in d.get('data',{}).get('alerts',[]) if a['state']=='firing']
print(f'  Firing alerts: {len(firing)}')
for a in firing:
    print(f'    {a[\"labels\"].get(\"alertname\",\"\")} — {a[\"labels\"].get(\"instance\",\"\")}')
" 2>/dev/null

echo ""
echo "=== Done ==="
