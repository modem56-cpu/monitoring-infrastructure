#!/usr/bin/env bash
# Allow Docker containers on monitoring network to reach Wazuh Indexer (port 9200) on host.
# Also updates Grafana datasource URL to use the correct host IP.
set -euo pipefail

DOCKER_BRIDGE_IP="172.18.0.1"   # monitoring_monitoring bridge gateway on host
DOCKER_SUBNET="172.18.0.0/16"

echo "=== Fix: Grafana → Wazuh Indexer connectivity ==="
echo ""

# ── 1. Allow Docker monitoring subnet → host port 9200 ──────────────────────
echo "Step 1: iptables — allow $DOCKER_SUBNET → port 9200"
# Insert before any DROP/REJECT rules
iptables -I INPUT 1 -s "$DOCKER_SUBNET" -p tcp --dport 9200 -j ACCEPT
echo "  iptables rule added"

# Persist via UFW (if active)
if ufw status | grep -q "Status: active"; then
  ufw allow from "$DOCKER_SUBNET" to any port 9200 comment "Docker→Wazuh Indexer"
  echo "  UFW rule added"
else
  echo "  UFW not active — iptables rule sufficient"
fi

echo ""
echo "Step 2: Verify port 9200 is reachable from docker bridge IP"
curl -sk -u kibanaserver:77RmIguYcnHPxjMJqG0EgeEsaIWLL3bE \
  "https://$DOCKER_BRIDGE_IP:9200/" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  OK — cluster: {d[\"cluster_name\"]}  version: {d[\"version\"][\"number\"]}')
" || echo "  WARN: still unreachable at $DOCKER_BRIDGE_IP — check wazuh-indexer network.host"

echo ""
echo "Step 3: Update Grafana Wazuh Indexer datasource URL"
# Find datasource by name
DS_ID=$(curl -sf -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  http://127.0.0.1:3000/api/datasources/name/Wazuh%20Indexer | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "  Datasource id: $DS_ID"

curl -sf -X PUT "http://127.0.0.1:3000/api/datasources/$DS_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  -d "{
    \"id\": $DS_ID,
    \"name\": \"Wazuh Indexer\",
    \"type\": \"elasticsearch\",
    \"url\": \"https://$DOCKER_BRIDGE_IP:9200\",
    \"access\": \"proxy\",
    \"basicAuth\": true,
    \"basicAuthUser\": \"kibanaserver\",
    \"secureJsonData\": {
      \"basicAuthPassword\": \"77RmIguYcnHPxjMJqG0EgeEsaIWLL3bE\"
    },
    \"jsonData\": {
      \"index\": \"wazuh-alerts-4.x-*\",
      \"timeField\": \"@timestamp\",
      \"esVersion\": \"7.10.0\",
      \"maxConcurrentShardRequests\": 5,
      \"logMessageField\": \"full_log\",
      \"logLevelField\": \"rule.level\",
      \"tlsSkipVerify\": true,
      \"serverName\": \"localhost\"
    },
    \"isDefault\": false
  }" | python3 -c "import json,sys; r=json.load(sys.stdin); print(f'  Datasource update: {r.get(\"message\")}')"

echo ""
echo "Step 4: Health check Wazuh Indexer datasource in Grafana"
curl -sf -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  "http://127.0.0.1:3000/api/datasources/$DS_ID/health" | python3 -m json.tool || \
  echo "  Health check endpoint not supported for this plugin type — check Grafana UI"

echo ""
echo "=== Done ==="
echo "Open http://192.168.10.20:3000 → Connections → Data Sources → Wazuh Indexer → Test"
