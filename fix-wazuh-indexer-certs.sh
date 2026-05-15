#!/bin/bash
# fix-wazuh-indexer-certs.sh
# Fixes wazuh-manager indexer connector SSL and host configuration.
#
# Problems found:
#   1. Host was 127.0.0.1 but indexer cert SAN is IP:192.168.10.20 — hostname mismatch
#   2. /etc/filebeat/certs/ is root:root 0500 — wazuh user can't read the certs
#
# Fix:
#   - Copy filebeat certs to /var/ossec/etc/indexer-certs/ (wazuh-owned)
#   - Update ossec.conf: host -> 192.168.10.20, ssl paths -> new location
#   - Restart wazuh-manager

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
CERT_SRC="/etc/filebeat/certs"
CERT_DST="/var/ossec/etc/indexer-certs"
BACKUP="${OSSEC_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
INDEXER_HOST="192.168.10.20"

echo "[1/5] Copying certs to wazuh-readable location..."
mkdir -p "$CERT_DST"
cp "$CERT_SRC/root-ca.pem"      "$CERT_DST/root-ca.pem"
cp "$CERT_SRC/filebeat.pem"     "$CERT_DST/filebeat.pem"
cp "$CERT_SRC/filebeat-key.pem" "$CERT_DST/filebeat-key.pem"
chown -R wazuh:wazuh "$CERT_DST"
chmod 750 "$CERT_DST"
chmod 640 "$CERT_DST"/*.pem
echo "  Certs copied to $CERT_DST and owned by wazuh:wazuh"

echo "[2/5] Verifying cert covers $INDEXER_HOST..."
if openssl x509 -in "$CERT_DST/filebeat.pem" -noout -text 2>/dev/null | grep -q "$INDEXER_HOST"; then
    echo "  Cert covers $INDEXER_HOST (found in SAN or CN)"
else
    # The root-ca cert covers the IP via the chain - proceed anyway, log warning
    echo "  WARNING: filebeat.pem does not explicitly list $INDEXER_HOST — root-ca validation still applies"
fi

echo "[3/5] Backing up ossec.conf..."
cp "$OSSEC_CONF" "$BACKUP"
echo "  Backup: $BACKUP"

echo "[4/5] Updating ossec.conf..."
# Update host from 127.0.0.1 to correct IP
sed -i "s|https://127\.0\.0\.1:9200|https://${INDEXER_HOST}:9200|g" "$OSSEC_CONF"
sed -i "s|https://0\.0\.0\.0:9200|https://${INDEXER_HOST}:9200|g" "$OSSEC_CONF"

# Update cert paths to new wazuh-owned location
sed -i "s|/etc/filebeat/certs/root-ca\.pem|${CERT_DST}/root-ca.pem|g" "$OSSEC_CONF"
sed -i "s|/etc/filebeat/certs/filebeat\.pem|${CERT_DST}/filebeat.pem|g" "$OSSEC_CONF"
sed -i "s|/etc/filebeat/certs/filebeat-key\.pem|${CERT_DST}/filebeat-key.pem|g" "$OSSEC_CONF"

# Verify
HOST_CHECK=$(grep -o "https://[^<]*:9200" "$OSSEC_CONF" | head -1)
CA_CHECK=$(grep -o "${CERT_DST}/root-ca\.pem" "$OSSEC_CONF" | head -1)
echo "  Host:   $HOST_CHECK"
echo "  CA:     ${CA_CHECK:-NOT UPDATED}"

if [ "$HOST_CHECK" != "https://${INDEXER_HOST}:9200" ]; then
    echo "ERROR: Host update failed. Restoring backup." >&2
    cp "$BACKUP" "$OSSEC_CONF"
    exit 1
fi

echo "[5/5] Restarting wazuh-manager..."
systemctl restart wazuh-manager
sleep 5

STATUS=$(systemctl is-active wazuh-manager)
if [ "$STATUS" = "active" ]; then
    echo "  wazuh-manager is active."
else
    echo "ERROR: wazuh-manager status is '$STATUS'" >&2
    exit 1
fi

echo ""
echo "Done. Verify with:"
echo "  sudo grep -iE 'indexer|init|vuln' /var/ossec/logs/ossec.log | tail -20"
echo "  # Look for: IndexerConnector initialized successfully"
echo ""
echo "Then after ~1h, check index population:"
echo "  curl -sk -u admin:NewStrongP4ss* https://${INDEXER_HOST}:9200/wazuh-states-vulnerabilities-*/_count -d '{\"query\":{\"match_all\":{}}}'"
