#!/usr/bin/env bash
set -euo pipefail

# Fix device-json-server:
# 1. Replace python3 -m http.server with HTTP/1.0 server (no keep-alive)
# 2. Open port 9117 to akvorado Docker bridge (247.16.14.0/24) via UFW
# Run as: sudo bash /opt/monitoring/deploy-fix-json-server.sh

cat > /opt/monitoring/bin/json-server.py << 'PYEOF'
#!/usr/bin/env python3
"""Device JSON server — HTTP/1.0 (no keep-alive) to prevent Go client connection reuse issues."""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

DATA_DIR = sys.argv[1] if len(sys.argv) > 1 else "/opt/monitoring/data"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9117

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # disables keep-alive entirely

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def do_GET(self):
        path = self.path.lstrip("/") or "index.json"
        filepath = Path(DATA_DIR) / path
        if not filepath.exists() or not filepath.is_file():
            self.send_response(404)
            self.end_headers()
            return
        data = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Serving {DATA_DIR} on port {PORT} (HTTP/1.0, no keep-alive)", flush=True)
    server.serve_forever()
PYEOF

chmod +x /opt/monitoring/bin/json-server.py

cat > /etc/systemd/system/device-json-server.service << 'SVCEOF'
[Unit]
Description=Device JSON server for Akvorado network-sources (:9117)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/monitoring/bin/json-server.py /opt/monitoring/data 9117
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl restart device-json-server.service

# Allow akvorado bridge subnet to reach port 9117
echo "Opening port 9117 to akvorado bridge 247.16.14.0/24..."
ufw allow from 247.16.14.0/24 to any port 9117 comment "Akvorado network-sources JSON"
ufw reload

sleep 2
systemctl status device-json-server.service --no-pager -l | tail -5

echo ""
echo "=== Test from host ==="
curl -s -o /dev/null -w "Host→9117: %{http_code}\n" http://127.0.0.1:9117/network_devices.json

echo ""
echo "=== Test from within akvorado Docker network ==="
docker run --rm --network akvorado_default alpine/curl:latest \
  curl -s -o /dev/null -w "Container→9117: %{http_code}\n" \
  http://247.16.14.1:9117/network_devices.json 2>/dev/null

echo ""
echo "Done. Watch orchestrator logs with:"
echo "  docker logs -f akvorado-akvorado-orchestrator-1 2>&1 | grep 'data source'"
