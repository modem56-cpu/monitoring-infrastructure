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
