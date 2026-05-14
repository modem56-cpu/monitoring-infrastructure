#!/usr/bin/env python3
"""
Monitoring report file server.

Serves /opt/monitoring/reports/ as static files on port 8088.
Supports a download endpoint that forces browser file download:

  GET /monitoring_report.json           → inline (view in browser)
  GET /monitoring_report.json?download=1 → attachment (force download)
"""
import os
import mimetypes
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

SERVE_DIR = "/opt/monitoring/reports"
BIND_ADDR = "0.0.0.0"
PORT = 8088


class ReportHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress per-request stdout noise; errors still go to stderr
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        force_download = "download" in params

        # Resolve file path, block directory traversal
        rel = parsed.path.lstrip("/") or "index.html"
        file_path = os.path.realpath(os.path.join(SERVE_DIR, rel))
        if not file_path.startswith(os.path.realpath(SERVE_DIR)):
            self._send_error(403, "Forbidden")
            return

        if not os.path.isfile(file_path):
            self._send_error(404, "Not Found")
            return

        mime, _ = mimetypes.guess_type(file_path)
        if mime is None:
            mime = "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except OSError:
            self._send_error(500, "Internal Server Error")
            return

        filename = os.path.basename(file_path)
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        if force_download:
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{filename}"'
            )
        else:
            self.send_header(
                "Content-Disposition",
                f'inline; filename="{filename}"'
            )
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, code, message):
        body = message.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = HTTPServer((BIND_ADDR, PORT), ReportHandler)
    print(f"Serving {SERVE_DIR} on {BIND_ADDR}:{PORT}")
    server.serve_forever()
