"""
Standalone PHP2Shell Lab Server (No-Docker)
===========================================
Runs a local HTTP server simulating vulnerable and patched PHP targets
from the lab/app directory without requiring Docker or a local PHP binary.
"""

from __future__ import annotations

import argparse
import http.server
import os
import sys
import threading
import time

APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app")


class StandaloneLabHandler(http.server.BaseHTTPRequestHandler):
    php_version: str = "8.4.26"
    server_software: str = "Apache/2.4.69 (Debian)"
    is_vulnerable: bool = True

    def _send_php_headers(self, status: int = 200, content_type: str = "text/html; charset=UTF-8"):
        self.send_response(status)
        self.send_header("Server", self.server_software)
        self.send_header("X-Powered-By", f"PHP/{self.php_version}")
        self.send_header("X-PHP2Shell-Lab", "standalone-fixture")
        self.send_header("Set-Cookie", "PHPSESSID=labsessionfixture0001; path=/")
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def do_HEAD(self):
        path = self.path.split("?")[0]
        if path in ("/index.php", "/", "/upload.php", "/phpinfo.php", "/admin/index.php", "/api/upload"):
            self._send_php_headers(200)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin/\nDisallow: /uploads/\n")
            return

        if path in ("/sitemap.xml", "/sitemap_index.xml"):
            self.send_response(404)
            self.end_headers()
            return

        if path in ("/index.php", "/"):
            self._send_php_headers(200)
            file_path = os.path.join(APP_DIR, "index.php")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>PHP2Shell Lab Fixture</h1>")
            return

        if path == "/phpinfo.php":
            self._send_php_headers(200)
            file_path = os.path.join(APP_DIR, "phpinfo.php")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>PHP Version</h1><p>8.4.26</p>")
            return

        if path == "/upload.php":
            self._send_php_headers(200)
            self.wfile.write(b"<html><body><form method='POST' enctype='multipart/form-data'><input type='file' name='f'></form></body></html>")
            return

        self._send_php_headers(200)
        self.wfile.write(b"OK")

    def do_POST(self):
        # Behavioral differential response: simulate differential status on deep multipart
        content_type = self.headers.get("Content-Type", "")
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""

        # Check for deep multipart probes (e.g., probe engine or exploit triggers)
        if b"PHP_SESSION_UPLOAD_PROGRESS" in body or b"name=\"f" in body:
            self._send_php_headers(200)
            self.wfile.write(b'{"status":"ok","received":true}')
        else:
            self._send_php_headers(200)
            self.wfile.write(b"POST processed")

    def log_message(self, format, *args):
        # Silence console log spam during automated scans
        pass


def run_lab_server(port: int = 8088, php_version: str = "8.4.26") -> http.server.HTTPServer:
    StandaloneLabHandler.php_version = php_version
    server = http.server.HTTPServer(("127.0.0.1", port), StandaloneLabHandler)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone PHP2Shell Lab Server")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    parser.add_argument("--version", default="8.4.26", help="PHP version to simulate in headers")
    args = parser.parse_args()

    print(f"[*] Starting Standalone PHP2Shell Lab on http://127.0.0.1:{args.port} (Simulating PHP {args.version})...")
    httpd = run_lab_server(args.port, args.version)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Lab stopped.")

