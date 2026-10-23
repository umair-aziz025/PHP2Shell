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
import re
import subprocess
import sys
import threading
import time
import urllib.parse

APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app")


class StandaloneLabHandler(http.server.BaseHTTPRequestHandler):
    php_version: str = "8.4.26"
    server_software: str = "Apache/2.4.69 (Debian)"
    is_vulnerable: bool = True
    simulate_real: bool = True
    active_webshells: dict = {}  # path -> param

    def _send_php_headers(self, status: int = 200, content_type: str = "text/html; charset=UTF-8"):
        self.send_response(status)
        self.send_header("Server", self.server_software)
        self.send_header("X-Powered-By", f"PHP/{self.php_version}")
        if not self.simulate_real:
            self.send_header("X-PHP2Shell-Lab", "standalone-fixture")
        self.send_header("Set-Cookie", "PHPSESSID=labsessionfixture0001; path=/")
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def do_HEAD(self):
        path = self.path.split("?")[0]
        if path in self.active_webshells:
            self._send_php_headers(200)
            return

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

        if path in self.active_webshells:
            self._send_php_headers(200)
            self.wfile.write(b"OK")
            return

        self._send_php_headers(200)
        self.wfile.write(b"OK")

    def do_POST(self):
        path = self.path.split("?")[0]
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""

        # Check if this request is hitting an active webshell
        if path in self.active_webshells or path.endswith(".php") and ("p2s_shell" in path or "shell" in path):
            param = self.active_webshells.get(path, "cmd")
            # Parse form data
            parsed = urllib.parse.parse_qs(body.decode("latin1", errors="replace"))
            command = ""
            for k, vals in parsed.items():
                if k == param or "echo" in vals[0] or ";" in vals[0]:
                    param = k
                    command = vals[0]
                    self.active_webshells[path] = param
                    break

            if not command and param in parsed:
                command = parsed[param][0]

            if not command and body:
                # Direct string fallback
                m = re.search(r"(?:^|&)" + re.escape(param) + r"=([^&]*)", body.decode("latin1", errors="replace"))
                if m:
                    command = urllib.parse.unquote_plus(m.group(1))

            output = ""
            if command:
                clean_cmd = command.strip().rstrip(";")
                if clean_cmd.startswith("echo ") and ("P2S_VERIFIED" in clean_cmd):
                    output = "P2S_VERIFIED\n"
                elif clean_cmd == "whoami":
                    output = "www-data\n"
                elif clean_cmd == "hostname":
                    output = "php2shell-lab\n"
                elif clean_cmd == "pwd":
                    output = "/var/www/html\n"
                else:
                    try:
                        res = subprocess.run(clean_cmd, shell=True, capture_output=True, text=True, timeout=5)
                        output = res.stdout + res.stderr
                    except Exception as e:
                        output = f"Execution output: {e}\n"

            self._send_php_headers(200)
            self.wfile.write(f"===P2S_START===\n{output}===P2S_END===\n".encode())
            return

        # Check for deep multipart probes (Stage 3 differential simulation)
        if b"PHP2ShellNestedProbe" in body or b"nested_array" in body or b"[a]" * 20 in body:
            self.send_response(500)
            self.send_header("Server", self.server_software)
            self.send_header("X-Powered-By", f"PHP/{self.php_version}")
            self.send_header("Content-Type", "text/html; charset=UTF-8")
            self.end_headers()
            self.wfile.write(b"Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 2048 bytes) in Unknown on line 0\n")
            return

        if b"PHP2ShellUploadProbe" in body:
            self.send_response(500)
            self.send_header("Server", self.server_software)
            self.send_header("X-Powered-By", f"PHP/{self.php_version}")
            self.send_header("Content-Type", "text/html; charset=UTF-8")
            self.end_headers()
            self.wfile.write(b"Fatal error: zend_mm_heap corrupted in Unknown on line 0\n")
            return

        # Check for webshell drop attempts (Stage 5 persistence dropper)
        if b"p2s_shell.php" in body or b"uninit_file" in body or b"P2S_START" in body or b"eval(base64_decode" in body:
            # Extract webshell parameter and filename
            m_fn = re.search(rb'filename="([^"]+\.php)"', body)
            ws_name = m_fn.group(1).decode() if m_fn else "p2s_shell.php"
            m_param = re.search(r"\$_REQUEST\['([a-zA-Z0-9_]+)'\]", body.decode("latin1", errors="replace"))
            ws_param = m_param.group(1) if m_param else "cmd"

            # Register webshell at multiple candidate routes
            for prefix in ("", "/", "/uploads/"):
                route = f"{prefix}{ws_name}" if prefix.startswith("/") else f"/{ws_name}"
                self.active_webshells[route] = ws_param
                self.active_webshells[f"/uploads/{ws_name}"] = ws_param

            self._send_php_headers(200)
            self.wfile.write(b'{"status":"ok","persisted":true}')
            return

        self._send_php_headers(200)
        self.wfile.write(b"POST processed")

    def log_message(self, format, *args):
        # Silence console log spam during automated scans
        pass


def run_lab_server(port: int = 8899, php_version: str = "8.4.26", simulate_real: bool = True) -> http.server.HTTPServer:
    StandaloneLabHandler.php_version = php_version
    StandaloneLabHandler.simulate_real = simulate_real
    server = http.server.HTTPServer(("127.0.0.1", port), StandaloneLabHandler)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone PHP2Shell Lab Server")
    parser.add_argument("--port", type=int, default=8899, help="Port to listen on (default: 8899)")
    parser.add_argument("--version", default="8.4.26", help="PHP version to simulate in headers")
    parser.add_argument("--fixture-header", action="store_true", help="Include synthetic fixture header")
    args = parser.parse_args()

    sim_real = not args.fixture_header
    print(f"[*] Starting Standalone PHP2Shell Lab on http://127.0.0.1:{args.port} (Simulating PHP {args.version})...")
    httpd = run_lab_server(args.port, args.version, simulate_real=sim_real)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Lab stopped.")

