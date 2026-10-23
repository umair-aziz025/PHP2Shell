# PHP2Shell: Critical RCE Vulnerabilities in PHP Core

## CVE-2026-109618 & CVE-2026-109619

**Advisory ID:** PHP2SHELL-2026-001
**Published:** 2026-10-22
**Last Updated:** 2026-10-22
**Severity:** Critical (CVSS 9.2)
**Author:** umair-aziz025

---

## Executive Summary

Two critical remote code execution (RCE) vulnerabilities have been identified in PHP's core request handling and memory management subsystems. These vulnerabilities, tracked as **CVE-2026-109618** and **CVE-2026-109619**, affect PHP versions 5.4 through unpatched releases of PHP 8.2, 8.3, 8.4, and 8.5.

When chained together, these vulnerabilities allow an unauthenticated remote attacker to achieve arbitrary code execution on any server running a vulnerable PHP version behind PHP-FPM, mod_php, or CGI. Authentication and user interaction are not required in confirmed cases. However, the demonstrated exploit paths can require multiple requests, worker reuse, specific PHP builds, and configuration; a universal single-request exploit should not be assumed.

Both vulnerabilities stem from fundamental flaws in PHP's error recovery and global state management during request lifecycle transitions. The first vulnerability (CVE-2026-109618) creates an exploitable memory corruption condition through out-of-memory (OOM) error mishandling, while the second (CVE-2026-109619) leverages stale global state after `longjmp()`-based error recovery to produce a use-after-free primitive.

> **Immediate Action Required:** All PHP deployments should be upgraded to patched versions immediately. See the [Remediation Guide](../remediation/REMEDIATION_GUIDE.md) for detailed instructions.

---

## Vulnerability Details

### CVE-2026-109618 — OOM-Triggered Uninitialized Memory Corruption

| Field | Value |
|---|---|
| **CVE ID** | CVE-2026-109618 |
| **CWE** | CWE-908: Use of Uninitialized Resource |
| **CVSS v4.0** | 9.2 (Critical) |
| **Attack Vector** | Network |
| **Attack Complexity** | High |\n| **Attack Requirements** | Present |
| **Privileges Required** | None |
| **User Interaction** | None |

#### Root Cause

When PHP encounters an out-of-memory (OOM) condition during request processing, the Zend Engine's memory manager (`zend_alloc.c`) triggers an emergency shutdown sequence. This interrupts the normal request parsing pipeline while internal request data structures are only **partially initialized**.

During the subsequent cleanup phase, the engine invokes `sapi_deactivate()` and `php_request_shutdown()`, which unconditionally traverse and operate on these data structures — treating partially initialized, invalid, or uninitialized memory as valid request data. This leads to memory corruption when:

1. **Partially initialized zval structures** are passed to destructors that attempt to free or decrement reference counts on invalid pointers.
2. **Incomplete HashTable entries** in the symbol table are iterated during cleanup, causing reads from uninitialized memory regions.
3. **SAPI-layer buffers** allocated during request startup but not yet populated are freed with incorrect sizes, corrupting the heap allocator's internal metadata.

#### Affected Code Paths

The vulnerability manifests across several interconnected code paths:

- **`Zend/zend_alloc.c`** — The `zend_mm_alloc_heap()` function invokes the OOM handler via `zend_mm_safe_error()`. Under memory pressure, this triggers `longjmp()` to the bailout context, bypassing normal cleanup.

- **`main/SAPI.c` → `sapi_deactivate()`** — Attempts to flush and close SAPI output buffers. When invoked after a partial initialization, it operates on buffer descriptors containing uninitialized length and pointer fields.

- **`main/main.c` → `php_request_shutdown()`** — The master shutdown function iterates through registered shutdown handlers and module deactivation callbacks. Partially initialized module state causes cascading corruption.

- **`Zend/zend_execute_API.c` → `shutdown_executor()`** — Destroys the executor globals, including the symbol table. Uninitialized entries in `EG(symbol_table)` lead to invalid pointer dereferences during `zval_ptr_dtor()` calls.

#### Trigger Mechanism

The OOM condition can be reliably triggered by sending crafted HTTP requests that force excessive memory allocation during the parsing phase. Examples include:

- Requests with extremely large `multipart/form-data` bodies containing thousands of parts
- Deeply nested JSON payloads processed during early request initialization
- Pathological `Content-Length` values combined with specific transfer encodings

The key insight is that the OOM must occur during a **specific window** in the request initialization sequence — after critical data structures have been allocated but before they are fully initialized.

#### Exploitation Primitive

Successful exploitation of CVE-2026-109618 yields a **heap corruption primitive**. The attacker can influence the contents of uninitialized memory through heap shaping (controlling allocations and deallocations via preceding requests on the same worker), transforming the uninitialized memory read into a controlled value. This enables:

- Corruption of heap allocator metadata to gain arbitrary write
- Overwriting of function pointers in adjacent heap objects
- Manipulation of PHP internal structures for control flow hijacking

---

### CVE-2026-109619 — Stale Global State Use-After-Free

| Field | Value |
|---|---|
| **CVE ID** | CVE-2026-109619 |
| **CWE** | CWE-416: Use After Free |
| **CVSS v4.0** | 9.2 (Critical) |
| **Attack Vector** | Network |
| **Attack Complexity** | High |\n| **Attack Requirements** | Present |
| **Privileges Required** | None |
| **User Interaction** | None |

#### Root Cause

PHP maintains per-request state through a set of **global accessor macros** — most notably `SG()` (SAPI Globals), `PG()` (PHP Core Globals), and `EG()` (Executor Globals). These macros resolve to thread-local or process-global structures depending on the SAPI mode (thread-safe vs. non-thread-safe builds).

During normal operation, these globals point to memory that is allocated at request startup and freed at request shutdown. However, when an error condition triggers **`longjmp()`-based bailout recovery** (via `zend_bailout()`), the normal shutdown sequence is partially or fully bypassed. Critically:

1. The **global pointers are not reset** after the error recovery path frees the underlying memory.
2. The next request handled by the **same worker process** inherits the stale global state.
3. When the new request's initialization code reads from `SG()` or `PG()` (e.g., to check configuration or previous request state), it **dereferences a freed pointer** — a classic use-after-free condition.

#### Affected Code Paths

- **`main/main.c` → `php_request_startup()` / `php_request_shutdown()`** — The request lifecycle functions that manage global state allocation and deallocation. The bailout path in `php_request_shutdown()` may skip the reset of `SG(request_info)` and `PG(connection_status)`.

- **`main/SAPI.c` → SAPI module globals** — The `sapi_globals_struct` contains pointers to request-specific data (headers, POST data, cookies). After bailout, `SG(request_info).request_uri` and `SG(request_info).content_type` may point to freed heap memory.

- **`Zend/zend.c` → `zend_bailout()` macro** — Expands to `longjmp(EG(bailout), FAILURE)`, which unwinds the call stack non-locally. This bypass means any cleanup code between the current execution point and the `setjmp()` site is never executed.

- **`sapi/fpm/fpm/fpm_main.c`** — The FPM worker loop that handles request recycling. After a bailed-out request, the worker re-enters the accept loop with corrupted global state.

#### Trigger Mechanism

The stale state condition requires two sequential requests to the same PHP-FPM worker process:

1. **Request 1 (Poison):** A crafted request that triggers `zend_bailout()` during a specific phase of execution. This can be achieved by combining CVE-2026-109618 (OOM trigger) or through other error conditions such as exceeding `max_execution_time`, triggering fatal errors in specific engine paths, or exploiting certain `pcre.backtrack_limit` violations.

2. **Request 2 (Exploit):** A subsequent request routed to the **same worker** that accesses the stale global state. PHP-FPM's default configuration uses a small number of worker processes, making worker reuse highly predictable (often deterministic with `pm = static` and `pm.max_children = 1` in testing environments).

#### Exploitation Primitive

CVE-2026-109619 provides a **use-after-free read/write primitive**:

- **Arbitrary Read:** By controlling the contents of the freed memory region (via heap feng shui on the intervening allocation), the attacker can read arbitrary memory through the stale `SG()` pointer. This is useful for defeating ASLR by leaking heap or library base addresses.

- **Arbitrary Write:** By placing a controlled object over the freed `SG()` region and triggering a write through the stale pointer (e.g., `SG(request_info).request_uri = ...`), the attacker achieves a write-what-where condition.

When combined with the heap corruption from CVE-2026-109618, these primitives form a complete exploit chain: **heap shaping → memory corruption → information leak → arbitrary code execution**.

---

## CVSS v4.0 Score Breakdown

The **official** CVSS v4.0 base score for each advisory is **9.2 (Critical)**. Do not reuse the earlier CVSS v3.1 vector, which has different metrics and produced misleading results.

| Metric | Official value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | High (H) |
| Attack Requirements (AT) | Present (P) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Vulnerable System Confidentiality / Integrity / Availability | High / High / High |
| Subsequent System Confidentiality / Integrity / Availability | None / None / None |

**Official vector (both advisories):** `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.

See the [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) for primary-source scoring.


---

## Affected Versions

| PHP Branch | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| PHP 5.4.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 5.5.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 5.6.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 7.0.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 7.1.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 7.2.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 7.3.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 7.4.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 8.0.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 8.1.x | All versions | ❌ End of Life — No fix available | ⚠️ Upgrade immediately |
| PHP 8.2.x | 8.2.0 – 8.2.34 | ✅ **8.2.35** | 🔄 Upgrade |
| PHP 8.3.x | 8.3.0 – 8.3.35 | ✅ **8.3.36** | 🔄 Upgrade |
| PHP 8.4.x | 8.4.0 – 8.4.26 | ✅ **8.4.27** | 🔄 Upgrade |
| PHP 8.5.x | 8.5.0 – 8.5.11 | ✅ **8.5.12** | 🔄 Upgrade |

---

## Attack Surface Analysis

### PHP-FPM (FastCGI Process Manager)

PHP-FPM serves requests using reusable worker processes, so it is within the affected product scope. However, the upstream stale-state advisory distinguishes **conditional FPM exposure** from a universal default-configuration exploit. Confirmed session-lifecycle demonstrations required a suitable producer during application execution and an early session-upload-progress consumer. Do not equate worker reuse with guaranteed RCE.

### mod_php (Apache Module)

The PHP project identifies Apache **mod_php as the highest-risk deployment** because an unauthenticated attack was demonstrated before application code ran. Applicability still depends on the PHP version, runtime build and exploit-specific memory layout. Do not infer mod_php simply from an `Apache` HTTP Server header: Apache also proxies to PHP-FPM.

### PHP-CGI and other SAPIs

The PHP security announcement considers all PHP installations serving web requests in scope, including php-cgi, LiteSpeed and FrankenPHP. Specific producer/consumer chains differ by SAPI. Pure CGI not retaining worker state does not by itself establish immunity to all reported corruption paths, and a conditional FPM demonstration should not be generalized to CGI. Inventory and patch all serving runtimes rather than treating a SAPI as a fix.

### CLI / CLI-Server

- PHP CLI scripts are typically not exposed to untrusted input via the same attack vector
- Do not expose the built-in development server (`php -S`) to untrusted network traffic; assess its PHP version and configuration separately
- Not typically a production concern but relevant for development environments

**Risk Level: Low (CLI) / High (CLI-Server if exposed)**

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-10-20 | PHP project announced an upcoming critical security release ([PHP mailing list](https://news-web.php.net/php.announce/start/494)) |
| 2026-10-21 | PHP disclosed both CVEs and released corrected PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 ([PHP official news](https://www.php.net/archive/2026.php)) |
| 2026-10-22 | OffSec published its overview and Exploit-DB #52704 ([OffSec blog](https://www.offsec.com/blog/php2shell-critical-vulnerabilities-in-php-core/)) |
| 2026-10-22 | This repository's technical advisory was published |

Earlier private discovery, reporting, review, and release dates were omitted because the cited public sources do not substantiate those entries.

---

## References

- **CVE Records:**
  - [CVE-2026-109618 — MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618)
  - [CVE-2026-109619 — MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619)

- **Primary security advisories:**
  - [CVE-2026-109618: OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
  - [CVE-2026-109619: Stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

- **PHP Security Advisories:**
  - [PHP Changelog — 8.2.35](https://www.php.net/ChangeLog-8.php#8.2.35)
  - [PHP Changelog — 8.3.36](https://www.php.net/ChangeLog-8.php#8.3.36)
  - [PHP Changelog — 8.4.27](https://www.php.net/ChangeLog-8.php#8.4.27)
  - [PHP Changelog — 8.5.12](https://www.php.net/ChangeLog-8.php#8.5.12)

- **Source Code References:**
  - [Zend/zend_alloc.c — PHP Source](https://github.com/php/php-src/blob/master/Zend/zend_alloc.c)
  - [main/main.c — PHP Source](https://github.com/php/php-src/blob/master/main/main.c)
  - [main/SAPI.c — PHP Source](https://github.com/php/php-src/blob/master/main/SAPI.c)

- **Related Research:**
  - [CWE-908: Use of Uninitialized Resource](https://cwe.mitre.org/data/definitions/908.html)
  - [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)

- **Remediation:**
  - [PHP2Shell Remediation Guide](../remediation/REMEDIATION_GUIDE.md)
  - [PHP2Shell Lab Setup](../lab/LAB_SETUP.md)

---

## Disclaimer

This advisory is provided for **defensive and educational purposes only**. The technical details are shared to help security teams understand the risk, prioritize patching, and develop detection capabilities. See [DISCLAIMER.md](../DISCLAIMER.md) for full terms.

---

*Advisory prepared by umair-aziz025 — PHP2Shell Research Project*
