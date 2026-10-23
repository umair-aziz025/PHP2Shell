# PHP2Shell — Verified Security Advisory

**CVE-2026-109618 · CVE-2026-109619**  
**Updated:** October 23, 2026  
**Severity:** Critical — **CVSS v4.0 9.2** for each CVE

This document reflects the PHP project's public security advisories. It does **not** claim that every affected installation is exploitable with the same proof of concept or that the PHP2Shell toolkit has been independently validated across all runtimes.

## Summary

Two critical PHP engine vulnerabilities were publicly disclosed and patched on **October 21, 2026**.

- **CVE-2026-109618** — Out-of-memory (OOM) corruption: interruption of PHP request handling may leave incompletely initialized internal data, which shutdown may subsequently process. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
- **CVE-2026-109619** — Stale global-state use-after-free: worker-persistent globals may retain pointers to freed request-owned memory, which subsequent operations consume. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

The two issues are distinct and do **not** universally require a combined chain. Application authentication does not protect against exploit paths executed before application code begins processing. Upstream reports a **CVSS v4.0** score of **9.2** for each issue; older references in this project incorrectly described 9.2 as a CVSS **v3.1** score.

## Upstream affected and fixed releases

| Branch | First upstream release containing fixes |
|---|---|
| PHP 8.2 | **8.2.35** |
| PHP 8.3 | **8.3.36** |
| PHP 8.4 | **8.4.27** |
| PHP 8.5 | **8.5.12** |

PHP 8.1 and earlier are beyond normal upstream support. The PHP project also supplied **minimal source backports for PHP 7.4, 8.0 and 8.1**, which vendors may incorporate into maintained packages. Check official distribution or image maintainer advisories: a backported fixed package may retain an older upstream-looking version.

Version headers and `php -v` are preliminary signals only. Check the **actual serving runtime** (mod_php, PHP-FPM, CGI variant, container) and the package build. Proxy banners and an Apache `Server` header do not prove that mod_php is in use.

## Runtime differences and verification

**mod_php / Apache:** Upstream confirmed unauthenticated RCE against mod_php for CVE-2026-109618. The [Exploit-DB #52704](https://www.exploit-db.com/exploits/52704) sample is calibrated to specific **PHP 8.4.26, Apache prefork** configurations and hard-coded library/layout offsets. It cannot be assumed portable to any PHP service.

**PHP-FPM:** The upstream OOM advisory identifies a possible attack surface but states that a complete FPM exploit was not demonstrated for that particular path. The stale-state advisory discusses different producer/consumer conditions and includes conditional FPM cases. The blanket claim that FPM is universally or trivially exploitable is unsupported.

**Stale global state:** CVE-2026-109619 requires a state-producing operation and a state-consuming operation, typically on separate requests in the same worker. Describing every exploit as a single crafted HTTP request is incorrect.

**Proof standards:** A sent request, HTTP 500, lost connection, version signature or successful GET of unrelated content is not proof of RCE. Report explicit unverified states and use fresh independent evidence before labeling a system compromised.

**Synthetic fixture:** `lab/standalone_lab.py` is a Python HTTP server simulating PHP headers. It does not run PHP or reproduce memory corruption. It can validate *fingerprinting code*, not CVE exploitation or patch effectiveness.

**Exploit-DB command constraint:** Its example packs a short command into a **167-byte `zend_string` allocation** and documents **14 available command bytes for that specific carrier**. This is a proof-of-concept layout restriction, not a limit imposed on all PHP or shell commands. The repository does not provide validated automatic staging for longer commands.

## Recommended remediation

Apply vendor or upstream security updates and replace all old web workers. Rebuild vulnerable containers, then verify the PHP binary that actually serves traffic.

When updates cannot happen immediately, consult the upstream advisories for **partial** reductions:

- For **CVE-2026-109618**, PHP recommends administratively enforced `memory_limit=-1` alongside robust frontend request limits and container/cgroup safeguards. This is temporary and not a complete fix. Simply lowering PHP's finite memory limit can make controlled OOM easier. Do not treat `RLIMIT_AS` or `RLIMIT_DATA` as safe mitigations for this issue.
- For **CVE-2026-109619**, `session.upload_progress.enabled=0` and, for PHP 8.5, `fatal_error_backtraces=0` may reduce exposure. These settings are **not** complete fixes.
- Bound **decoded** HTTP request sizes and multipart headers/parts at the reverse proxy, even if the incoming request lacks a usable `Content-Length` header.
- WAF rules, worker recycling, hiding PHP headers and restricting shell functions are defense-in-depth, not alternatives to patching.

## Public disclosure milestones

| Date | Verifiable public event |
|---|---|
| **2026-10-21** | PHP published the security releases and upstream advisories |
| **2026-10-21** | Datadog and Wiz published technical analyses |
| **2026-10-22** | OffSec published its research summary and Exploit-DB #52704 |
| **2026-10-23** | This document updated for source accuracy |

Previous versions of this document listed unsupported dates for discovery, private reports, CVE assignment and review. Those claims were removed; the repository does not provide adequate evidence to substantiate them.

## References

1. [PHP — CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
2. [PHP — CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
3. [PHP 8.4.27 Security Release](https://www.php.net/releases/8_4_27.php)
4. [Datadog Security Labs — detection, mitigation, caveats](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
5. [Calif Research — PHP2Shell technical investigation](https://calif.io/php2shell/)
6. [OffSec — PHP2Shell research](https://www.offsec.com/blog/php2shell-critical-vulnerabilities-in-php-core/)
7. [Exploit-DB #52704 — build-specific proof of concept](https://www.exploit-db.com/exploits/52704)
8. [Wiz — PHP2Shell research](https://www.wiz.io/blog/php2shell-php-rce)
9. [Remediation Guide](../remediation/REMEDIATION_GUIDE.md)

*For authorized security testing and defensive research only. Risk assessment must be corroborated against the affected deployment.*
