# Responsible-use and evidence disclaimer

PHP2Shell contains security research material and potentially disruptive memory-corruption demonstrations. Use it **only on systems you own or have written authorization to assess**, preferably in an isolated environment. Do not use production services as exploit test targets.

The PHP core vulnerabilities described in this repository are documented by the [official PHP project](https://www.php.net/archive/2026.php). This repository's individual exploit implementation, WAF rules, and lab configurations are **not independently certified** by the PHP team, OffSec or the other cited researchers.

- PHP versions in HTTP headers are untrusted indicators; vendors may backport patches.
- An Apache server header does not establish the PHP SAPI.
- The standalone Python fixture is not a real vulnerable PHP installation and does not prove exploitation.
- Sending a payload, seeing a timeout or a crash, or requesting a callback is **not** sufficient evidence of code execution.
- A local proof file must be fresh for the specific test; files from previous runs should not be treated as proof.
- The only reliable remediation is to install a fixed PHP version or a verified vendor security backport. WAF signatures and configuration changes alone are incomplete mitigations.

For the official reports and fixed releases, see [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

Licensing: repository references currently contain conflicting license labels and no signed root license grant. Obtain and confirm the necessary rights to any third-party proof-of-concept source before redistributing under a particular license.
