# PHP2Shell — Remediation Guide

## CVE-2026-109618 & CVE-2026-109619

**Last Updated:** 2026-10-22

---

## Table of Contents

- [Immediate Actions Checklist](#immediate-actions-checklist)
- [Version Upgrade Instructions](#version-upgrade-instructions)
- [Docker / Container Remediation](#docker--container-remediation)
- [Temporary Mitigations](#temporary-mitigations)
- [PHP Configuration Hardening](#php-configuration-hardening)
- [Verification Steps](#verification-steps)
- [Monitoring for Compromise](#monitoring-for-compromise)

---

## Immediate Actions Checklist

**Upstream facts:** The first fixed versions are PHP **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. PHP also published minimal source backports for 7.4, 8.0 and 8.1; vendors may distribute fixes without changing the apparent upstream version. Always verify the actual **web-serving** runtime, not only `php -v`.

[PHP CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [PHP CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)


> ⚠️ **These vulnerabilities are Critical (CVSS 9.2). Treat remediation as an emergency.**

- [ ] **Identify all PHP installations** across your infrastructure (servers, containers, CI/CD runners, development machines)
- [ ] **Determine PHP versions** using `php -v` or the scanner tool in this toolkit
- [ ] **Check SAPI mode** — PHP-FPM and mod_php are highest risk (`php -r "echo php_sapi_name();"`)
- [ ] **Upgrade PHP** to a patched version (see [Version Upgrade Instructions](#version-upgrade-instructions))
- [ ] **Restart PHP-FPM / Apache** after upgrading to ensure new binaries are loaded
- [ ] **Deploy WAF rules** as a temporary layer of defense (see [Temporary Mitigations](#temporary-mitigations))
- [ ] **Harden php.ini** to reduce attack surface (see [PHP Configuration Hardening](#php-configuration-hardening))
- [ ] **Verify the patch** was applied correctly (see [Verification Steps](#verification-steps))
- [ ] **Check for indicators of compromise** (see [Monitoring for Compromise](#monitoring-for-compromise))
- [ ] **Notify your security team** and update your vulnerability tracking system

---

## Version Upgrade Instructions

### Target Versions

| Current Branch | Upgrade To |
|---|---|
| PHP 8.2.x | **8.2.35** |
| PHP 8.3.x | **8.3.36** |
| PHP 8.4.x | **8.4.27** |
| PHP 8.5.x | **8.5.12** |
| PHP ≤ 8.1 | **Upgrade to 8.2.35+ or newer supported branch** |

---

### Ubuntu / Debian

#### Using Ondřej Surý PPA (Recommended)

```bash
# Add the PPA if not already added
sudo add-apt-repository ppa:ondrej/php
sudo apt update

# Upgrade PHP (replace 8.3 with your branch)
sudo apt upgrade php8.3 php8.3-fpm php8.3-cli php8.3-common

# Verify the installed version
php -v

# Restart PHP-FPM
sudo systemctl restart php8.3-fpm

# Restart Apache if using mod_php
sudo systemctl restart apache2
```

#### Using Default Repositories

```bash
# Check if patched version is available
apt-cache policy php8.3

# If available, upgrade
sudo apt update && sudo apt upgrade php8.3*

# Restart services
sudo systemctl restart php8.3-fpm
sudo systemctl restart apache2    # if applicable
sudo systemctl restart nginx      # if applicable
```

> **Note:** Default Ubuntu/Debian repositories may lag behind. If the patched version is not yet available, use the Ondřej Surý PPA or compile from source.

---

### RHEL / CentOS / Rocky Linux / AlmaLinux

#### Using Remi Repository (Recommended)

```bash
# Enable Remi repo if not already enabled
sudo dnf install https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %{rhel}).rpm

# Enable the desired PHP branch
sudo dnf module reset php
sudo dnf module enable php:remi-8.3

# Upgrade PHP
sudo dnf upgrade php php-fpm php-cli php-common

# Verify
php -v

# Restart PHP-FPM
sudo systemctl restart php-fpm

# Restart httpd if using mod_php
sudo systemctl restart httpd
```

#### Using Default Repositories

```bash
sudo dnf update php*
php -v
sudo systemctl restart php-fpm
```

---

### Alpine Linux

```bash
# Update package index
apk update

# Upgrade PHP (replace php83 with your branch)
apk upgrade php83 php83-fpm php83-cli php83-common

# Verify
php -v

# Restart PHP-FPM (OpenRC)
rc-service php-fpm83 restart

# Or if using a container, rebuild from updated base
```

---

### Windows

#### Manual Installation

1. Download the patched PHP build from [windows.php.net](https://windows.php.net/download/)
2. Select the correct build:
   - **Thread Safe (TS)** for Apache mod_php
   - **Non-Thread Safe (NTS)** for IIS/FastCGI and PHP-FPM
3. Extract to your PHP installation directory (e.g., `C:\php`)
4. Replace existing files, preserving your `php.ini`
5. Restart your web server (IIS, Apache)
6. Verify: `php -v`

#### Using Chocolatey

```powershell
choco upgrade php --version=8.3.36
# Restart IIS
iisreset /restart
```

#### Using XAMPP / WAMP / Laragon

- Check for updates from the respective project
- XAMPP: Download updated PHP binaries and replace `C:\xampp\php\`
- WAMP: Use WampServer's PHP version switcher after downloading the update
- Laragon: Menu → Tools → Change PHP Version (after placing updated binaries)

---

## Docker / Container Remediation

### Update Base Images

```dockerfile
# Before (VULNERABLE)
FROM php:8.3.35-fpm-alpine
FROM php:8.4.26-apache

# After (PATCHED)
FROM php:8.3.36-fpm-alpine
FROM php:8.4.27-apache
```

### Rebuild and Redeploy

```bash
# Pull latest images
docker pull php:8.3.36-fpm-alpine

# Rebuild your application image
docker build --no-cache -t myapp:patched .

# Redeploy (Docker Compose)
docker compose pull
docker compose up -d --build

# Verify inside running container
docker exec <container_id> php -v
```

### Scan Running Containers

```bash
# List all running containers with PHP
docker ps --format '{{.ID}} {{.Image}}' | while read id image; do
    version=$(docker exec $id php -v 2>/dev/null | head -1)
    if [ -n "$version" ]; then
        echo "$id | $image | $version"
    fi
done
```

### Kubernetes Deployments

```bash
# Update the image tag in your deployment manifest
kubectl set image deployment/myapp php=php:8.3.36-fpm-alpine

# Or edit the deployment
kubectl edit deployment myapp

# Verify rollout
kubectl rollout status deployment/myapp

# Check PHP version in running pod
kubectl exec <pod-name> -- php -v
```

---

## Temporary Mitigations

> **Important:** These mitigations **reduce risk** but do **not eliminate** the vulnerability. Upgrading PHP is the only complete fix.

### WAF Rules

**Important:** The following example WAF rules are not comprehensive and **must not be treated as sufficient PHP2Shell protection**. Relying only on incoming `Content-Length` is bypassable by requests with missing or unusable lengths. Enforce bounds on *decoded* request sizes, nested input depth, multipart headers and part counts **before PHP parses them**. Consult your WAF vendor's syntax and test before deploying.


#### ModSecurity / OWASP CRS

```apache
# Block requests with excessively large multipart bodies (OOM trigger)
SecRule REQUEST_HEADERS:Content-Type "multipart/form-data" \
    "id:2026001, \
     phase:1, \
     deny, \
     status:413, \
     chain, \
     msg:'PHP2Shell mitigation - excessive multipart body'"
    SecRule REQUEST_HEADERS:Content-Length "@gt 10485760" ""

# Limit the number of multipart parts
SecRule MULTIPART_PART_LIMIT "@gt 100" \
    "id:2026002, \
     phase:1, \
     deny, \
     status:413, \
     msg:'PHP2Shell mitigation - excessive multipart parts'"

# Block abnormally large request headers
SecRule REQUEST_HEADERS_NAMES "" \
    "id:2026003, \
     phase:1, \
     deny, \
     status:431, \
     chain, \
     msg:'PHP2Shell mitigation - oversized headers'"
    SecRule &REQUEST_HEADERS "@gt 100" ""
```

#### Nginx Rate Limiting

```nginx
# Limit request body size
client_max_body_size 10m;

# Limit request rate per IP
limit_req_zone $binary_remote_addr zone=php2shell:10m rate=30r/s;

server {
    location ~ \.php$ {
        limit_req zone=php2shell burst=10 nodelay;
        # ... existing fastcgi_pass config ...
    }
}
```

#### Cloudflare / CDN-Level Rules

- Create a WAF rule to block requests with `Content-Length > 10MB` to PHP endpoints
- Enable Bot Management to filter automated exploitation attempts
- Set rate limiting rules for PHP endpoints (e.g., 30 requests/second per IP)

### PHP-FPM Hardening

```ini
; /etc/php/8.3/fpm/pool.d/www.conf

; Worker recycling is not a validated complete mitigation for CVE-2026-109619
pm.max_requests = 500

; Limit request processing time
request_terminate_timeout = 30s

; Limit request body size at FPM level
php_admin_value[post_max_size] = 10M
php_admin_value[upload_max_filesize] = 10M
```

---

## PHP Configuration Hardening

### php.ini Recommendations

```ini
; =============================================================
; PHP2Shell Hardening — php.ini settings
; Apply to your production php.ini (cli and fpm)
; =============================================================

; --- Memory Limits ---
; AFTER PATCHING, apply resource limits appropriate to your app.
; BEFORE PATCHING CVE-2026-109618, upstream guidance instead calls
; for administrator-enforced memory_limit=-1, strict frontend request
; controls and container memory safeguards. That is only temporary.
; Merely lowering a finite PHP memory_limit can facilitate controlled OOM.
; Do NOT copy this normal post-patch example as an emergency fix.
memory_limit = 128M

; --- Request Size Limits ---
; Limit POST data and file uploads
post_max_size = 10M
upload_max_filesize = 10M
max_file_uploads = 20

; --- Input Limits ---
; Limit input variables to prevent resource exhaustion
max_input_vars = 1000
max_input_nesting_level = 64
max_input_time = 60

; --- Execution Limits ---
max_execution_time = 30
max_input_time = 60

; --- Disable Dangerous Functions ---
; Defense in depth only; NOT a PHP2Shell fix.
; Remove any functions your application does not need
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,pcntl_exec

; --- Error Handling ---
; Never expose errors in production
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log

; --- Session Hardening ---
; CVE-2026-109619 partial reductions pending patch (not full fixes):
; session.upload_progress.enabled = 0
; PHP 8.5: fatal_error_backtraces = 0
; Enforce before PHP request parsing and restart all workers.
session.cookie_httponly = On
session.cookie_secure = On
session.use_strict_mode = On

; --- Miscellaneous ---
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
```

### Apply and Restart

```bash
# After editing php.ini, restart PHP-FPM
sudo systemctl restart php8.3-fpm

# Verify settings
php -i | grep memory_limit
php -i | grep disable_functions
```

---

## Verification Steps

### 1. Verify PHP Version

```bash
# CLI version
php -v

# Expected output (example for 8.3):
# PHP 8.3.36 (cli) (build timestamp depends on the package; release announced Oct 21 2026) (NTS)

# FPM version (may differ from CLI)
php-fpm8.3 -v

# Or check via phpinfo()
php -r "phpinfo();" | grep "PHP Version"
```

### 2. Verify via HTTP

Create a temporary test script (remove immediately after testing):

```php
<?php
// /tmp/version_check.php — DELETE AFTER USE
echo "PHP Version: " . phpversion() . "\n";
echo "SAPI: " . php_sapi_name() . "\n";
echo "Zend Version: " . zend_version() . "\n";
```

```bash
curl -s http://localhost/version_check.php
# Verify the version matches the patched release
# DELETE the test script immediately after
```

### 3. Use the PHP2Shell Scanner

```bash
# Run the scanner from this toolkit
python php2shell.py http://127.0.0.1:8080/ --json

# Expected output for a patched server:
# [✓] PHP 8.3.36 — NOT VULNERABLE
```

### 4. Verify PHP-FPM Worker Recycling

```bash
# Check that pm.max_requests is set
grep -r "pm.max_requests" /etc/php/*/fpm/pool.d/

# Verify workers are being recycled (watch PID changes)
watch -n 5 "ps aux | grep php-fpm"
```

### 5. Verify WAF Rules

```bash
# Validate the documented request-size limit in an isolated test environment.
# Use a finite test payload and inspect reverse-proxy/WAF logs for the result.
# An HTTP 413 or 403 response is not guaranteed on every deployment.
# Never stream /dev/urandom directly: it has no natural end-of-file.
```

---

## Monitoring for Compromise

### Indicators of Compromise (IOCs)

If your servers were running vulnerable PHP versions before patching, check for the following indicators:

#### Log Analysis

```bash
# Check for unusual OOM errors in PHP logs (potential CVE-2026-109618 exploitation)
grep -i "out of memory" /var/log/php/*.log
grep -i "allowed memory size" /var/log/php/*.log

# Check for abnormal PHP-FPM worker crashes
grep -i "segfault\|signal 11\|SIGSEGV" /var/log/syslog /var/log/messages
journalctl -u php8.3-fpm | grep -i "segfault\|signal\|exited"

# Check for unusual POST requests with large bodies
awk '$9 == 413 || $10 > 10485760' /var/log/nginx/access.log
grep "POST" /var/log/apache2/access.log | awk '{if ($NF > 10485760) print}'

# Check for rapid sequential requests to the same worker
# (Indicative of CVE-2026-109619 exploitation — poison + exploit pattern)
```

#### File System Checks

```bash
# Look for webshells or unauthorized PHP files (common post-exploitation)
find /var/www -name "*.php" -newer /var/www/index.php -mtime -30
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|exec\|passthru" {} \;

# Check for unexpected SUID/SGID files
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Check for unauthorized cron jobs
crontab -l
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*
```

#### Network Indicators

```bash
# Check for unexpected outbound connections from PHP-FPM processes
ss -tnp | grep php-fpm
lsof -i -P -n | grep php-fpm

# Check for connections to known C2 infrastructure
# (Cross-reference with threat intelligence feeds)

# Check for DNS queries to suspicious domains
# (Review DNS logs or use passive DNS monitoring)
```

#### Process Analysis

```bash
# Check for unusual processes spawned by PHP-FPM
pstree -p $(pgrep -o php-fpm) | grep -v php-fpm

# Check for processes running as the PHP-FPM user (www-data)
ps aux | grep www-data | grep -v php-fpm

# Check for unexpected network listeners
ss -tlnp | grep -v -E "(nginx|apache|php-fpm|sshd)"
```

### Response Actions

If compromise indicators are found:

1. **Isolate** the affected server from the network immediately
2. **Preserve** logs and forensic evidence before making changes
3. **Capture** memory dumps of running PHP-FPM processes if possible
4. **Document** all findings with timestamps
5. **Engage** your incident response team or a qualified IR firm
6. **Report** the incident to relevant authorities if required (e.g., data protection regulations)
7. **Rebuild** affected systems from known-good backups after forensic analysis
8. **Rotate** all secrets, API keys, database credentials, and certificates that may have been exposed

---

## Additional Resources

- [Technical Advisory](../advisory/TECHNICAL_ADVISORY.md) — Full vulnerability details
- [Lab Setup Guide](../lab/LAB_SETUP.md) — Set up a safe testing environment
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)

---

*Remediation guide prepared by umair-aziz025 — PHP2Shell Research Project*
