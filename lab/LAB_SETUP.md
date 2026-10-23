# PHP2Shell — Lab Environment Setup Guide

## Safely Testing Against Vulnerable PHP Versions

**Last Updated:** 2026-10-22

---

## ⚠️ Safety Warning

> **This lab environment runs intentionally vulnerable PHP versions.** It is designed for security research, scanner validation, and educational purposes only. Follow all isolation recommendations carefully.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Network Isolation](#network-isolation)
- [Quick Start](#quick-start)
- [Docker Compose Setup](#docker-compose-setup)
- [Running the Scanner Against the Lab](#running-the-scanner-against-the-lab)
- [Teardown](#teardown)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Docker Engine | 24.0+ | [Install Docker](https://docs.docker.com/engine/install/) |
| Docker Compose | 2.20+ | Included with Docker Desktop |
| Python | 3.9+ | For running the PHP2Shell scanner |
| Git | 2.30+ | To clone this repository |
| RAM | 4 GB free | For running 5 PHP containers simultaneously |
| Disk | 2 GB free | For Docker images |

### Verify Prerequisites

```bash
docker --version          # Docker Engine 24.0+
docker compose version    # Docker Compose v2.20+
python3 --version         # Python 3.9+
git --version             # Git 2.30+
```

---

## Architecture Overview

The lab deploys five PHP-FPM containers, each running a different PHP version — four vulnerable and one patched for comparison:

```
┌────────────────────────────────────────────────────────────┐
│                   Host Machine                             │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          php2shell-lab (Isolated Docker Network)      │  │
│  │                   172.28.0.0/16                       │  │
│  │                                                      │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐             │  │
│  │  │ PHP 8.2  │ │ PHP 8.3  │ │ PHP 8.4  │             │  │
│  │  │  8.2.34  │ │  8.3.35  │ │  8.4.26  │             │  │
│  │  │  :8082   │ │  :8083   │ │  :8084   │             │  │
│  │  │VULNERABLE│ │VULNERABLE│ │VULNERABLE│             │  │
│  │  └──────────┘ └──────────┘ └──────────┘             │  │
│  │                                                      │  │
│  │  ┌──────────┐ ┌──────────┐                          │  │
│  │  │ PHP 8.5  │ │ PHP 8.3  │                          │  │
│  │  │  8.5.11  │ │  8.3.36  │                          │  │
│  │  │  :8085   │ │  :8086   │                          │  │
│  │  │VULNERABLE│ │ PATCHED  │                          │  │
│  │  └──────────┘ └──────────┘                          │  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

| Service | PHP Version | Port | Status |
|---|---|---|---|
| `php82-vuln` | 8.2.34 | `localhost:8082` | ❌ Vulnerable |
| `php83-vuln` | 8.3.35 | `localhost:8083` | ❌ Vulnerable |
| `php84-vuln` | 8.4.26 | `localhost:8084` | ❌ Vulnerable |
| `php85-vuln` | 8.5.11 | `localhost:8085` | ❌ Vulnerable |
| `php83-patched` | 8.3.36 | `localhost:8086` | ✅ Patched |

---

## Network Isolation

### Mandatory Precautions

1. **Never expose the lab to the internet.** All ports bind to `127.0.0.1` only.

2. **Use an isolated Docker network.** The `docker-compose.yml` creates a dedicated bridge network (`php2shell-lab-net`) with no connection to other Docker networks.

3. **Firewall the host.** Ensure no port forwarding or NAT rules expose the lab ports externally.

4. **Run on a dedicated machine or VM.** For maximum isolation:

   ```bash
   # Option A: Use a dedicated VM (recommended)
   # Create a VM with no bridged networking — use NAT or host-only
   
   # Option B: Use Docker's network isolation
   # The provided docker-compose.yml already configures this
   ```

5. **Do not run production workloads on the same Docker daemon** as the lab.

### Verifying Isolation

```bash
# Confirm ports are bound to localhost only
ss -tlnp | grep -E "808[2-6]"
# Should show 127.0.0.1:808x, NOT 0.0.0.0:808x

# Confirm Docker network is isolated
docker network inspect php2shell-lab-net | grep -A5 "IPAM"

# Confirm containers cannot reach the internet
docker exec php83-vuln ping -c 1 8.8.8.8
# Should fail (no external connectivity)
```

---

## Quick Start

```bash
# 1. Clone the repository (if you haven't already)
git clone https://github.com/umair-aziz025/php2shell-research-toolkit.git
cd php2shell-research-toolkit

# 2. Start the lab environment
cd lab
docker compose up -d

# 3. Verify all containers are running
docker compose ps

# 4. Run the scanner against the lab
cd ..
pip install -r requirements.txt
python scanner/php2shell_scanner.py --target http://127.0.0.1:8082
python scanner/php2shell_scanner.py --target http://127.0.0.1:8083
python scanner/php2shell_scanner.py --target http://127.0.0.1:8086  # patched — should pass

# 5. Tear down when finished
cd lab
docker compose down -v
```

---

## Docker Compose Setup

### Directory Structure

```
lab/
├── docker-compose.yml          # Container definitions
├── LAB_SETUP.md                # This guide
└── app/
    └── index.php               # Simple test application
```

### Create the Test Application

The repository includes a harmless fingerprint fixture in `lab/app/`. It
exposes only synthetic version evidence for scanner validation; it does not
execute exploit payloads, allocate attacker-controlled memory, run commands,
or expose real `phpinfo()` output.

```bash
mkdir -p lab/app
```

Create `lab/app/index.php`:

```php
<?php
/**
 * PHP2Shell Lab — Test Application
 * 
 * This is a minimal PHP application used for scanner testing.
 * It exposes the PHP version and configuration for detection.
 * 
 * WARNING: This is intentionally informative. Do NOT deploy in production.
 */

header('Content-Type: application/json');

$response = [
    'status'      => 'ok',
    'php_version'  => phpversion(),
    'sapi'         => php_sapi_name(),
    'server_time'  => date('c'),
    'extensions'   => get_loaded_extensions(),
    'memory_limit' => ini_get('memory_limit'),
];

echo json_encode($response, JSON_PRETTY_PRINT) . "\n";
```

### Start the Lab

```bash
cd lab

# Build and start all containers
docker compose up -d

# Check status
docker compose ps

# Expected output:
# NAME              STATUS    PORTS
# php82-vuln        running   127.0.0.1:8082->80/tcp
# php83-vuln        running   127.0.0.1:8083->80/tcp
# php84-vuln        running   127.0.0.1:8084->80/tcp
# php85-vuln        running   127.0.0.1:8085->80/tcp
# php83-patched     running   127.0.0.1:8086->80/tcp
```

### Verify Each Service

```bash
# Test each container
for port in 8082 8083 8084 8085 8086; do
    echo "--- Port $port ---"
    curl -s http://127.0.0.1:$port/ | python3 -m json.tool | grep php_version
done

# Expected output:
# --- Port 8082 ---
# "php_version": "8.2.34"
# --- Port 8083 ---
# "php_version": "8.3.35"
# --- Port 8084 ---
# "php_version": "8.4.26"
# --- Port 8085 ---
# "php_version": "8.5.11"
# --- Port 8086 ---
# "php_version": "8.3.36"
```

---

## Running the Scanner Against the Lab

### Single Target Scan

```bash
# Scan a single vulnerable instance
python scanner/php2shell_scanner.py --target http://127.0.0.1:8083

# Expected output:
# ╔══════════════════════════════════════════════════════════╗
# ║  PHP2Shell Vulnerability Scanner                        ║
# ╠══════════════════════════════════════════════════════════╣
# ║  Target: http://127.0.0.1:8083                          ║
# ║  PHP Version: 8.3.35                                    ║
# ║  Status: ❌ VULNERABLE                                  ║
# ║  CVE-2026-109618: AFFECTED                              ║
# ║  CVE-2026-109619: AFFECTED                              ║
# ╚══════════════════════════════════════════════════════════╝
```

### Batch Scan (All Lab Targets)

```bash
# Scan all lab instances at once
python scanner/php2shell_scanner.py \
    --targets \
    http://127.0.0.1:8082 \
    http://127.0.0.1:8083 \
    http://127.0.0.1:8084 \
    http://127.0.0.1:8085 \
    http://127.0.0.1:8086

# Or use a targets file
echo "http://127.0.0.1:8082
http://127.0.0.1:8083
http://127.0.0.1:8084
http://127.0.0.1:8085
http://127.0.0.1:8086" > targets.txt

python scanner/php2shell_scanner.py --file targets.txt
```

### Scan with JSON Output

```bash
# Generate machine-readable output
python scanner/php2shell_scanner.py \
    --target http://127.0.0.1:8083 \
    --output json \
    > scan_results.json
```

### Compare Vulnerable vs. Patched

```bash
# Scan the vulnerable instance
python scanner/php2shell_scanner.py --target http://127.0.0.1:8083
# Result: VULNERABLE

# Scan the patched instance
python scanner/php2shell_scanner.py --target http://127.0.0.1:8086
# Result: NOT VULNERABLE

# This comparison validates the scanner's accuracy
```

---

## Teardown

### Stop the Lab

```bash
cd lab

# Stop and remove all containers, networks, and volumes
docker compose down -v

# Verify everything is cleaned up
docker compose ps      # Should show nothing
docker network ls      # php2shell-lab-net should be gone
```

### Full Cleanup

```bash
# Remove all lab-related Docker images
docker rmi $(docker images --filter "reference=php:8.*" -q) 2>/dev/null

# Remove any dangling images
docker image prune -f

# Verify no lab artifacts remain
docker ps -a | grep php2shell
docker network ls | grep php2shell
```

---

## Troubleshooting

### Container Fails to Start

```bash
# Check container logs
docker compose logs php83-vuln

# Common issues:
# - Port conflict: Another service is using port 8082-8086
#   Fix: Stop the conflicting service or change ports in docker-compose.yml
# - Image not found: The specific PHP version tag doesn't exist
#   Fix: Check available tags at https://hub.docker.com/_/php/tags
```

### Scanner Cannot Connect

```bash
# Verify the container is running and the port is mapped
docker compose ps

# Test connectivity manually
curl -v http://127.0.0.1:8083/

# Check if PHP-FPM is running inside the container
docker exec php83-vuln ps aux | grep php

# Check container networking
docker exec php83-vuln cat /etc/hosts
```

### Permission Issues

```bash
# If the test app isn't served, check file permissions
docker exec php83-vuln ls -la /var/www/html/

# Fix permissions if needed
docker exec php83-vuln chmod 644 /var/www/html/index.php
```

### Resource Constraints

```bash
# Check Docker resource usage
docker stats --no-stream

# If containers are OOM-killed, increase Docker's memory limit
# Docker Desktop: Settings → Resources → Memory → 4GB+
```

---

## Security Reminders

1. **This lab is for research only.** Never use it to test against systems you don't own.
2. **Keep the lab isolated.** All ports bind to `127.0.0.1`.
3. **Tear down after use.** Don't leave vulnerable containers running.
4. **Don't modify the test app** to become a real application. It's intentionally minimal.
5. **Review the [DISCLAIMER](../DISCLAIMER.md)** before using any tools in this repository.

---

*Lab guide prepared by umair-aziz025 — PHP2Shell Research Project*
