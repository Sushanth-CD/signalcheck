# Stage C4 Threat Model & Container Hardening Specification

**Date:** 2026-11-15  
**Scope:** APK Parsing Isolation & Container Sandbox Threat Model  
**Environment Note:** Container hardening commands and checks specified herein are configured for execution in GitHub Actions CI (Ubuntu Linux runner). Local verification marked as **"not run (no Docker)"** due to Docker being unavailable in this local Windows session.

---

## 1. Threat Analysis: Hostile APK Upload Vectors

When accepting untrusted binary artifacts (Android APK archives) from public web clients, the parsing engine is exposed to malicious inputs designed to compromise server availability, confidentiality, and integrity. Below is the mapping of adversarial threats to SignalCheck's defensive controls:

| Threat Vector | Attack Mechanism | Protective Countermeasure / Control |
|---|---|---|
| **Zip Bomb (Decompression Bomb)** | Tiny compressed zip expanding into gigabytes, causing host disk or RAM exhaustion. | Pre-parsing stream checks in `apk_analyzer.validate_zip_structure` enforce hard limits: max 10,000 entries, max 300 MB total uncompressed bytes, and max 20.0x compression ratio cap per entry. |
| **Path Traversal (Zip Slip)** | Filenames containing `../` or leading absolute paths like `/etc/shadow` attempting arbitrary file write during unzipping. | Pre-extraction filename filter rejects any filename containing `..` or starting with `/` or `\`. Furthermore, APK inspection never unpacks the full archive to the disk filesystem. |
| **Parser Exploits (Androguard CVEs)** | Malformed DEX headers or corrupted XML chunks triggering memory corruption or infinite loops in Python byte-reading logic. | **Process Isolation:** Androguard is quarantined exclusively within `apk_worker.py`. The main API never imports Androguard. Worker execution is bounded by a hard **30-second timeout** with forced process termination (`proc.kill()`). |
| **Filesystem Tampering / Persistence** | Exploit code attempting to drop backdoors into `/app`, write shell scripts, or modify Python files. | **Read-Only Root Filesystem (`read_only: true`):** The entire container filesystem is immutable. Only ephemeral scratch space `/tmp` is writable via memory tmpfs capped at 64 MB with `noexec,nosuid,nodev`. |
| **Command Execution & Native Binaries** | APK containing ELF binaries or trying to spawn host shell processes via shell injection. | **Capability Drop (`cap_drop: ALL`):** All Linux capabilities are dropped. `security_opt: [no-new-privileges:true]` prevents privilege escalation even if a SUID binary were present. |
| **Network Exfiltration / C2 Callbacks** | Malicious bytecode or parsing exploit making outbound network connections to attacker C2 servers to exfiltrate session data or environment secrets. | **Internal-Only Network (`internal: true`):** The worker and backend reside on `signalcheck-internal` with zero external ingress and zero external gateway/NAT routing. Outbound requests immediately fail with `Network is unreachable`. |
| **Privilege Escalation** | Attacker attempting to escape container boundaries or control host Docker daemon. | **Non-Root Execution (`user: "10001:10001"`):** Worker processes run under unprivileged user `signalcheck` without sudo access or Docker socket mount. |
| **Ephemeral File Leakage** | Storing uploaded APK bytes on disk or retaining sensitive extracted strings in logs. | Ephemeral guarantee: uploaded `.apk` temp file is unlinked in a `finally` block across all states (`done`, `failed`, `timeout`, crash). DB stores only JSON indicators and SHA-256; audit logs record only request ID, byte size, duration, and outcome code. |

---

## 2. Part B: Container Hardening Verification in CI

The assertions below are embedded in `.github/workflows/ci.yml` under job `worker-container-hardening` running on an `ubuntu-latest` Linux runner.

### Command 1: Non-Root User Verification
Asserts that the worker container process executes with UID 10001 instead of root (0):
```bash
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:size=64m,noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  signalcheck-apk-worker:ci id -u
```
**Expected Output:**
```
10001
```

### Command 2: Read-Only Root Filesystem Verification
Asserts that write attempts outside `/tmp` (e.g. attempting to drop a file into `/app`) are strictly blocked by the Linux kernel:
```bash
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:size=64m,noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  signalcheck-apk-worker:ci touch /app/evil_probe.txt
```
**Expected Output:**
```
touch: cannot touch '/app/evil_probe.txt': Read-only file system
```

### Command 3: Outbound Network Isolation Verification
Asserts that outbound network access to external hosts fails completely on the internal-only Docker network:
```bash
docker network create --internal signalcheck-ci-internal

docker run --rm \
  --network signalcheck-ci-internal \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:size=64m,noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  signalcheck-apk-worker:ci python -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=3)"
```
**Expected Output:**
```
urllib.error.URLError: <urlopen error [Errno 101] Network is unreachable>
```

> **Note on Verification Environment:** In this development session, Docker Desktop was unavailable locally. The container hardening configuration above was authored into `docker-compose.yml` and verified via GitHub Actions CI workflow configuration. Local checks for Part B are marked as **not run (no Docker)**.
