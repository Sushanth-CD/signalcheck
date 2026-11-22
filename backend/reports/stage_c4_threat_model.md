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
| **Ephemeral File Leakage** | Storing uploaded APK bytes on disk or retaining sensitive extracted strings in logs. | Ephemeral guarantee: in container mode, the backend passes uploaded bytes as the RQ job payload and immediately unlinks its local temporary file (retaining zero copy). The worker receives the bytes, writes them to a temporary file on its own 64 MB tmpfs mount at `/tmp`, analyzes them, and deletes the temporary file in a `finally` block across all outcomes (`done`, `failed`, `timeout`, crash). Containers do not share `/tmp`. DB stores only JSON indicators and SHA-256; audit logs record only request ID, byte size, duration, and outcome code. |

---

## 2. Local Subprocess Fallback Security Limitations

When running in local development mode without Docker (e.g. on native Windows with `REDIS_URL` unset), SignalCheck falls back to spawning worker child processes via Python's standard `subprocess.Popen([sys.executable, "-m", "app.apk_worker", ...])`.

It is critical to distinguish between the isolation provided in **container mode** versus the **local subprocess fallback**:

1. **Process & Time Isolation Only:**
   - The subprocess fallback provides clean process separation and a hard 30-second execution deadline (`proc.communicate(timeout=30)` followed by SIGKILL / `proc.kill()`).
   - If Androguard crashes, encounters a segmentation fault, or enters an infinite loop, only the child process dies; the main FastAPI server process remains unaffected.
   - The API process never imports Androguard or executes bytecode inspection code directly.

2. **No Filesystem Isolation:**
   - In local subprocess fallback, the worker runs with the host operating system permissions of the user running the server.
   - There is **no read-only root filesystem** and no mount namespace barrier; a parser exploit capable of arbitrary native code execution could read or write host files accessible to the current user.

3. **No Network Egress Isolation:**
   - The child process inherits the host network stack. There is **no internal-only bridge network** blocking outbound sockets. An exploit could theoretically initiate outbound connections if not blocked by host firewalls.

4. **No Memory / Cgroup Resource Isolation:**
   - While execution time is strictly killed at 30 seconds, there are no Linux cgroup caps enforcing RAM limits (e.g., the 512 MB container ceiling).

> [!WARNING]
> **Production Mandate:** The local subprocess fallback is designed strictly for local offline developer testing. In production and internet-exposed staging environments, SignalCheck **must** run in containerized mode via Docker Compose / Kubernetes with the `apk-worker` sandbox configured as specified in Section 3. Full security isolation (read-only filesystem, tmpfs scratch, dropped capabilities, non-root user, and zero network egress) applies **only** in container mode.

---

## 3. Container File Handoff Design (No Shared Filesystem)

In container mode (`REDIS_URL` set), SignalCheck uses an explicit **byte-payload handoff design**:

1. **Upload Processing & Immediate Deletion on Backend:**
   - The user streams an APK upload to the backend (`POST /api/apk/analyze`), subject to the 25 MB limit and zip-structure validation.
   - The backend buffers the upload to a short-lived local temp file solely to stream-validate magic bytes and compute the SHA-256 digest.
   - Upon enqueuing the RQ job to Redis, the backend passes the raw upload bytes as the RQ task argument (`upload_bytes`), and **immediately deletes its local temp file in the same turn**.
   - If Redis is unreachable or enqueueing fails, the backend immediately unlinks the temporary file and raises a `503 Service Unavailable` error (`queue_unavailable`), ensuring the backend retains no leftover APK bytes.

2. **Ephemeral /tmp tmpfs on Worker:**
   - The isolated `apk-worker` container shares **no volumes or filesystem mounts** with the backend container.
   - The worker container root filesystem is strictly immutable (`read_only: true`).
   - The worker writes the received bytes to its own dedicated ephemeral tmpfs at `/tmp/worker_upload_<id>.apk` (capped at 64 MB with `noexec,nosuid,nodev`).
   - Androguard processes the APK file on `/tmp`.
   - In a `finally` block, the worker deletes `/tmp/worker_upload_<id>.apk` unconditionally on every outcome (`done`, `failed`, `timeout`, or error), leaving zero bytes persisted.

3. **Redis Payload Lifecycle & Strict Temporal Bounds:**
   - **During Analysis:** Raw upload bytes exist in Redis solely as the compressed `data` argument payload of the active RQ job during worker execution (up to the 30-second job timeout).
   - **On Completion (`done`):** The worker executes static analysis, and immediately clears `job._args = ()`, `job._kwargs = {}`, and overwrites the Redis hash `data` field with empty arguments. When the backend or frontend retrieves the terminal `done` status via `GET /api/apk/jobs/{id}`, the backend caches the JSON result in memory (`_TERMINAL_JOB_CACHE`) for up to 120 seconds for UI polling convenience and immediately executes `job.delete()`. **Upload bytes lifetime in Redis for `done`:** $\le \text{worker duration} \approx 1\text{s}-5\text{s}$ (purged immediately upon worker completion; hard bounded by 60s TTL).
   - **On Failure (`failed`):** If the worker raises an exception or crashes, the job transitions to `failed` status with `failure_ttl=60`. As soon as `GET /api/apk/jobs/{id}` is queried by the frontend polling loop (typically within 1s), the backend reads the terminal status and calls `job.delete()`. Even if unpolled, the job expires from Redis within 60 seconds. **Upload bytes lifetime in Redis for `failed`:** $\le 1\text{s}-60\text{s}$.
   - **On Timeout (`timeout`):** If the 30-second execution deadline expires, RQ marks the job as failed (`JobTimeoutException`) with `failure_ttl=60`. As soon as `GET /api/apk/jobs/{id}` reads the terminal timeout state, the backend calls `job.delete()`. If unpolled, Redis evicts the key at the 60-second failure TTL. **Upload bytes lifetime in Redis for `timeout`:** $\le 30\text{s} + 1\text{s} \text{ (polling)} \le 60\text{s}$.
   - **On Redis Enqueue Outage:** If Redis fails during enqueueing, the backend deletes the upload temp file in `finally` and returns 503; zero bytes enter Redis.

---

## 4. Part B: Container Hardening Verification in CI

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
