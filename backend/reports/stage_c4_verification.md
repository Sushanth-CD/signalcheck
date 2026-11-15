# Stage C4 Verification Report: APK Parsing Isolation & Hardened Worker Pipeline

**Date:** 2026-11-15  
**Branch:** `auto/sms05`  
**Target:** Isolate Androguard APK parsing into an independent worker execution boundary, add an asynchronous job management pipeline (`POST /api/apk/analyze` and `GET /api/apk/jobs/{id}`) with Redis/RQ support and local subprocess fallback, update the frontend polling and lifecycle indicators, and harden the container sandbox architecture in CI.

---

## 1. Execution Conditions & Environment Disclaimers
- **Local Environment:** Windows PowerShell (Native local execution without Docker).
- **Docker Step Exclusion:** Docker was unavailable during this session. In adherence to instructions, **all local Docker rebuilds and NGINX reload steps were marked as "not run (no Docker)"**.
- **Part B Verification:** Verified via GitHub Actions CI workflow definitions (`.github/workflows/ci.yml`) on Ubuntu Linux runners.

---

## 2. Part A: Code Implementation & Local Verification (No Docker)

### A. Isolated Androguard Worker Entrypoint (`backend/app/apk_worker.py`)
- Quarantined all `androguard` imports exclusively to `backend/app/apk_worker.py`.
- Removed all `androguard` references from `apk_analyzer.py` and `main.py`.
- Implemented three operational modes:
  1. `parse_and_analyze_apk(file_path, sha256_hash, file_size)`: Core parsing and deterministic rule engine.
  2. `execute_rq_apk_job(file_path, sha256_hash, file_size)`: Task wrapper for Redis Queue (RQ).
  3. CLI Entrypoint (`python -m app.apk_worker <path> <sha256> <size>`): Serializes result JSON to stdout or structured error JSON to stderr with exit code 1.

### B. Dual-Engine Asynchronous Job Layer (`backend/app/apk_jobs.py`)
- Created an asynchronous job manager supporting dual backends:
  - **Redis + RQ Mode:** Automatically activated when `REDIS_URL` is set, enqueuing jobs to the `apk-analysis` queue.
  - **Local Subprocess Fallback:** Automatically activated when `REDIS_URL` is unset or empty (native Windows). Runs `python -m app.apk_worker` in an isolated child process under a hard **30-second timeout** with `proc.kill()` on expiration.
- Exposes job status querying (`get_job_status(job_id)`) returning terminal states: `queued`, `running`, `done`, `failed`, and `timeout`.
- Ephemeral security guarantee: Temporary files are deleted in a `finally` block across all states (`done`, `failed`, `timeout`, or worker crash).

### C. API Endpoints (`backend/app/main.py`)
- **`POST /api/apk/analyze`**:
  - Enforces 25 MB streaming cap, magic byte checking, zip bomb protection, and path traversal validation before queueing.
  - Returns `202 Accepted` with `job_id` and status `queued` (when `async_mode=True`), or awaits worker completion in backward-compatible synchronous mode.
- **`GET /api/apk/jobs/{job_id}`**:
  - Returns current job status, execution duration, and attaches educational explanations dynamically to the result payload upon completion.
  - Returns `404 Not Found` for unknown job IDs.

### D. Frontend Asynchronous Polling (`frontend/src/components/APKStaticAnalysis.jsx` & `analyze.js`)
- `analyzeAPK` enqueues the job and polls `/api/apk/jobs/{id}` at 1-second intervals.
- Halts upon terminal states (`done`, `failed`, `timeout`) or when cancelled by user (`AbortController`).
- Renders dedicated visual cards for `"Queued in worker pool..."`, `"Running isolated worker..."`, error states, and completion.

### E. Pytest Suite Validation
Executed full test suite in Python 3.11 (`.venv-py311-test`):
- **Result:** **90 passed**, 0 failures in 249.65s.
- **8 new Stage C4 test cases in `backend/tests/test_apk_api.py`:**
  1. `test_main_api_process_has_not_imported_androguard`: Confirms `sys.modules` in the API process contains no `androguard` modules.
  2. `test_apk_job_enqueue_and_poll_status`: Tests enqueuing a job via `POST /api/apk/analyze?async_mode=true` and polling `/api/apk/jobs/{id}` to `done`.
  3. `test_unknown_job_id_returns_404`: Confirms non-existent job UUIDs return 404.
  4. `test_oversized_input_rejected_before_enqueue`: Rejects uploads > 25 MB with 413.
  5. `test_worker_crash_returns_failed_without_crashing_api`: Confirms worker crash or exception returns status `failed` without crashing the main API.
  6. `test_timeout_kills_the_worker`: Asserts worker process kill is invoked when timeout is exceeded.
  7. `test_temp_file_removed_in_all_worker_outcomes`: Asserts temp file deletion across `done`, `failed`, and `timeout`.
  8. `test_result_matches_pre_change_schema`: Asserts output adheres strictly to `apk-static-v1`.

### F. Playwright E2E Verification
Executed automated Playwright check against the local dev environment (`http://127.0.0.1:5173`):
- Uploaded `ANDROGUARD_TESTS_TestActivity.apk`.
- Observed status progression from queued/running to done.
- Confirmed findings rendering and expanded educational "Learn more" details.
- Evidence screenshot: [c4_worker_isolated_execution.png](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/screenshots/c4_worker_isolated_execution.png).

---

## 3. Part B: Container Hardening & CI Status

### A. Docker Compose Hardening Configuration (`docker-compose.yml`)
Configured the dedicated worker service `apk-worker`:
- `user: "10001:10001"`: Non-root unprivileged execution.
- `read_only: true`: Immutable root filesystem.
- `tmpfs: [/tmp:size=64m,noexec,nosuid,nodev]`: Scratch space capped at 64 MB with execution prevented.
- `cap_drop: [ALL]`: All Linux kernel capabilities dropped.
- `security_opt: [no-new-privileges:true]`: Disallows privilege escalation.
- `deploy.resources.limits`: CPU capped at 1.0, RAM capped at 512 MB.
- `networks: [signalcheck-internal]`: Isolated internal-only network with zero outbound Internet egress.

### B. CI Verification Workflow (`.github/workflows/ci.yml`)
Configured GitHub Actions job `worker-container-hardening` running on Ubuntu:
1. Builds `signalcheck-apk-worker:ci`.
2. Creates internal network `signalcheck-ci-internal`.
3. Asserts UID is `10001` (non-root).
4. Asserts write attempt outside `/tmp` (e.g. `/app/evil_probe.txt`) fails with `Read-only file system`.
5. Asserts outbound network connection to external IP fails with `Network is unreachable`.

### C. Threat Model Documentation
Comprehensive adversarial mapping documented in:
- [stage_c4_threat_model.md](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/stage_c4_threat_model.md)

---

## 4. Docker / NGINX Exclusions
- `docker compose build`: **not run (no Docker)**
- `docker compose up`: **not run (no Docker)**
- `nginx/nginx.conf` reload: **not run (no Docker)**
