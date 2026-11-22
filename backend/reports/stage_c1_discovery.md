# Stage C1 Discovery Report: APK Static Analysis & Androguard Readiness

**Date:** 2026-11-13  
**Auditor:** Antigravity Agent  
**Target:** `backend/reports/stage_c1_discovery.md`  
**Git Branch:** `auto/sms05`  
**Baseline Test Count:** **56 passed** (0 failed, 19 warnings across `test_api.py`, `test_phishing_url_extraction_v2.py`, `test_phishing_v3_pipeline.py`, and `test_sms_api.py`)

---

## 1. Existing Androguard Extractor & V3 Prototype Inventory

A thorough scan of the repository identified the following key research artifacts and scripts:

### A. Core Extractor Module
- **Path:** `backend/reports/ml/android_v3_runs/run_016_feature_extractor/android_v3_extractor.py` (695 lines)
- **Role & Capabilities:** Concrete implementation of the Android Feature Schema V3 static extractor.
- **Extracted Information:**
  - `APK` parsing via `androguard.core.apk.APK`:
    - Package name, version code, version name, min SDK, target SDK.
    - Declared permissions (`<uses-permission>`), categorized into `DANGEROUS_PERMISSIONS` and `SIGNATURE_OR_SYSTEM_PERMISSIONS`.
    - Declared components: activities, services, broadcast receivers, content providers, exported status, intent filters.
    - Cryptographic signature check (v1, v2, v3 signing schemes, debug-signed cert detection).
  - Multi-DEX analysis via `androguard.core.analysis.analysis.Analysis` and `androguard.core.dex.DEX`:
    - Traversal of bytecode instruction streams (`invoke-*`) for sensitive API categories: Reflection/Dynamic Class Loading (`DexClassLoader`, `PathClassLoader`, `Class.forName`), Command/Process Execution (`Runtime.exec`, `ProcessBuilder`, `System.loadLibrary`), Device Identifiers/IMEI, Telephony/SMS (`SmsManager.sendTextMessage`), Location tracking, Cryptographic ciphers, Package inspection/anti-AV reconnaissance, Accessibility services (`AccessibilityService`, `AccessibilityNodeInfo.performAction`), Raw network sockets (`java.net.Socket`).
    - Obfuscation hints: ratio of very short class and method names.
  - Strict bounded scaling and feature normalization (for the 48-feature numerical vector).
- **Environment & Dependency Documentation:**
  - `backend/reports/ml/android_v3_runs/run_016_feature_extractor/extractor_environment.md`
  - Requires `androguard==4.1.4`, `cryptography`, `lxml`, `mutf8`, `loguru`.

### B. Pre-Existing Test APK Fixtures
Multiple non-malicious test APK fixtures are already present in the repository from Androguard's official test suite:
- `backend/reports/ml/android_v3_runs/run_017_dataset_acquisition/acquired_apks/ANDROGUARD_TESTS_TestActivity.apk` (174,896 bytes)
- `backend/reports/ml/android_v3_runs/run_017_dataset_acquisition/acquired_apks/ANDROGUARD_TESTS_com.politedroid_4.apk` (18,489 bytes)
- `backend/reports/ml/android_v3_runs/run_017_dataset_acquisition/acquired_apks/ANDROGUARD_TESTS_com.teleca.jamendo_35.apk` (426,386 bytes)
- `backend/reports/ml/android_v3_runs/run_017_dataset_acquisition/acquired_apks/ANDROGUARD_TESTS_duplicate.permisssions.apk` (11,988 bytes)
- `backend/reports/ml/android_v3_runs/run_017_dataset_acquisition/acquired_apks/ANDROGUARD_TESTS_hello-world.apk` (1,722,314 bytes)

---

## 2. Dependency Audit & Androguard Availability

### A. Current Configuration in `backend/pyproject.toml`
`androguard` is **not** currently listed in `backend/pyproject.toml`.
Current dependencies:
```toml
dependencies = [
    "fastapi>=0.115,<1.0",
    "uvicorn[standard]>=0.30,<1.0",
    "joblib==1.5.3",
    "scikit-learn==1.8.0",
    "slowapi>=0.1.9,<1.0",
    "redis>=5.0.0,<9.0.0",
]
```

### B. Virtual Environment Audit
- In `.venv-py311-test`: `import androguard` currently raises `ModuleNotFoundError`.
- In `backend/reports/ml/android_v3_runs/run_016_feature_extractor/venv_v3`: `androguard` version `4.1.4` is present and functional.
- In Docker image `signalcheck-backend`: `androguard` is currently missing.
- In `python-multipart`: Required by FastAPI for `multipart/form-data` file uploads.

### C. Network & Installation Pre-flight
- A dry-run pip check confirmed network connectivity to PyPI is available and `androguard==4.1.4` (along with dependencies `mutf8`, `lxml`, `asn1crypto`, `cryptography`, `loguru`) resolves cleanly.
- In addition, FastAPI requires `python-multipart` to parse `UploadFile` / `File(...)` multipart requests.

---

## 3. Platform Security Controls, Limits, & Architecture

### A. Request Body Limits
- **NGINX (`nginx/nginx.conf`):**
  - Current global default: `client_max_body_size 1m;` (enforced at the edge for existing JSON endpoints).
  - Requirement: Update NGINX configuration to allow `client_max_body_size 25m;` specifically for `location /api/apk/analyze` (or `location /api/apk/`), keeping the strict 1 MB limit for all other routes.
- **FastAPI / Streaming:**
  - Must not read the full 25 MB payload into memory at once.
  - Stream chunks (e.g. 64 KB or 1 MB) into a temporary spool file while calculating SHA-256 and enforcing byte count $\le 25 \times 1024 \times 1024$.

### B. Timeouts
- **NGINX:** `proxy_read_timeout 15s;` (needs to accommodate 20s hard timeout; update `proxy_read_timeout 30s` for `/api/apk/`).
- **Application Level:** Hard analysis timeout of 20 seconds using thread pool / process execution or cooperative cancellation.

### C. Rate Limiting
- **SlowAPI (`backend/app/security.py`):**
  - Add `SIGNALCHECK_RATE_LIMIT_APK` (default: `"5/minute"`).
  - Uses existing Redis storage and trusted proxy client IP resolution (`get_client_ip`).

### D. Zip-Bomb & File Integrity Guards
Before parsing:
1. Validate magic bytes `PK\x03\x04` at offset 0.
2. Inspect ZIP directory entries without extracting:
   - Cap maximum entries (e.g. $\le 10,000$).
   - Cap cumulative uncompressed size ($\le 300\text{ MB}$).
   - Cap compression ratio ($\le 10\times$ or $20\times$).
   - Reject path traversal elements (`..`, absolute paths, leading slashes).
3. Validate required entries: must contain `AndroidManifest.xml` and at least one `classes*.dex`.
4. Delete temporary file in a `finally` block on both success and failure paths.

---

## 4. Next Actions
Proceed with:
1. Adding `androguard>=4.1.4,<5.0` and `python-multipart>=0.0.9,<1.0` to `backend/pyproject.toml` and installing into `.venv-py311-test`.
2. Implementing `backend/app/apk_analyzer.py` and output schemas in `backend/app/schemas.py`.
3. Implementing `POST /api/apk/analyze` in `backend/app/main.py`.
