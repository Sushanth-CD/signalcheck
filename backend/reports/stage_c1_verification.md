# Stage C1 Verification Report: APK Static Analysis & Safe Upload Pipeline

**Date:** 2026-11-13  
**Auditor / Implementer:** Antigravity Agent  
**Target:** `backend/reports/stage_c1_verification.md`  
**Git Branch:** `auto/sms05`  
**Deployment Ports:** HTTP: `http://localhost:8080`, HTTPS: `https://localhost:8443`  
**Full Pytest Test Suite:** **67 passed** (0 failed, 20 deprecation warnings across 5 modules)  

---

## 1. Executive Summary

Stage C1 of the SignalCheck platform roadmap has been implemented and verified. The Android Research Lab now provides real, safe static analysis of uploaded Android application packages (`.apk`) via a dedicated endpoint (`POST /api/apk/analyze`).

In accordance with strict safety mandates:
1. **Static Analysis Only:** The system extracts structural package metadata, declared permissions, component intent filters, cryptographic signing facts, and bytecode indicator references using Androguard 4.1.4. The uploaded APK or DEX bytecode is **never installed, executed, emulated, or dynamically loaded**.
2. **Ephemeral Upload Guarantee:** Uploaded APKs are streamed directly into temporary spool files on disk with chunked byte counting, inspected under a strict 20-second timeout, and **unlinked in a `finally` block** under all execution paths (success, validation failure, timeout, or runtime error). Container inspections confirmed zero orphaned upload remnants in `/tmp`.
3. **No Unvalidated ML Verdicts:** The system does not train or run any ML malware classifier on uploaded APKs, nor does it present probability percentages or the words "safe", "clean", or "malware". Instead, findings are categorized via an auditable rule table into neutral indicator levels (`no_notable_indicators`, `some_indicators`, `many_indicators`) alongside a permanent limitations notice.
4. **Existing API Contracts Unchanged:** `POST /api/ml/analyze`, `POST /api/ml/analyze-sms`, and `POST /api/ml/analyze-android` remain 100% stable with zero regressions.

---

## 2. Files Changed & Added

| File | Change Type | Purpose |
|---|---|---|
| `backend/pyproject.toml` | Modified | Added production dependencies `androguard>=4.1.4,<5.0` and `python-multipart>=0.0.9,<1.0`. |
| `backend/Dockerfile` | Modified | Updated builder stage to install `androguard` and `python-multipart`. |
| `backend/app/schemas.py` | Modified | Added versioned `apk-static-v1` response schemas (`APKAppInfo`, `APKPermissionGroup`, `APKComponentsInfo`, `APKSigningInfo`, `APKCodeIndicators`, `APKFinding`, `APKAnalysisResponse`). |
| `backend/app/apk_analyzer.py` | **Added** | Core static analysis engine with zip-bomb protection, Androguard metadata/bytecode extraction, and deterministic rule table. |
| `backend/app/security.py` | Modified | Added `SIGNALCHECK_RATE_LIMIT_APK` documentation and env getter. |
| `backend/app/main.py` | Modified | Implemented `POST /api/apk/analyze` with streaming size cap, thread pool timeout, audit logging, and `finally` file cleanup. |
| `backend/tests/test_apk_api.py` | **Added** | Automated test suite covering valid APKs, non-ZIP rejection, manifest/dex checks, oversize uploads, zip bombs, path traversal, timeouts, temp file cleanup, log safety, and rate limits. |
| `nginx/nginx.conf` | Modified | Configured dedicated `location /api/apk/` with `client_max_body_size 25m;`, `client_body_timeout 30s;`, and `proxy_read_timeout 30s;`. |
| `.env.example` | Modified | Added `SIGNALCHECK_RATE_LIMIT_APK=5/minute` and `SIGNALCHECK_APK_*` configuration defaults. |
| `frontend/src/api/analyze.js` | Modified | Added `analyzeAPK(file, onProgress, signal)` with AbortController cancellation and relative URL resolution. |
| `frontend/src/components/APKStaticAnalysis.jsx` | **Added** | Accessible drag-and-drop file picker, client-side size check (25 MB), progress/cancel states, SHA-256 copy, findings cards, grouped permissions, signing facts, and permanent limitations notice. |
| `frontend/src/components/ResearchToolsSection.jsx` | Modified | Integrated tab switcher between the new APK Static Analysis tool and the legacy 226-feature vector tool. |
| `frontend/src/components/ui/Icons.jsx` | Modified | Added `FileTextIcon`, `SlidersIcon`, and `ChevronUpIcon`. |
| `frontend/src/design-system.css` | Modified | Added styling for dropzone, severity pills, findings cards, permission grids, and collapsible panels. |
| `frontend/src/components/AboutSafetySection.jsx` | Modified | Updated Android section description to accurately reflect static package inspection. |
| `README.md` | Modified | Updated features and research lab descriptions to accurately document `/api/apk/analyze`. |

---

## 3. Endpoint Contract & Rule Table

### A. Endpoint Specification: `POST /api/apk/analyze`
- **Content-Type:** `multipart/form-data` (field: `file`).
- **Response Format:** JSON (`apk-static-v1`).
- **Rate Limit:** 5 requests/minute per client IP (Redis-backed, SlowAPI).
- **Hard Resource Caps:**
  - Maximum upload size: 25 MB (`SIGNALCHECK_APK_MAX_SIZE_BYTES=26214400`).
  - Analysis timeout: 20 seconds (`SIGNALCHECK_APK_TIMEOUT_SECONDS=20`).
  - Zip-bomb protections: Max 10,000 entries (`SIGNALCHECK_APK_MAX_ENTRIES`), Max 300 MB uncompressed (`SIGNALCHECK_APK_MAX_UNCOMPRESSED_BYTES`), Max 20.0x compression ratio (`SIGNALCHECK_APK_MAX_COMPRESSION_RATIO`).
  - Path traversal: Rejects any archive containing entries with `..`, absolute paths, or leading slashes.
  - Required container elements: Must contain `AndroidManifest.xml` and at least one `classes*.dex`.

### B. Heuristic Rule Table
The static analyzer applies 10 deterministic rules:

| Rule ID | Category | Severity | Description & Trigger Conditions |
|---|---|---|---|
| `RULE_SMS_EXFILTRATION_CAPABILITY` | Permission Combination | **HIGH** | `RECEIVE_SMS` or `READ_SMS` declared concurrently with `INTERNET`. Intercepts 2FA OTPs and transmits out-of-band. |
| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | Privilege Escalation | **HIGH** | Accessibility service or event handling combined with `SYSTEM_ALERT_WINDOW` overlay. Abused by banking trojans for tapjacking. |
| `RULE_DEVICE_ADMIN_PRIVILEGE` | Device Administration | **HIGH** | Declares `BIND_DEVICE_ADMIN` permission or `DEVICE_ADMIN_ENABLED` intent filter. Allows screen lock and wipe. |
| `RULE_COMMAND_EXECUTION` | Code Execution | **HIGH** | Bytecode references `java.lang.Runtime.exec` or `ProcessBuilder.start`. Shell invocation capability. |
| `RULE_UNSIGNED_PACKAGE` | Package Integrity | **HIGH** | Archive contains no valid cryptographic signatures. Origin unverified. |
| `RULE_DYNAMIC_CODE_LOADING` | Evasion | **MEDIUM** | Bytecode references `DexClassLoader`, `PathClassLoader`, or `InMemoryDexClassLoader`. Potential secondary payload execution. |
| `RULE_BOOT_PERSISTENCE` | Persistence | **MEDIUM** | Declares `RECEIVE_BOOT_COMPLETED` permission or intent filter. Launches background services on device startup. |
| `RULE_DEBUG_SIGNED_CERT` | Package Integrity | **MEDIUM** | Signed with well-known development debug certificate ("Android Debug"). |
| `RULE_PACKAGE_INSTALLER` | Installation Rights | **MEDIUM** | Declares `REQUEST_INSTALL_PACKAGES` or `INSTALL_PACKAGES`. Prompts installation of secondary packages (dropper behavior). |
| `RULE_HARDCODED_IP_URL` | Network Indicators | **MEDIUM** | Discovered raw numeric IPv4/IPv6 communication endpoints. Bypasses DNS filtering. |
| `RULE_OBFUSCATION_HINT` | Obfuscation | **LOW** | $>40\%$ of class/method names are $\le 2$ characters. Renaming/packing heuristic. |

### C. Indicator Level Derivation
- **`many_indicators`**: Triggered when $\ge 2$ high-severity rules, or $\ge 1$ high + $\ge 2$ medium rules, or $\ge 4$ medium rules match.
- **`some_indicators`**: Triggered when $\ge 1$ high rule or $\ge 1$ medium rule matches.
- **`no_notable_indicators`**: Triggered when no high or medium heuristic rules are flagged.

---

## 4. Test Verification Evidence

### A. Full Automated Backend Suite (`pytest`)
Executed under Python 3.11.9 (`.venv-py311-test`):
- **Total Test Count:** **67** (Baseline was 56, +11 new APK tests)
- **Passed:** **67**
- **Failed:** **0**
- **Regressions:** **0**
- **Breakdown by Module:**
  - `backend/tests/test_api.py`: 34 passed
  - `backend/tests/test_apk_api.py`: 11 passed
  - `backend/tests/test_phishing_url_extraction_v2.py`: 6 passed
  - `backend/tests/test_phishing_v3_pipeline.py`: 7 passed
  - `backend/tests/test_sms_api.py`: 9 passed

### B. Docker Compose & Container Verification
1. **Container Health:**
   - `signalcheck-nginx`: Up (healthy), ports `8080->80` and `8443->443`.
   - `signalcheck-frontend`: Up (healthy), internal port `80`.
   - `signalcheck-backend`: Up (healthy), internal port `8000`.
   - `signalcheck-redis`: Up (healthy), internal port `6379`.
2. **Ephemeral File Cleanup:**
   - Ran `docker exec signalcheck-backend ls -la /tmp` before and after test APK upload.
   - Verified that `/tmp` contains only the root directory entries (`.` and `..`); zero orphaned `.apk` spool files remained.
3. **Audit Logging Compliance:**
   - Inspected backend container logs (`docker logs --tail 30 signalcheck-backend`):
     ```text
     SIGNALCHECK_APK_AUDIT: req_id=a96feffb-2168-415b-95fc-fe113081ea75 size_bytes=174896 duration_sec=0.1011 outcome=SUCCESS
     ```
   - Confirmed: Zero upload content, zero extracted strings, and zero file names logged.
4. **End-to-End Headless Browser Verification (Playwright):**
   - Initial APK upload dropzone rendered with accessible prompt and 25 MB limit notice.
   - Non-APK file upload rejected client-side with clean error banner.
   - Real test APK (`TestActivity.apk`, 174,896 bytes) uploaded via same-origin `POST https://localhost:8443/api/apk/analyze`: Status `200 OK`.
   - UI correctly rendered: SHA-256 fingerprint copy button, package name `tests.androguard`, version codes, indicator level banner, findings cards, permission groups, signing details, and technical bytecode metrics.
   - Verified: Zero console errors, zero CSP violations, zero mixed-content warnings.
5. **Regression Verification across Existing Endpoints:**
   - `POST https://localhost:8443/api/ml/analyze` (Phishing): Status `200 OK` (score 0.9958).
   - `POST https://localhost:8443/api/ml/analyze` (Benign): Status `200 OK` (score 0.1394).
   - `POST https://localhost:8443/api/ml/analyze-sms` (Smishing): Status `200 OK` (score 0.9518).
   - `POST https://localhost:8443/api/ml/analyze-sms` (Legitimate): Status `200 OK` (score 0.1210).

---

## 5. Evidence Screenshots

The following screenshots were captured during live end-to-end browser execution:
- **Initial Upload Dropzone:** `backend/reports/screenshots/apk_upload_initial.png`
- **Validation Error Handling:** `backend/reports/screenshots/apk_upload_error.png`
- **Analysis Result & Findings View:** `backend/reports/screenshots/apk_analysis_result.png`

---

## 6. Known Limitations & Not Done

1. **No Dynamic Emulation or Execution:** Analysis is strictly static. Code paths guarded by dynamic class loaders, reflective proxies, runtime unpackers, or native C/C++ libraries (`.so`) are not executed or monitored dynamically.
2. **No External Intelligence Lookups:** Integration with VirusTotal, Google Play Protect, or external reputation feeds was not performed (strictly out of scope).
3. **No ML Classification Verdict for APKs:** An ML malware verdict is intentionally omitted because no statistically validated V3 ML model artifact exists. The legacy 226-feature offline benchmark remains isolated as an educational research tool.
4. **No Scan History Persistence:** Uploads and scan results are ephemeral and never stored in a database or local filesystem.
5. **Educational Disclaimer:** SignalCheck static APK analysis does not constitute commercial security certification or anti-malware verification.
