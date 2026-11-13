# Stage C2 Verification Report: APK Static Analysis Result History and Export

**Project:** SignalCheck (Cyber Security Awareness Platform)  
**Branch:** `auto/sms05`  
**Execution Date:** 2026-11-13  
**Status:** PASSED (All criteria met, 0 regressions)

---

## 1. Executive Summary

Stage C2 extends the APK Static Analysis capability by introducing persistent result history and PDF technical report exports. In accordance with zero-trust privacy and security guidelines:
- **Zero raw APK or byte persistence:** The uploaded binary is never stored, emulated, or retained on disk or database. Only the structured `apk-static-v1` JSON result, metadata (package name, file size, SHA-256 fingerprint, indicator level), outcome status, and timestamps are persisted in SQLite via SQLAlchemy.
- **Docker volume persistence:** The SQLite database is mounted at `/app/data/signalcheck.db` backed by the named Docker volume `backend-data`, ensuring analysis records survive container updates and rebuilds.
- **Audit & Privacy:** No sensitive content or extracted strings are written to server logs. A strict retention policy (`SIGNALCHECK_APK_HISTORY_MAX=200`) automatically prunes the oldest records when the limit is exceeded.
- **Full Test Suite Compliance:** 75 passed, 0 failures across the complete automated test suite (including 8 new dedicated Stage C2 test cases).
- **End-to-End Browser Verification:** Verified live in containerized NGINX HTTPS deployment at `https://localhost:8443` via Playwright, capturing screenshot evidence of recent history views and verified PDF report generation.

---

## 2. Architecture & Implementation

### 2.1 Persistence Architecture (`backend/app/apk_db.py`)
- **Database Engine:** SQLite via SQLAlchemy ORM (`sqlite:////app/data/signalcheck.db` in Docker, configurable via `SIGNALCHECK_DB_PATH`).
- **Schema Model (`APKAnalysisRecord`):**
  - `id`: Integer primary key autoincrement.
  - `sha256`: String(64) indexed hash of the analyzed package.
  - `package_name`: String(255) application package identifier.
  - `file_size`: Integer byte size of uploaded APK.
  - `indicator_level`: String(50) summary threat rating (`no_notable_indicators`, `some_indicators`, `elevated_indicators`).
  - `outcome`: String(32) processing outcome (`SUCCESS`, `PARSE_ERROR`, etc.).
  - `result_json`: Text JSON payload containing full `apk-static-v1` findings, permissions, component counts, and limitations.
  - `created_at`: DateTime UTC timestamp indexed for newest-first ordering.
- **Automatic Pruning:** `save_apk_result()` calculates current row count; if greater than or equal to `SIGNALCHECK_APK_HISTORY_MAX` (default: 200), the oldest records are deleted atomically in the same transaction.

### 2.2 Endpoints (`backend/app/main.py`)
1. **`POST /api/apk/analyze`:**
   - Enforces 25 MB max streaming body limit, zip validation, zip-bomb checks, and 20s execution timeout.
   - Saves static analysis summary and full JSON result to database; returns response enriched with persistent `id`.
2. **`GET /api/apk/history`:**
   - Query parameters: `limit` (default 20, min 1, max 50), `offset` (default 0, min 0).
   - Validates pagination bounds (returns HTTP 422 for negative or invalid pagination values).
   - Rate limit: 30 requests/minute via SlowAPI.
3. **`GET /api/apk/report/{record_id}`:**
   - Returns full stored `apk-static-v1` JSON structure. Returns HTTP 404 for non-existent IDs.
   - When requested with `?format=pdf`, streams a structured one-page technical PDF report.
   - Rate limit: 30 requests/minute via SlowAPI.

### 2.3 PDF Export Engine (`backend/app/apk_pdf.py`)
- Implemented using ReportLab (`reportlab>=4.0.0,<6.0.0`).
- Generates a standalone single-page technical report containing:
  - Header with SignalCheck branding, report ID, generation timestamp, and package metadata.
  - SHA-256 fingerprint, file size, Android SDK targets (Min SDK, Target SDK).
  - High/Medium/Low Security Findings table with evidence and security context.
  - Grouped permissions breakdown and digital signature details (schemes, debug sign indicator, certificate subject/issuer).
  - Explicit Static Analysis Limitations notice box.
- Configured with `Content-Disposition: attachment; filename="signalcheck-report-<package>-<sha>.pdf"`.

### 2.4 NGINX Configuration & Limits (`nginx/nginx.conf`)
- Dedicated exact match `location = /api/apk/analyze` allows `client_max_body_size 25M;`.
- Prefix location `location /api/apk/` enforces strict `client_max_body_size 1M;` for history and report queries.
- Shared SSL/TLS headers, HSTS, and Content Security Policy applied across all endpoints.

---

## 3. Automated Test Suite Results

The full backend pytest suite was executed against Python 3.11:

```
================= 75 passed, 21 warnings in 190.43s (0:03:10) =================
```

### Stage C2 Test Cases (`backend/tests/test_apk_api.py`):
1. `test_apk_analysis_persists_to_history`: Confirms `POST /api/apk/analyze` saves record and returns database ID.
2. `test_apk_history_ordering_newest_first`: Confirms records are sorted newest-first in history listings.
3. `test_apk_history_pagination_bounds`: Confirms limit/offset pagination, caps, and 422 validation on negative inputs.
4. `test_apk_report_by_id_json`: Confirms `GET /api/apk/report/{id}` returns accurate stored JSON matching analysis.
5. `test_apk_report_unknown_id_returns_444_or_404`: Confirms non-existent ID yields HTTP 404.
6. `test_apk_report_pdf_export`: Confirms `?format=pdf` returns `Content-Type: application/pdf` with non-empty PDF binary structure.
7. `test_apk_history_retention_cap`: Confirms oldest records are deleted when inserting past `SIGNALCHECK_APK_HISTORY_MAX`.
8. `test_no_apk_bytes_persisted_in_database`: Inspects all database tables and columns, asserting no binary blob or raw file bytes are stored.

---

## 4. End-to-End Browser & Live Verification

Playwright end-to-end testing was performed against the live container stack at `https://localhost:8443`:
1. Navigated to SignalCheck UI -> **Research Lab** -> **APK Static Analysis**.
2. Uploaded test package fixture `ANDROGUARD_TESTS_TestActivity.apk`.
3. Initiated static analysis; confirmed live findings display, grouped permissions, and digital signature facts.
4. Confirmed the analysis record immediately populated in the **Recent Static Analyses** history card with package name, SHA-256 preview, indicator rating, and timestamp.
5. Clicked **Download PDF Report**; verified browser received and downloaded `signalcheck-report-tests.androguard-3bb32dd5.pdf` (3,457 bytes).

### Verification Evidence Artifacts:
- **History View:** `backend/reports/screenshots/c2_apk_history_view.png`
- **Report Download:** `backend/reports/screenshots/c2_apk_report_download.png`

---

## 5. Security & Privacy Audit Check

| Requirement | Implementation Verification | Status |
|---|---|---|
| Zero APK Bytes Persisted | Only JSON findings metadata stored; SQLite schema audited | **PASS** |
| Volume Persistence | `backend-data:/app/data` mounted in Docker Compose | **PASS** |
| Retention Limit | `SIGNALCHECK_APK_HISTORY_MAX=200` enforced on insert | **PASS** |
| Strict NGINX Body Limits | 25 MB on `/api/apk/analyze`, 1 MB on `/api/apk/history` & `/api/apk/report` | **PASS** |
| Zero Secrets/Logs Leakage | Audit logging outputs only non-sensitive metrics (size, ID, outcome) | **PASS** |
