# Verification Report: Anonymous Browser Session Privacy for APK History

**Project:** SignalCheck (Cyber Security Awareness Platform)  
**Branch:** `auto/sms05`  
**Execution Date:** 2026-11-14  
**Status:** PASSED (76/76 automated tests passing, 0 regressions)

---

## 1. Executive Summary

This update restricts APK static analysis history and report exports to the specific browser session that submitted the upload. 
- **Zero user accounts required:** Privacy is established using anonymous, cryptographically secure 256-bit random tokens (`secrets.token_urlsafe(32)`).
- **Secure session cookie issuance:** The token is issued on first `/api/apk/analyze` via an `httpOnly`, `SameSite=Strict`, `Secure` cookie named `signalcheck_apk_sid` (30-day lifetime).
- **One-way cryptographic hash storage:** The server never stores the raw session token in the database. Instead, only its SHA-256 digest (`session_hash`) is indexed alongside each analysis record.
- **Strict multi-tenant session isolation:** `GET /api/apk/history` and `GET /api/apk/report/{id}` only retrieve records matching the SHA-256 hash of the caller's session cookie.
- **ID probing defense:** Requests attempting to probe arbitrary or other sessions' record IDs return HTTP 404 (`report_not_found`), preventing enumeration of foreign records. Unauthenticated sessions without a cookie receive an empty history list (`total: 0`) and 404 on any direct report query.
- **Per-session retention cap:** The retention limit (`SIGNALCHECK_APK_HISTORY_MAX=200`) is enforced independently per `session_hash`. One session's activity cannot cause another session's history to be pruned.

---

## 2. Technical Implementation

### 2.1 Security & Session Helpers (`backend/app/security.py`)
- `APK_SESSION_COOKIE_NAME`: `"signalcheck_apk_sid"`
- `APK_SESSION_MAX_AGE`: `2592000` (30 days)
- `hash_session_token(token: str) -> str`: SHA-256 hash of the session token.
- `get_or_create_apk_session(request: Request) -> Tuple[str, str, bool]`: Extracts existing token or creates a new 32-byte URL-safe secret token and computes its hash.
- `get_apk_session_hash(request: Request) -> str`: Extracts the session hash from the incoming cookie if present.
- `set_apk_session_cookie(response: Response, token: str, is_secure: bool)`: Sets the `httpOnly`, `SameSite=Strict`, `Secure`, `Path=/` cookie on the response.

### 2.2 Database Partitioning & Retention (`backend/app/apk_db.py`)
- Schema updated: `session_hash = Column(String(64), nullable=False, default="", index=True)`.
- `init_db()` includes lightweight automated SQLite migration adding the column and index if missing.
- `save_apk_result()` stores `session_hash` and checks count filtered by `session_hash == current_session_hash` before pruning excess records.
- `get_apk_history()` filters records strictly by `session_hash`.
- `get_apk_record_by_id()` queries strictly by `id == record_id` AND `session_hash == current_session_hash`.

### 2.3 Endpoint Modifications (`backend/app/main.py`)
- `POST /api/apk/analyze`: Checks for existing session cookie; if absent, generates a new token and sets the `signalcheck_apk_sid` cookie in the HTTP response headers. Saves record under `session_hash`.
- `GET /api/apk/history`: Resolves `session_hash` from cookie. If no cookie is present, returns empty items array (`items: []`, `total: 0`).
- `GET /api/apk/report/{record_id}`: Resolves `session_hash` from cookie. If record does not exist or does not match `session_hash`, immediately returns HTTP 404 (`report_not_found`).

### 2.4 Frontend API Client (`frontend/src/api/analyze.js`)
- Added `credentials: "same-origin"` to `analyzeAPK`, `fetchAPKHistory`, and `fetchAPKReportJson` fetch requests to ensure browser session cookies are sent and received reliably over same-origin HTTPS requests.

---

## 3. Automated Test Verification

The full pytest suite was executed against the Python 3.11 runtime:
```
================= 76 passed, 21 warnings in 95.70s (0:01:35) ==================
```

### New & Updated Session Privacy Tests (`backend/tests/test_apk_api.py`):
1. `test_apk_analysis_persists_to_history`:
   - Confirms that analyzing an APK sets the `signalcheck_apk_sid` cookie on the response.
   - Verifies the owner session can immediately fetch its record from `/api/apk/history`.
2. `test_apk_history_retention_cap_per_session`:
   - Simulates Session A (8 records) and Session B (3 records) with a retention cap of 5.
   - Confirms Session A is trimmed to 5 records while Session B retains all 3 records independently.
3. `test_apk_cross_session_isolation_and_id_probing`:
   - Creates Session A and Session B with separate cookie jars.
   - Proves Session B receives empty history before analyzing.
   - Proves Session B cannot read Session A's record ID via `/api/apk/report/{id}` (returns HTTP 404).
   - Proves Session B cannot export PDF of Session A's report ID (returns HTTP 404).
   - Proves Session A cannot read Session B's record ID (returns HTTP 404).
   - Confirms distinct session cookies are assigned to each browser session.
4. `test_no_apk_bytes_persisted_in_database`:
   - Audits SQLite records ensuring zero binary content or ZIP signatures are stored.

---

## 4. Live Browser & End-to-End Validation

Tested against live Docker containers (`signalcheck-backend`, `signalcheck-frontend`, `signalcheck-nginx`, `signalcheck-redis`) at `https://localhost:8443`:
- First upload generated an HTTP 200 response with header:
  `Set-Cookie: signalcheck_apk_sid=...; HttpOnly; Max-Age=2592000; Path=/; SameSite=strict; Secure`
- Querying `/api/apk/history` without cookies returns `{"items":[],"total":0,"limit":20,"offset":0}`.
- Querying `/api/apk/report/{id}` without cookies returns HTTP 404: `{"detail":{"error":"report_not_found","message":"No APK analysis record found with ID ..."}}`.
- Multi-context Playwright script verified that Context A retains full history while an isolated Context B views the empty history state.
