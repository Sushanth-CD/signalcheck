# Local Run Without Docker Verification Report

**Date:** 2026-11-14  
**Branch:** `auto/sms05`  
**Execution Environment:** Windows PowerShell (Native Local Development, No Docker)  

---

## 1. Scope & Execution Conditions
Due to Docker being unavailable in this session:
- **Docker rebuilds & NGINX steps:** **Not run (no Docker)**.
- **Backend Service:** Executed natively using Uvicorn (`app.main:app`) on `127.0.0.1:8000` with in-memory storage fallback.
- **Frontend Dev Server:** Executed via Vite dev server (`npm run dev`) on `127.0.0.1:5173` with reverse proxy mapping `/api` to `http://127.0.0.1:8000`.

---

## 2. Implementation Summary

### A. In-Memory Rate Limiting Fallback (`backend/app/security.py`)
- Verified `get_rate_limit_storage_uri()` logic:
  - When `REDIS_URL` or `SIGNALCHECK_RATE_LIMIT_STORAGE_URL` is configured, Redis remains the active backend.
  - When unset or empty, the SlowAPI limiter automatically falls back to in-memory storage (`memory://`).
  - Automated tests confirmed correct URI resolution under both configured and unconfigured conditions.

### B. Vite Development Proxy (`frontend/vite.config.js`)
- Inspected `frontend/vite.config.js` to ensure the dev proxy forwards `/api` to the backend on `127.0.0.1:8000`:
  ```javascript
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  }
  ```
- Verified proxy connectivity by executing requests to `http://127.0.0.1:5173/api/apk/history` which routed cleanly to the running Uvicorn backend without CORS issues.

### C. Documentation (`README.md`)
- Added Section 10: **"Run without Docker (Windows PowerShell)"** detailing:
  - Exact PowerShell commands for activating the Python 3.11 virtual environment and running Uvicorn.
  - Instructions for launching the frontend with `npm run dev`.
  - Explanations of automatic `memory://` fallback, dev proxy routing, and local SQLite database persistence.

---

## 3. Verification & Validation Evidence

### Full Pytest Suite
Executed in Python 3.11 environment:
- **Result:** `82 passed, 21 warnings in 158.71s`
- **Failures:** 0

### Playwright E2E Verification Against Dev URL (`http://127.0.0.1:5173`)
Executed automated headless Chromium check against the native dev stack:
1. **Web Phishing Scanner:** Submitted `"URGENT: Verify your account immediately at http://secure-login-update.com"`; proxy forwarded request to `/api/ml/analyze` and displayed the phishing summary card.
2. **SMS Smishing Scanner:** Submitted `"URGENT: Your account has been locked. Call 0800123456 immediately."`; proxy forwarded request to `/api/ml/analyze-sms` and displayed the smishing assessment card.
3. **Research Lab (APK Static Analysis):** Uploaded `ANDROGUARD_TESTS_TestActivity.apk`; proxy forwarded request to `/api/apk/analyze`, displayed findings and the Severity Guidance Legend, and expanded the educational "Learn more" details via `aria-expanded`.
4. **Captured Screenshot:**
   - [local_dev_run_without_docker.png](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/screenshots/local_dev_run_without_docker.png)

---

## 4. Docker / NGINX Exclusions
- `docker compose build`: **Not run (no Docker)**
- `docker compose up`: **Not run (no Docker)**
- `nginx/nginx.conf` reload: **Not run (no Docker)**
