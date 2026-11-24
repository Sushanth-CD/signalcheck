# SignalCheck — Cyber Security Awareness Platform

SignalCheck is a modern, accessible web application designed to help non-technical users and security researchers evaluate suspicious electronic communications and mobile software artifacts. 

The platform provides focused, transparent machine-learning-based classification for **Web & Link Phishing**, **SMS Smishing lures**, and **Android permission/feature vectors**, paired with actionable guidance and official incident reporting resources.

---

## Table of Contents
1. [Key Features](#key-features)
2. [System Architecture](#system-architecture)
3. [Documentation & Guides](#documentation--guides)
4. [Technology Stack](#technology-stack)
5. [Repository Structure](#repository-structure)
6. [Prerequisites](#prerequisites)
7. [Backend Installation & Setup](#backend-installation--setup)
8. [Frontend Installation & Setup](#frontend-installation--setup)
9. [Environment Configuration](#environment-configuration)
10. [Running SignalCheck Locally](#running-signalcheck-locally)
11. [Run without Docker (Windows PowerShell)](#run-without-docker-windows-powershell)
12. [How to Run the APK Heuristic Evaluation](#how-to-run-the-apk-heuristic-evaluation)
13. [API Endpoints Reference](#api-endpoints-reference)
14. [Testing & Quality Verification](#testing--quality-verification)
15. [Machine Learning Models & Lineage](#machine-learning-models--lineage)
16. [Research Lab & Android Limitations](#research-lab--android-limitations)
17. [Known Limitations & Disclaimers](#known-limitations--disclaimers)
18. [University & Hackathon Demonstration Guide](#university--hackathon-demonstration-guide)

---

## 1. Key Features

- **Web & Link Phishing Scanner:** Classifies email bodies, message text, and suspicious URLs using a domain-grouped TF-IDF + Logistic Regression pipeline.
- **SMS Smishing Scanner:** Evaluates SMS lures (including urgent linkless banking, delivery, and callback scams) using the frozen **SMS-05-C** combined word and character model.
- **Dedicated Cybersecurity Design System:** WCAG 2.2 Level AA compliant interface with high contrast ratios ($\ge 4.5:1$), visible focus rings, multi-modal status indicators, and keyboard shortcuts (`Ctrl+Enter` / `Cmd+Enter`).
- **Research Tools Lab:** Dedicated offline Android 226-feature benchmark interface (`/api/ml/analyze-android`) evaluating precomputed permission and feature vectors against the legacy Random Forest baseline.
- **Cryptographic Model Verification:** Enforces SHA-256 integrity checks at application startup before model deserialization to prevent artifact tampering.
- **Dynamic CORS Protection:** Configurable via environment variables without wildcard permissions.

---

## 2. System Architecture

SignalCheck operates as a decoupled client-server application:

```
+-----------------------------------------------------------------------------------------+
|                                    SIGNALCHECK CLIENT                                   |
|                             (Vite + React 18 SPA on Port 5173/4173)                     |
+-----------------------------------------------------------------------------------------+
       |                                      |                                   |
       | POST /api/ml/analyze                 | POST /api/ml/analyze-sms          | POST /api/ml/analyze-android
       v                                      v                                   v
+-----------------------------------------------------------------------------------------+
|                                   FASTAPI BACKEND SERVICE                               |
|                         (Python 3.11+ / Uvicorn Daemon on Port 8000)                    |
+-----------------------------------------------------------------------------------------+
|  Lifespan Model Loader:                                                                 |
|    - Validates SHA-256 integrity digests against trusted model manifest                |
|    - Deserializes scikit-learn 1.8.0 pipelines into memory                              |
|                                                                                         |
|  Inference Engines:                                                                     |
|    1. Text Phishing Pipeline (Domain-Grouped Word N-Gram TF-IDF + Logistic Regression)  |
|    2. SMS Smishing Pipeline (SMS-05-C: Word + Char FeatureUnion + Logistic Regression)  |
|    3. Android Permission Classifier (Random Forest 200 trees, 226 tabular features)     |
+-----------------------------------------------------------------------------------------+
```

For the complete architectural design, container isolation boundaries, Redis lifecycle, and Mermaid diagrams, see:
- [System Architecture & Isolation Guide](docs/architecture.md)
- [Technical Limitations & Operating Parameters](docs/limitations.md)
- [3-Minute Live Demonstration Script](docs/demo-script.md)

---

## 3. Documentation & Guides

Comprehensive documentation files are available in [`docs/`](docs/):
- **[Architecture & Isolation (docs/architecture.md)](docs/architecture.md):** Detailed layer breakdown, Mermaid flowcharts, non-root user execution, read-only root filesystems, and tmpfs boundaries.
- **[Demonstration Script (docs/demo-script.md)](docs/demo-script.md):** 3-minute presentation walkthrough covering APK upload, findings, educational "Learn more" explanations, PDF export, and private history.
- **[Technical Limitations (docs/limitations.md)](docs/limitations.md):** Detailed boundaries covering static-only analysis, deterministic heuristic rules, lack of verdicts, and subprocess development fallback.

---

## 4. Technology Stack

- **Frontend:** React 18, Vite 6, Tailwind/CSS Variables Design System, Native SVG Icons.
- **Backend API:** FastAPI 0.115+, Uvicorn 0.30+, Pydantic V2, Starlette.
- **Machine Learning & Data Science:** scikit-learn 1.8.0, Joblib 1.5.3, NumPy 2.x, Androguard 4.1.4 (V3 extractor research).
- **Quality & Testing:** Pytest, AnyIO, Headless Chrome automation.

---

## 4. Repository Structure

```
cyber-security-awareness-platform/
├── backend/
│   ├── app/
│   │   ├── main.py                   # FastAPI application entry point & CORS configuration
│   │   ├── schemas.py                # Pydantic v2 typed API contracts
│   │   ├── ml_classifier.py          # Phishing text model loader & inference engine
│   │   ├── sms_classifier.py         # SMS-05-C model loader & inference engine
│   │   ├── android_classifier.py     # Android tabular model loader & validator
│   │   └── model_integrity.py        # SHA-256 checksum verification module
│   ├── models/
│   │   ├── model_integrity_manifest.json # Authoritative cryptographic hash manifest
│   │   ├── text/                     # Phishing text classification model artifacts
│   │   ├── sms/                      # SMS-05-C smishing classification model artifacts
│   │   └── android/                  # Android Random Forest tabular model artifacts
│   ├── reports/                      # Forensic audits, training logs & Phase 1-4 reports
│   └── tests/                        # Automated Pytest suite (51 test cases)
├── frontend/
│   ├── src/
│   │   ├── components/               # React workspace & UI components
│   │   ├── design-system.css         # Foundational SaaS design tokens
│   │   ├── App.jsx                   # Primary application navigation shell
│   │   └── main.jsx                  # React application root
│   └── package.json                  # Frontend dependencies and build scripts
├── docs/                             # Architecture and API contracts
├── .env.example                      # Environment configuration template
└── README.md                         # This file
```

---

## 5. Prerequisites

- **Python:** 3.11, 3.12, 3.13, or 3.14.
- **Node.js:** Node 18+ and npm 9+.
- **Operating System:** Windows 10/11, macOS, or Linux.

---

## 6. Backend Installation & Setup

1. Open a terminal and navigate to the `backend/` directory:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install backend dependencies:
   ```bash
   pip install -e .
   pip install -e ".[dev]"
   ```

---

## 7. Frontend Installation & Setup

1. Open a second terminal and navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```

2. Install npm dependencies:
   ```bash
   npm install
   ```

---

## 8. Environment Configuration

SignalCheck provides an environment template at `.env.example`. 

To configure allowed origins for CORS:
```bash
# Copy template to .env
cp .env.example .env
```

**Environment Variables:**
- `SIGNALCHECK_CORS_ORIGINS`: Comma-separated list of allowed browser origins (e.g. `http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:4173`). Wildcards (`*`) are strictly rejected.

---

## 9. Running SignalCheck Locally

### Step 1: Start the Backend API
In your activated backend terminal:
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info
```
- API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`
- Health Probe: `http://127.0.0.1:8000/health`

### Step 2: Start the Frontend UI
In your frontend terminal:
```bash
cd frontend
# For development with hot reloading:
npm run dev

# OR for production preview:
npm run build
npm run preview
```
Open your browser and navigate to: `http://127.0.0.1:5173` (or `http://127.0.0.1:4173` for preview).

---

## 10. Run without Docker (Windows PowerShell)

When Docker or Docker Desktop is unavailable, SignalCheck runs entirely natively on Windows without container virtualization or external services.

### Key Behaviors without Docker
- **In-Memory Rate Limiting (`memory://`):** If no Redis URL is configured (`REDIS_URL` or `SIGNALCHECK_RATE_LIMIT_STORAGE_URL` unset), the SlowAPI rate limiter automatically defaults to process-local in-memory storage (`memory://`). When `REDIS_URL` is set, Redis remains the default storage backend.
- **Frontend Vite Dev Proxy:** The Vite development server automatically proxies all `/api` requests from `http://127.0.0.1:5173/api/*` directly to the backend at `http://127.0.0.1:8000/api/*`, resolving CORS and routing seamlessly.
- **SQLite Database Persistence:** APK static analysis history persists automatically to local SQLite storage without requiring Docker volumes.

### PowerShell Terminal 1: Start the Backend Service
```powershell
cd "C:\Projects\cyber-security-awareness-platform"

# Activate the virtual environment
.\.venv-py311-test\Scripts\Activate.ps1

# Optional: Ensure CORS allows local Vite development origins
$env:SIGNALCHECK_CORS_ORIGINS="http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:4173,http://localhost:4173"

# Optional: In-memory rate limiting is automatically used when REDIS_URL is empty
# $env:REDIS_URL=""

# Start the FastAPI Uvicorn server on port 8000
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

Verify backend health:
```powershell
curl.exe http://127.0.0.1:8000/health
# Expected: {"status":"ok"}
```

### PowerShell Terminal 2: Start the Frontend Dev Server
```powershell
cd "C:\Projects\cyber-security-awareness-platform\frontend"

# Install npm dependencies (if not already installed)
npm install

# Start the Vite development server with API proxying
npm run dev
```

Open the application:
- Web App: `http://127.0.0.1:5173`
- Backend API Docs: `http://127.0.0.1:8000/docs`

---

## 11. How to Run the APK Heuristic Evaluation

Stage C5 introduces an automated, isolated static analysis evaluation harness (`backend/eval/run_eval.py`) that executes deterministic heuristic rules against benign and suspicious APK datasets without executing code, importing Androguard in the harness, or touching the database.

### Prerequisites & Safety
- **No Execution / Installation:** APKs are analyzed purely as static zip archives and bytecode. They are never executed, installed, or emulated.
- **Privacy Enforcement:** Output files (`results.csv`) record only SHA-256 hashes, group, outcome, and 0/1 rule triggers. Zero file names or file paths are ever recorded or committed.

### Directory Setup
Place APK samples into the following directories (or supply custom paths via CLI flags):
```powershell
backend/eval/data/benign/
backend/eval/data/suspicious/
```

### Execution (Windows PowerShell)

Run evaluation using default dataset paths:
```powershell
cd "C:\Projects\cyber-security-awareness-platform"
.\.venv-py311-test\Scripts\python.exe backend/eval/run_eval.py
```

Run evaluation using custom dataset or output directories:
```powershell
cd "C:\Projects\cyber-security-awareness-platform"
.\.venv-py311-test\Scripts\python.exe backend/eval/run_eval.py `
  --benign-dir "backend/eval/data/benign" `
  --suspicious-dir "backend/eval/data/suspicious" `
  --output-csv "backend/eval/results.csv" `
  --output-summary "backend/eval/summary.md"
```

### Outputs
- `backend/eval/results.csv`: Per-sample SHA-256, group, execution outcome (`SUCCESS`, `REJECTED_*`, `TIMEOUT`, `FAILED_*`), and 0/1 trigger column for each of the 11 heuristic rules.
- `backend/eval/summary.md`: Aggregate counts, trigger rates with 95% Wilson confidence intervals, gap analysis, noisy/never-fire warning flags, statistical limitations statement, and proposed adjustments.

---

## 12. API Endpoints Reference

All endpoints enforce strict Pydantic schemas (`extra="forbid"`). Content is processed strictly in-memory and is never logged or written to disk.

### 1. `POST /api/ml/analyze`
Classifies suspicious email or webpage text.
- **Payload:** `{"content": "URGENT: Verify account at http://login-secure.com"}` (1 to 10,000 characters)
- **Response:**
  ```json
  {
    "classification": "phishing",
    "phishing_score": 0.9958,
    "score_kind": "uncalibrated_model_score",
    "threshold": 0.5,
    "model_id": "phishing-tfidf-logreg-domain-grouped-v1",
    "disclaimer": "This result is an uncalibrated model score, not proof..."
  }
  ```

### 2. `POST /api/ml/analyze-sms`
Classifies suspicious mobile SMS messages.
- **Payload:** `{"content": "Your parcel is pending payment. Call 0800123456"}` (1 to 2,000 characters)
- **Response:**
  ```json
  {
    "classification": "smishing",
    "smishing_score": 0.9518,
    "score_kind": "uncalibrated_model_score",
    "threshold": 0.5,
    "model_id": "sms-05-c-combined-v1",
    "disclaimer": "This result is an uncalibrated experimental model score..."
  }
  ```

### 3. `POST /api/ml/analyze-android`
Evaluates a prepared 226-feature Android permission vector.
- **Payload:** `{"features": {"SEND_SMS": 1, "READ_SMS": 1, ...}}` (exactly 226 binary 0/1 integers)
- **Response:**
  ```json
  {
    "classification": "malicious",
    "malware_score": 0.912,
    "score_kind": "uncalibrated_model_score",
    "threshold": 0.5,
    "model_id": "android-random-forest-grouped-sklearn-1.8.0-v1",
    "disclaimer": "This endpoint analyzes prepared feature values and does not scan APK files..."
  }
  ```

---

## 11. Testing & Quality Verification

Run the full backend test suite:
```bash
cd backend
python -m pytest -v
```

> **Note on CI & Offline URL Extraction Tests:** The 6 regression tests in `backend/tests/test_phishing_url_extraction_v2.py` require a local Oracle JDK with its bundled Public Suffix List (`backend/notebooks/oracleJdk-27/`). Because this directory is gitignored and absent in CI environments, these tests automatically skip in CI with `"local JDK with Public Suffix List not available"`. Fallback approximations are intentionally forbidden to ensure evaluation fidelity.

Run frontend production build verification:
```bash
cd frontend
npm run build
```

---

## 12. Machine Learning Models & Lineage

1. **Phishing Classifier (`phishing-tfidf-logreg-domain-grouped-v1`):**
   - *Architecture:* Word n-gram (1,2) TF-IDF (200k features) + Logistic Regression ($C=1.0$).
   - *Lineage:* Evaluated under domain-held-out validation to minimize domain-memorization shortcuts.
2. **SMS Smishing Classifier (`sms-05-c-combined-v1`):**
   - *Architecture:* Combined Word + Character n-gram (3,5) FeatureUnion + Logistic Regression.
   - *Lineage:* Developed specifically to solve structural linkless smishing vulnerabilities while maintaining a low false-positive rate on legitimate personal SMS.
3. **Android Tabular Classifier (`android-random-forest-grouped-sklearn-1.8.0-v1`):**
   - *Architecture:* Random Forest (200 estimators) fitted on 226 binary permission and API flags.

---

## 13. Research Lab & Android Limitations

> [!IMPORTANT]
> **Android Research Scope:**
> The Android Research Lab provides an offline benchmark for precomputed 226-feature permission vectors against the legacy Random Forest baseline model. It operates strictly on precomputed vectors and does not upload, open, inspect, or execute APK files. Only 44 of the model's 226 features can be reproduced directly from an APK container, so direct APK scoring is not supported.

---

## 14. Known Limitations & Disclaimers

1. **Educational Awareness Tool:** SignalCheck is designed to promote cybersecurity awareness and caution. It does not replace enterprise endpoint detection and response (EDR) or secure email gateways.
2. **Uncalibrated Model Scores:** Model scores reflect classifier margins through a standard logistic sigmoid function. They are uncalibrated model scores and must not be interpreted as mathematically calibrated posterior probabilities.
3. **No Active Network Scraping:** Scanners inspect submitted text only; SignalCheck does not actively crawl destination web links or download external files.
4. **Model Deserialization:** Models are stored in serialized Joblib files protected by startup SHA-256 integrity verification. Safe tensor format migration (`skops.io`) is planned for enterprise releases.

---

## 15. University & Hackathon Demonstration Guide

### Preparing for the Presentation
1. Start the FastAPI backend on `http://127.0.0.1:8000`.
2. Start the Vite development or preview server on `http://127.0.0.1:5173`.
3. Open `http://127.0.0.1:5173` in Google Chrome or Firefox.

### Recommended Demo Walkthrough Flow
1. **Introduction (Dashboard):** Show the clean Cybersecurity SaaS landing view and explain the platform's awareness mission.
2. **Web Phishing Scanner:**
   - *Phishing Test:* Paste `"URGENT: Your account has been suspended. Verify immediately at http://secure-update-login.com"`. Show the immediate `Threat Detected` banner, uncalibrated score display, and actionable defensive guidance.
   - *Benign Test:* Paste `"Hey team, the draft meeting agenda is attached for tomorrow's standup."`. Show the clean `Likely Legitimate` status.
3. **SMS Smishing Scanner:**
   - *Smishing Test:* Paste `"URGENT: Your debit card is blocked. Call 08712404000 immediately to unlock."`. Highlight that SignalCheck detects linkless lures that evade simple URL blocklists.
4. **Android 226-Feature Benchmark (Research Lab):** Open the Research Lab, click "Load Sample Vector" to load the genuine 226-feature vector, click "Analyse Benchmark", and review the model output, uncalibrated score, and research limitations.
5. **Safety Resources:** Review the About & Safety view and the direct link to official reporting channels (`https://cybercrime.gov.in/`).
