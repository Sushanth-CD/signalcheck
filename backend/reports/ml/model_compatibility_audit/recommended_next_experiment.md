# Recommended Next Evaluation & Experimental Milestone

**Audit Scope:** Forward Strategy & Independent Evaluation Roadmap  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Date:** November 2026  

---

## 1. Executive Summary

Having completed the external HTML/URL evaluation of CompPhish V4 ($N = 2,000$) and audited the current runtime architecture, the most glaring risk to the platform is **modality mismatch and untested plain-text performance**:
1. The active API exposes a single text endpoint (`POST /api/ml/analyze`) loading the V2 Baseline.
2. The V2 Baseline was proven broken on HTML (8.85% recall) and was never independently benchmarked on pure URLs or real SMS messages.
3. The V3 models (URL-Only and Dual-Channel) have demonstrated value on HTML/web corpora, but V3 URL-Only has an intolerable 35.7% false alarm rate, and V3 Dual-Channel is blocked by the API's 10,000-character payload limit.
4. **No independent evaluation dataset has ever been evaluated for plain-text messages (SMS, email body text, chat phishing).**

To build a defensible, multi-modal cybersecurity awareness service, we outline the exact independent test data requirements and define the next experimental milestone.

---

## 2. Requirements for Independent Test Data by Modality

To prevent data leakage, evaluation corpora must satisfy strict independence criteria: zero domain or text overlap with the 77,677 training records, no use for threshold selection, and balanced temporal representation.

### 2.1 Modality 1: Plain-Text Phishing & Legitimate Messages (SMS / Email)
- **Primary Need:** An external, independently gathered dataset of SMS and short message lures alongside authentic benign communications.
- **Specific Characteristics Required:**
  - **Phishing/Smishing:** Real-world SMS lures (delivery notifications, bank account alerts, tax refunds, 2FA prompt lures) collected independently of `combined_reduced.json`.
  - **Legitimate Messages:** Genuine transactional SMS (bank OTP notifications, delivery dispatch messages, promotional marketing, friend-to-friend text) to benchmark false alarm rates.
  - **Diversity:** Must include messages with embedded shortlinks (`bit.ly`, `tinyurl`) AS WELL AS messages with no links (requesting callbacks or keyword replies).
- **Candidate Benchmark Sources to Investigate:**
  - Independent academic SMS spam/smishing corpora (e.g., Almeida SMS Spam Collection, Tiago Smishing datasets, or recent 2024–2025 mobile threat research feeds).

### 2.2 Modality 2: Standalone URLs with Independently Sourced Labels
- **Primary Need:** A dedicated standalone URL benchmark to measure URL-Only and candidate lightweight classifiers without HTML dependency.
- **Specific Characteristics Required:**
  - Fresh phishing URLs from multiple independent feeds (e.g., PhishTank, OpenPhish, URLhaus).
  - Modern legitimate web traffic sampled across top-level domains, content-delivery networks, cloud infrastructure (AWS S3, Azure Blob, GitHub Pages), and deep e-commerce/blog paths—specifically avoiding the "bare homepage root" bias seen in `top_sites_seed`.
  - Contemporary 2024–2026 registration dates with modern TLD diversity (`.dev`, `.app`, `.cloud`, `.ai`).

### 2.3 Modality 3: Modern Webpage Content (HTML)
- **Current Status:** Thoroughly evaluated on CompPhish V4 (2,000 records).
- **Remaining Need:** A specialized challenge set focused on **JavaScript-rendered and cloaked phishing landing pages** to evaluate whether client-side DOM extraction is required when static HTML bodies are empty.

---

## 3. Recommended Next Experimental Milestone: "Milestone Text-Eval-1"

### Milestone Title: Independent Plain-Text & Message Modality Evaluation

Prior to making further application code modifications or deploying V3 models to production, the platform must conduct an independent evaluation of **plain-text and message phishing detection**.

```
+---------------------------------------------------------------------------------------------------+
| ROADMAP & EXPERIMENTAL MILESTONE                                                                  |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [COMPLETED] CompPhish V4 External Evaluation (HTML & URLs, N = 2,000)                            |
|              - Proved V2 collapses on HTML (Recall 8.85%)                                         |
|              - Proved V3 URL-Only has high recall (88.49%) but high FPR (35.69%)                  |
|              - Proved V3 Dual-Channel cuts URL false alarms by 32% (Specificity 75.80%)           |
|                                                                                                   |
|  [CURRENT AUDIT] Architecture & Modality Compatibility Audit                                      |
|              - Identified severe API mismatch (10k char limit, V2 loaded, no routing)            |
|              - Identified zero independent evaluation on plain text / SMS                         |
|                                                                                                   |
|  [RECOMMENDED NEXT MILESTONE: Milestone Text-Eval-1]                                              |
|  Objective: Independent Plain-Text & Message Modality Evaluation                                  |
|              1. Identify an independent open-access SMS / email phishing benchmark                |
|              2. Screen candidates against the 77,677 project corpus for duplicate independence   |
|              3. Evaluate frozen V2 Baseline and V3 Content-Only on text without URLs              |
|              4. Quantify true operational False Positive Rate on benign transactional messages    |
|                                                                                                   |
|  [FOLLOW-UP MILESTONE: Architecture Modernization & Routing]                                      |
|              - Implement modality routing in FastAPI:                                             |
|                * /api/ml/analyze-text  -> Text-specialized model                                  |
|                * /api/ml/analyze-url   -> URL-specialized model (with threshold recalibration)    |
|                * /api/ml/analyze-html  -> Dual-Channel model (payload limit expanded to 2 MB)     |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### Key Phases of Milestone Text-Eval-1:

1. **Dataset Identification & Verification (Read-Only):**
   - Survey publicly available, peer-reviewed independent SMS / email phishing datasets.
   - Verify license, collection timeframe (preferring 2023–2025), sample counts, and label provenance.
2. **Deterministic Independence Audit:**
   - Execute exact-text normalized hashing and 64-bit SimHash screening against the entire 77,677 project corpus to guarantee zero leakage.
3. **Frozen Model Baseline Evaluation:**
   - Evaluate the frozen V2 text model and V3 variants strictly on the independent text dataset.
   - Specifically measure performance across two distinct sub-cohorts:
     - Text containing embedded URLs.
     - Pure text containing no URLs (social engineering, callback scams).
4. **Decision Gate:**
   - Use the empirical metrics to decide whether V2 should be retained for SMS/text or if a dedicated text/message model must be trained before updating the FastAPI `/api/ml/analyze` endpoint.

---

## 4. Policy for Application & Model Changes

Until Milestone Text-Eval-1 is completed:
- **Do NOT retrain or overwrite the frozen V2 or V3 models.**
- **Do NOT alter the FastAPI endpoint schemas or remove validation bounds in production.**
- Keep all research bounded, reproducible, and verifiable.
