# Input Modality Gaps & Compatibility Analysis

**Audit Scope:** Cross-Modality Architecture Gap Analysis  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Date:** November 2026  

---

## 1. Executive Summary

The Cyber Security Awareness Platform is conceived as an educational and defensive tool to evaluate potential cyber threats across different attack vectors:
1. **SMS and instant messaging** (short text, informal language, mobile links).
2. **Email text** (longer narrative bodies, formal notifications, embedded action links).
3. **Standalone URLs** (user-submitted links, suspicious browser redirects).
4. **Webpage content** (raw HTML, DOM structures, login form markup).

This document analyzes the gap between the models currently implemented and the actual modalities expected in production. It distinguishes **empirically demonstrated capabilities** from **untested architectural assumptions**.

---

## 2. Modality Readiness Matrix

| Input Modality | Existing Model | Evaluation Evidence | Integration Readiness |
| :--- | :--- | :--- | :--- |
| **SMS / Plain Text** | **V2 Baseline** (`phishing_tfidf_logreg_domain_grouped`)<br>*(or V3 Dual-Channel)* | **Weak / In-Domain Only:** Evaluated on V2 internal validation test set containing mixed text snippets (F1 ~0.90). **Severe gap:** V3 Content-Only exhibited 0.00% specificity on short text $\le 100$ chars (263/263 false alarms). Zero independent external SMS/text benchmark has been evaluated. | **Experimental Only.** Cannot reliably distinguish promotional SMS, OTPs, or casual text without unacceptable false positive rates or blind spots when no URL is present. |
| **Suspicious Email Text** | **V2 Baseline**<br>*(or V3 Dual-Channel)* | **Moderate / In-Domain Only:** Trained on synthetic and legacy email text corpora (`combined_reduced.json`). High validation accuracy within the training distribution. However, susceptible to concept drift and keyword manipulation. | **Partially Ready (with Caveats).** Works for basic keyword-heavy lures, but lacks calibration against contemporary legitimate newsletters, marketing mail, and business correspondence. |
| **Standalone URL** | **V3 URL-Only** (`url_only_model.joblib`)<br>*(V2 currently loaded in API)* | **Demonstrated on Web Data:** Evaluated on 2,000 independent CompPhish V4 samples. Achieved **Recall = 88.49%** across multiple live feeds. **Known Defect:** Severe False Positive Rate (**35.69% overall**, climbing to **42.51%** on contemporary 2025 web crawls). | **Not Production-Ready.** 35.7% FPR causes massive alert fatigue. Missing operational endpoint. Requires threshold recalibration and modern benign domain re-weighting. |
| **Raw HTML** | **V3 Dual-Channel** (`dual_channel_v3_model.joblib`)<br>*(V2 currently loaded in API)* | **Demonstrated on Web Data:** Evaluated on 2,000 independent CompPhish V4 samples. Achieved **F1 = 0.6947**, **Recall = 67.80%**, **Specificity = 75.80%**. Proved that fusing HTML content cuts URL false alarms by 32% (from 379 to 257). However, dropped to 59.4% recall on cloaked/stub landing pages. V2 baseline collapsed completely (Recall = 8.85%). | **Not Ready for Active API.** The active API (`/api/ml/analyze`) has a 10,000-character ceiling that rejects real HTML files, and currently loads V2 which has 8.85% recall on HTML. Dual-Channel requires an updated ingestion pipeline. |

---

## 3. Detailed Modality Analysis

### 3.1 Plain Text & SMS Modality
- **Demonstrated Findings:**
  - V2 Baseline was trained on unstructured text, including short messages.
  - V3 experiments revealed a critical failure mode in text processing: when URLs are removed or absent, the content channel over-indexes on general alert words (`urgent`, `verify`, `account`, `suspended`). On the internal validation split, `short_messages_le_100` resulted in **0% specificity** for Content-Only.
- **Architectural Gaps:**
  - The project has **never evaluated an independent, pure-text phishing dataset** (such as external SMS spam/smishing corpora or real-world conversational lures).
  - All recent rigorous external evaluation (PhreshPhish pilot, CompPhish V4 100-record pilot, CompPhish V4 2,000-sample corpus) was strictly focused on **web URLs and HTML landing pages**.
  - As a result, claims about the platform's performance on plain-text messages rest almost entirely on synthetic in-sample cross-validation.

### 3.2 Suspicious Email Text Modality
- **Demonstrated Findings:**
  - Emails typically contain both contextual text (greeting, hook, call to action) and action links (buttons, href targets).
  - V3 Dual-Channel is conceptually well-matched to this modality because its dual pipeline processes both the narrative body and the link parameters.
- **Architectural Gaps:**
  - The current API endpoint does not extract links from HTML emails prior to analysis. If an email is submitted as raw MIME or HTML, it is either rejected for exceeding 10,000 characters or corrupted by raw markup tags entering the V2 vectorizer.
  - No independent email corpus with verified modern sender headers, authentication results (SPF/DKIM/DMARC), and body text has been evaluated.

### 3.3 Standalone URL Modality
- **Demonstrated Findings:**
  - V3 URL-Only provides high sensitivity ($88.49\%$ recall on CompPhish V4), proving that structural tokenization (host labels, path slugs, parameter names) successfully captures modern phishing infrastructure patterns.
  - However, specificity is deficient ($64.31\%$), producing 379 false alarms across 1,062 legitimate domains.
- **Architectural Gaps:**
  - The active FastAPI backend has **no URL-specific endpoint** (e.g., `POST /api/ml/analyze-url`).
  - When a user submits a URL to `POST /api/ml/analyze`, it is passed to the V2 text model, which decomposes the URL using generic regex word patterns rather than the V2 candidate URL extractor.
  - The URL model's reliance on tokens like `www` creates an artificial bias against modern clean domain roots.

### 3.4 Raw HTML / Webpage Content Modality
- **Demonstrated Findings:**
  - V2 Baseline completely fails on raw HTML documents (F1 = 0.1589, Recall = 0.0885).
  - V3 Dual-Channel successfully processes raw HTML by parsing DOM text and extracting candidate URLs in parallel, boosting specificity over URL-Only by 11.5 percentage points.
  - When phishing pages employ evasive maneuvers (empty HTML body, JavaScript-rendered forms, bot-blocking cloaking), Dual-Channel recall degrades to $59.36\%$.
- **Architectural Gaps:**
  - The FastAPI application enforces a hard 10,000-character validation limit on `content`. Because typical HTML files range from 20 KB to 500 KB, **the current API rejects virtually all real-world HTML documents with HTTP 413**.
  - The active API loads V2 Baseline rather than V3 Dual-Channel.
  - The application lacks an automated headless rendering or DOM hydration pipeline (e.g., executing client-side scripts to uncover dynamic DOM forms).

---

## 4. Summary of Assumptions vs. Demonstrated Facts

| Capability Claim | Current Status | Supporting Fact / Refutation |
| :--- | :--- | :--- |
| *"The API can detect phishing in submitted URLs"* | **Assumption / Misaligned** | Submitting a URL to the API invokes V2 Text Baseline, NOT the V3 URL model. V2 has never been evaluated as a standalone URL detector. |
| *"The API can analyze phishing web pages"* | **Assumption / Blocked** | HTTP 413 rejects inputs $>10,000$ chars. If truncated to fit, V2 misses $>91\%$ of phishing HTML (tested on CompPhish V4). |
| *"The V3 URL model is ready for production"* | **Refuted by Evidence** | CompPhish V4 evaluation demonstrated a 35.69% false positive rate on legitimate sites. |
| *"The platform detects SMS phishing reliably"* | **Untested Assumption** | Zero external SMS test data has been evaluated; short message validation showed extreme false positive risk. |
| *"Dual-Channel fusion improves over URL-Only"* | **Empirically Demonstrated** | CompPhish V4 proved Dual-Channel reduces false alarms by 122 cases (32% reduction), achieving 75.8% specificity. |
