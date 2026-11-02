# Text-Eval-1 Benchmark Protocol

**Milestone:** TEXT-EVAL-1  
**Scope:** Experimental Design, Evaluation Cohorts, Subgroup Stratification, and Decision Metrics  
**Status:** Protocol Specification Only (Read-Only)  
**Date:** November 2026  

---

## 1. Executive Summary

This protocol defines the exact methodology for evaluating our existing frozen phishing detection models on independent text messages. It establishes three isolated evaluation cohorts (SMS, Email, and URL-containing messages), outlines model routing and restriction rules, and details the performance metrics and subgroup analyses required to make defensible deployment decisions.

---

## 2. Benchmark Architecture & Cohort Definitions

```
+---------------------------------------------------------------------------------------------------+
| TEXT-EVAL-1 BENCHMARK ARCHITECTURE                                                                |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [COHORT A: SMS MODALITY]                                                                         |
|  - A1: Confirmed Smishing/Phishing SMS (WSPR-NCSU IEEE S&P 2024 / IMC 2025)                       |
|  - A2: Benign Ham SMS (UCI SMS Spam Collection - Ham subset)                                      |
|  - A3: Generic Commercial Spam SMS (UCI SMS Spam Collection - Spam subset)                        |
|                                                                                                   |
|  [COHORT B: EMAIL MODALITY]                                                                       |
|  - B1: Confirmed Phishing Email Bodies (IWSPA-AP 2018/2020 & Zenodo CEAS 2008)                     |
|  - B2: Legitimate Business/Personal Email Bodies (IWSPA-AP Benign & Zenodo CEAS Benign)           |
|                                                                                                   |
|  [COHORT C: URL-CONTAINING vs. URL-ABSENT MESSAGES]                                              |
|  - C1: Messages WITH Extractable High-Confidence URLs (Phishing & Benign)                         |
|  - C2: Pure Narrative Messages WITHOUT URLs (Social engineering, phone callback lures, OTP scams) |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### 2.1 Cohort A: Mobile SMS
- **A1 — Confirmed Smishing ($N \approx 500$–$1,000$):** Real-world phishing text messages sourced from WSPR-NCSU (2024) and IMC 2025. Must include bank lures, delivery alerts, toll scams, and credential harvesting hooks.
- **A2 — Benign Ham ($N \approx 1,000$):** Normal conversational, personal, and transactional SMS messages from the UCI SMS Ham subset.
- **A3 — Generic Commercial Spam ($N \approx 300$):** Non-malicious promotional advertising, marketing texts, and ringtone offers from the UCI Spam subset.
  - *Evaluation Purpose for A3:* Measures whether classifiers erroneously label annoying commercial spam as dangerous phishing, or whether they properly differentiate nuisance ads from malicious deception.

### 2.2 Cohort B: Email Bodies
- **B1 — Phishing Email Bodies ($N \approx 500$):** Realistic phishing emails from IWSPA-AP and CEAS 2008. Must exclude Nazario emails.
- **B2 — Legitimate Email Bodies ($N \approx 1,000$):** Routine business, personal, and newsletter emails from IWSPA-AP and CEAS 2008. Must exclude Enron emails.

### 2.3 Cohort C: URL Stratification
Across all acquired SMS and email records, partition samples into two mutually exclusive sub-cohorts:
- **C1 (URL-Present):** Messages where the project's offline V2 candidate parser (`extract_candidates`) detects at least one `high-confidence` URL with status `normalized_hostname` or `ip_literal`.
- **C2 (URL-Absent):** Messages containing zero extractable URLs (pure prose, telephone callback requests, conversational lures).

---

## 3. Model Evaluation & Routing Rules

To ensure scientific rigor, models must only be evaluated where their architecture is technically capable of operating:

```
+---------------------------------------------------------------------------------------------------+
| MODEL ROUTING & EVALUATION MATRIX                                                                 |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  Input Sample                   V2 Baseline     V3 Content-Only   V3 URL-Only   V3 Dual-Channel   |
|  -----------------------------------------------------------------------------------------------  |
|  Message WITH extractable URL   EVALUATE        EVALUATE          EVALUATE      EVALUATE          |
|  Message WITHOUT extractable URL EVALUATE       EVALUATE          DO NOT EVAL*  EVALUATE (stub)   |
|                                                                                                   |
|  *RULE: V3 URL-Only outputs an empty token string when no URL exists, defaulting to the model     |
|   intercept (P = 0.1741). Evaluating URL-Only on URL-absent messages as if it possessed natural   |
|   language detection capability is METHODOLOGICALLY INVALID and strictly prohibited.              |
+---------------------------------------------------------------------------------------------------+
```

### Specific Evaluation Instructions:
1. **V2 Baseline:** Evaluate on all cohorts ($A, B, C1, C2$). Scores the full raw string using word TF-IDF.
2. **V3 Content-Only:** Evaluate on all cohorts ($A, B, C1, C2$). In plain text, strips all detected URL spans and scores remaining prose.
3. **V3 URL-Only:**
   - **Evaluate ONLY on Cohort C1 (URL-Present).**
   - Record coverage statistics: report what percentage of phishing lures and legitimate messages in Cohorts A and B contain extractable URLs.
   - For Cohort C2 (URL-Absent), report coverage = 0. Do not treat intercept fallbacks as active predictions.
4. **V3 Dual-Channel:**
   - Evaluate on Cohort C1 (joint content + URL features).
   - Evaluate on Cohort C2 to measure default degradation when the URL branch produces a zero vector.

---

## 4. Performance Metrics and Subgroup Analyses

### 4.1 Primary Operational Metrics
All evaluations use the frozen operating threshold $\tau = 0.50$ (do NOT tune thresholds on test data):
- **Recall (Sensitivity):** $\text{TP} / (\text{TP} + \text{FN})$ (Target: $\ge 85\%$).
- **Specificity:** $\text{TN} / (\text{TN} + \text{FP})$ (Target: $\ge 90\%$).
- **False Positive Rate (FPR):** $1 - \text{Specificity} = \text{FP} / (\text{FP} + \text{TN})$.
- **Precision:** $\text{TP} / (\text{TP} + \text{FP})$.
- **F1-Score:** Harmonic mean of Precision and Recall.
- **ROC-AUC & Average Precision (PR-AUC):** Threshold-independent discriminative power.

### 4.2 Mandatory Subgroup Analyses
To prevent aggregate Simpson's paradox biases, compute and report metrics separately across:
1. **Length-Stratified Subgroups:**
   - *Short Messages:* $\text{Length} \le 100$ characters (typical SMS / push notifications).
   - *Medium Messages:* $101 < \text{Length} \le 500$ characters (extended SMS / short email notes).
   - *Long Messages:* $\text{Length} > 500$ characters (full email bodies).
2. **Spam vs. Phishing Differentiation:**
   - Specificity on Benign Ham (Cohort A2).
   - False Alarm Rate on Commercial Spam (Cohort A3). (Does the model confuse annoying marketing with malicious phishing?).
3. **Link-Type Stratification (within Cohort C1):**
   - Messages using URL Shorteners (`bit.ly`, `tinyurl`, `t.co`).
   - Messages using IP Literals (`http://192.168.1.1/...`).
   - Messages using Brand-Spoofing Hostnames (`login-paypal-verify.com`).
   - Messages using Bare Domain Roots (`example.com`).

---

## 5. Threshold & Independence Governance

- **Zero Test Tuning:** Threshold $\tau = 0.50$ remains strictly frozen. Threshold sweep curves may be plotted for diagnostic purposes, but reported headline metrics must use $\tau = 0.50$.
- **Zero In-Sample Overlap:** All candidates must pass the 4-stage deduplication check (SHA-256 + SimHash $H \le 3$ + Jaccard $\ge 0.90$ + Domain filter) before inclusion in the final benchmark.
- **Campaign Grouping:** Messages sharing identical campaign IDs or near-identical text shingles must be grouped so that no single burst campaign dominates the metric weights.
