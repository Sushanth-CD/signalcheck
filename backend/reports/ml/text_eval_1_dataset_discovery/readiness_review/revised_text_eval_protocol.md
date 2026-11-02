# Revised Text-Eval-1 Benchmark Protocol

**Milestone:** TEXT-EVAL-1 Readiness Review  
**Scope:** Revised Multi-Cohort Benchmark Design, Label Semantics, and Isolation Rules  
**Status:** Protocol Specification  
**Date:** November 2026  

---

## 1. Executive Summary: Architecture & Cohort Allocations

To evaluate our frozen models across diverse, realistic, and independently screened plain-text attack vectors without dataset contamination, we establish five isolated evaluation cohorts:

```
+---------------------------------------------------------------------------------------------------+
| REVISED TEXT-EVAL-1 BENCHMARK COHORTS                                                             |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [COHORT A: Confirmed Mobile Smishing]                                                            |
|  - Source: WSPR-NCSU SMS Phishing (IEEE S&P 2024)                                                 |
|  - Pilot Target: 100 samples (from 100 distinct campaigns)                                        |
|  - Ground Truth Label: Positive (1 = Phishing)                                                    |
|                                                                                                   |
|  [COHORT B: Independent Legitimate SMS (Ham)]                                                     |
|  - Source: UCI SMS Spam Collection (Ham subset, post-screened) + ExAIS_SMS (Ham subset)           |
|  - Pilot Target: 100 samples (strictly passing exact-hash & SimHash screening)                    |
|  - Ground Truth Label: Negative (0 = Benign)                                                      |
|                                                                                                   |
|  [COHORT C: Generic Commercial SMS Spam (Nuisance Control)]                                      |
|  - Source: ExAIS_SMS (Spam subset) + UCI SMS (Spam subset, post-screened)                          |
|  - Pilot Target: 50 samples                                                                       |
|  - Ground Truth Label: Evaluated as Negative for Phishing (Should NOT trigger phishing alert)     |
|                                                                                                   |
|  [COHORT D: Confirmed Phishing Emails]                                                            |
|  - Source: Zenodo CEAS 2008 Sub-Corpus (`CEAS_08.csv`) + IWSPA-AP V1.0 Phishing                  |
|  - Pilot Target: 100 samples (Enron/Nazario strictly excluded)                                    |
|  - Ground Truth Label: Positive (1 = Phishing)                                                    |
|                                                                                                   |
|  [COHORT E: Independent Legitimate Emails]                                                        |
|  - Source: Zenodo CEAS 2008 Sub-Corpus (`CEAS_08.csv`) Legitimate subset                           |
|  - Pilot Target: 100 samples                                                                      |
|  - Ground Truth Label: Negative (0 = Benign)                                                      |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Cohort Specifications & Label Semantics

| Cohort | Description | Proposed Pilot Size | Positive / Negative Semantics | Sourcing Strategy | Grouping & Isolation Requirement |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **Cohort A** | Confirmed Smishing | **100** | $Y = 1$ (Phishing) | Sampled from `wspr-ncsu/sms-phishing` (`phishing_messages.csv`). | Exactly 1 message per `campaign_id`. PII (destination numbers) stripped. |
| **Cohort B** | Legitimate SMS | **100** | $Y = 0$ (Benign) | Screened Ham from UCI SMS and ExAIS_SMS. | Discard all samples colliding with Mishra & Soni / 77,677 corpus. |
| **Cohort C** | Generic Commercial Spam | **50** | $Y = 0$ (Nuisance Spam $\ne$ Phishing) | Commercial marketing texts from ExAIS_SMS and UCI Spam. | Measures nuisance vs. security threat discrimination. |
| **Cohort D** | Phishing Emails | **100** | $Y = 1$ (Phishing) | Extracted bodies from `CEAS_08.csv` (label=1). | Exclude all Enron and Nazario records. Screen against project corpus. |
| **Cohort E** | Legitimate Emails | **100** | $Y = 0$ (Benign) | Extracted bodies from `CEAS_08.csv` (label=0). | Screen against project corpus. |

---

## 3. Model Evaluation and Restriction Matrix

```
+---------------------------------------------------------------------------------------------------+
| MODEL ROUTING RULES FOR TEXT-EVAL-1                                                               |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  Cohort / Condition              V2 Baseline     V3 Content-Only   V3 URL-Only   V3 Dual-Channel   |
|  -----------------------------------------------------------------------------------------------  |
|  Message WITH extractable URL    EVALUATE        EVALUATE          EVALUATE      EVALUATE          |
|  Message WITHOUT extractable URL EVALUATE        EVALUATE          BLOCKED*      EVALUATE (stub)   |
|                                                                                                   |
|  *CRITICAL RULE: V3 URL-Only outputs an empty token string when no URL is detected. Evaluating   |
|   it on URL-absent text is structurally invalid and prohibited.                                   |
+---------------------------------------------------------------------------------------------------+
```

### Metrics:
- Fixed decision threshold $\tau = 0.50$ across all models.
- Core metrics: Recall, Specificity, False Positive Rate (FPR), Precision, F1-Score, Balanced Accuracy.
- Stratified reporting by:
  - Short ($\le 100$ chars) vs. Long ($> 100$ chars) messages.
  - URL-present vs. URL-absent messages.
  - Commercial spam false alarm rate (Cohort C).
