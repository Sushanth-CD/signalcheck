# SMS-05 Evaluation Protocol: Multi-Tier Verification Standards

**Milestone:** SMS-05 Planning — Linkless Smishing Generalization  
**Scope:** Two-Tier Evaluation Architecture, Group Stratification, and Benchmark Isolation  
**Status:** Protocol Specification Complete  
**Date:** November 2026  

---

## 1. Executive Summary & Evaluation Framework

To eliminate the risk of overfitting and ensure that SMS-05 generalizes across independent mobile threat feeds, the evaluation framework is organized into **two completely isolated tiers**:

1. **Tier 1 — Internal Test Partition ($N \approx 1,020$):**  
   Evaluates message-, campaign-, and template-level generalization on unseen records drawn from the balanced development pool (WSPR, IMC 2025, Mishra & Soni Remaining, ExAIS, UCI).
2. **Tier 2 — Independent Source-Held-Out Benchmark ($N \approx 500$):**  
   Evaluates true cross-source generalization on an external mobile phishing feed that **never contributed a single record to SMS-05 development**.

> [!IMPORTANT]
> **Permanent Quarantine Rules:**
> - The **500-message Mishra & Soni benchmark** (`benchmark_manifest.csv`) was already used to diagnose SMS-03 and is **permanently quarantined**. It cannot be used for model selection or development in SMS-05.
> - The **250-message TEXT-EVAL-1 pilot** remains a permanent external diagnostic baseline.
> - A **brand new external corpus** will be designated for Tier 2 evaluation of SMS-05.

---

## 2. Proposed Independent Source for SMS-05 Tier 2 Evaluation

For the Tier 2 external source-held-out evaluation of SMS-05, we designate:

### The Zenodo Multiclass NLP Threat Corpus (2025) / CallShield Global Feeds
- **Source Identifier:** [`10.5281/zenodo.15235123`](https://doi.org/10.5281/zenodo.15235123) / CallShield 2024
- **Target Extraction Size:** Exactly **500 records**:
  - **150 Linkless Smishing Lures** (conversational pretexting, verification codes, fake emergency SMS).
  - **100 URL-Bearing Smishing Lures** (modern cloud shorteners, bank redirects).
  - **150 Benign Personal Ham** (independent everyday mobile chat).
  - **100 Commercial Marketing Spam** (independent retail & subscription advertising).
- **Independence Guarantee:** This dataset postdates all training corpora (published in 2025) and has zero overlap with WSPR, UCI, or ExAIS.

---

## 3. Disaggregated Metrics and Reporting Standard

To prevent high URL-bearing recall from masking poor conversational detection (the exact defect in SMS-03), every evaluation of SMS-05 must compute and report:

### 1. Primary Classification Performance
- Confusion Matrix ($TN, FP, FN, TP$).
- Overall Accuracy and Balanced Accuracy.
- Precision, Recall, Specificity, and F1 Score.
- ROC-AUC and Average Precision (PR-AUC).

### 2. Mandatory Modality Disaggregations
- **Linkless Smishing Recall ($N \ge 150$):**  
  Primary metric testing conversational, telephone callback, and pretexting detection.
- **URL-Bearing Smishing Recall ($N \ge 100$):**  
  Measures detection of modern evasive web links and credential harvesting portals.

### 3. False Alarm Control Subgroups
- **Benign Personal Ham FPR:** Must remain $\le 0.50\%$ (at least $99.50\%$ specificity).
- **Commercial Marketing Spam FPR:** Must remain $\le 3.50\%$ (at least $96.50\%$ specificity).

### 4. Length Tier Performance
- Short ($\le 70$ chars)
- Medium (71–140 chars)
- Long ($> 140$ chars)

---

## 4. Cryptographic Model Freezing Protocol

Before Tier 2 external evaluation begins:
1. The winning SMS-05 model will be serialized to `sms_05_model.joblib`.
2. A cryptographic SHA-256 hash will be calculated and committed to `model_integrity_manifest.json`.
3. The operating threshold will be permanently locked at **0.50**.
4. The SHA-256 hash will be re-verified pre- and post-inference.
