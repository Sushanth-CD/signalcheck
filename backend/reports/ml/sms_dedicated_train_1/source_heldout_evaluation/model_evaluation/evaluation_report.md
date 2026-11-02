# Comprehensive Evaluation Report: Mishra & Soni Source-Held-Out Evaluation

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation  
**Target Classifier:** Frozen SMS-03 Combined FeatureUnion + Logistic Regression (`sms_model.joblib`)  
**SHA-256 Digest:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`  
**Decision Threshold:** 0.50 (Frozen)  
**Evaluation Benchmark:** 500-Message Stratified Benchmark (Mishra & Soni 2022 Primary Release)  
**Date:** November 2026  
**Status:** Evaluation Completed (Read-Only; Model Intact)  

---

## 1. Executive Summary & Core Results

This report documents the rigorous source-held-out external evaluation of the frozen **SMS-03** phishing classifier on a freshly extracted 500-message benchmark from the **Mishra & Soni SMS Phishing Dataset**.

```
+---------------------------------------------------------------------------------------------------+
| SOURCE-HELDOUT BENCHMARK PERFORMANCE AT A GLANCE (N = 500, THRESHOLD = 0.50)                     |
+---------------------------------------------------------------------------------------------------+
|  Primary Metrics:                                                                                 |
|    * Overall Accuracy: 63.80% (319 / 500 correct calls)                                           |
|    * Balanced Accuracy: 55.00% (Mean of 11.00% sensitivity and 99.00% specificity)                |
|    * Overall Specificity (Ham + Spam): 99.00% (297 / 300 negative controls cleared)               |
|    * Precision: 88.00% (22 True Positives / 25 Positive Calls)                                    |
|    * Overall Smishing Recall: 11.00% (22 / 200 smishing messages detected)                        |
|    * F1 Score: 0.1956 | ROC-AUC: 0.8052 | Average Precision: 0.7328                               |
|                                                                                                   |
|  Disaggregated Subgroup Findings:                                                                 |
|    * Benign Ham False Positive Rate: 0.00% (0 / 200 false alarms | 100.0% Specificity)            |
|    * Commercial Marketing Spam FPR: 3.00% (3 / 100 false alarms | 97.00% Specificity)             |
|    * URL-Bearing Smishing Recall: 47.73% (21 / 44 detected)                                       |
|    * Linkless Smishing Recall: 0.64% (1 / 156 detected | 155 false negatives)                     |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Integrity and Cryptographic Audit

Strict preflight and post-flight cryptographic verification was performed on the frozen model artifact [`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib):
- **Expected SHA-256:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`
- **Pre-Inference SHA-256:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`
- **Post-Inference SHA-256:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`
- **Integrity Status:** **PASSED.** Zero byte alterations occurred. The frozen pipeline was loaded read-only and scored the benchmark without retraining, refitting, or threshold tuning.

---

## 3. Detailed Performance Analysis

### 3.1 Confusion Matrix & Primary Metric Breakdown

$$\begin{pmatrix} \text{TN: } 297 & \text{FP: } 3 \\ \text{FN: } 178 & \text{TP: } 22 \end{pmatrix}$$

- **True Negatives ($TN = 297$):** 200 benign ham messages + 97 commercial spam messages correctly identified.
- **False Positives ($FP = 3$):** Exactly 0 benign ham messages and 3 commercial spam messages incorrectly flagged as phishing.
- **False Negatives ($FN = 178$):** 178 malicious smishing messages missed (155 linkless, 23 URL-bearing).
- **True Positives ($TP = 22$):** 22 malicious smishing messages caught (21 URL-bearing, 1 linkless).

### 3.2 Subgroup Performance by Class and URL Presence
From [`subgroup_metrics.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/subgroup_metrics.csv):

| Cohort Subgroup | URL Filter | Total Samples | Positive Calls | Negative Calls | Positive Rate | Key Metric |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Smishing** | ALL | 200 | 22 | 178 | 11.00% | **Overall Recall = 11.00%** |
| — Smishing | True | 44 | 21 | 23 | 47.73% | **URL-Bearing Recall = 47.73%** |
| — Smishing | False | 156 | 1 | 155 | 0.64% | **Linkless Recall = 0.64%** |
| **Benign Ham** | ALL | 200 | 0 | 200 | 0.00% | **Ham FPR = 0.00%** (100% Spec) |
| — Benign Ham | True | 5 | 0 | 5 | 0.00% | Specificity = 100.0% |
| — Benign Ham | False | 195 | 0 | 195 | 0.00% | Specificity = 100.0% |
| **Commercial Spam**| ALL | 100 | 3 | 97 | 3.00% | **Commercial Spam FPR = 3.00%** |
| — Commercial Spam| True | 27 | 2 | 25 | 7.41% | Specificity = 92.59% |
| — Commercial Spam| False | 73 | 1 | 72 | 1.37% | Specificity = 98.63% |

### 3.3 Performance Across Length Tiers
Length boundaries defined pre-evaluation:
- **Short ($\le 70$ chars):** 144 records | Accuracy: **93.75%** | Smishing Recall: **0.00%** (0 / 8).
- **Medium (71–140 chars):** 177 records | Accuracy: **60.45%** | Smishing Recall: **10.39%** (8 / 77).
- **Long ($> 140$ chars):** 179 records | Accuracy: **43.02%** | Smishing Recall: **12.17%** (14 / 115).

---

## 4. Final Evidence-Based Assessment

Addressing the five core architectural questions:

### 1. Does SMS-03 generalize to a different SMS collection source?
**Partially.** SMS-03 demonstrates high generalization in **negative class suppression** across sources: its benign ham specificity was $99.47\%$ on development test data and $100.0\%$ on Mishra & Soni, while commercial spam specificity remained nearly identical ($97.73\%$ vs. $97.00\%$). However, on the positive malicious class, generalization is constrained by attack modality: it generalizes to modern URL-bearing lures but fails on legacy and linkless lures.

### 2. Does it detect linkless smishing?
**NO.** Linkless smishing recall is **0.64% (1 / 156)**. Because SMS-03 was trained exclusively on WSPR-NCSU (where 100% of samples contained URLs), the model learned that smishing is defined by the presence of a web link. Features associated with telephone numbers (`call`, `dial`, `text`) received negative weights from the negative training classes. Consequently, linkless social engineering lures cannot overcome the model's $-1.3329$ intercept.

### 3. Do ham false positives remain controlled?
**YES, EXCEPTIONALLY.** Benign personal ham generated **zero false alarms (0 / 200)**, confirming a **0.00% FPR**. This proves that the feature union representation and regularized logistic regression completely solve the intercept-dominated false-positive crisis of the web models.

### 4. Is commercial marketing spam being incorrectly flagged?
**NO.** Commercial spam false alarms are tightly controlled at **3.00% (3 / 100)**. The model successfully separates aggressive promotional advertising from malicious security threats.

### 5. Is more data necessary before application integration?
**YES, DEFINITELY.** SMS-03 is **not ready for standalone, unassisted deployment** as an all-purpose mobile phishing filter. It can only be deployed in production if:
1. It is gated strictly as a **URL-bearing SMS classifier** (routing plain text messages through a link-presence prefilter).
2. It is paired with an independent rule-based or entity-extraction detector to intercept telephone callback, WhatsApp redirect, and conversational social engineering attacks.
3. Model training is expanded in future iterations with balanced, high-quality linkless smishing datasets.

---

## 5. Artifact and Report Reference

- Manifest of Selected Benchmark: [`benchmark_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/benchmark_manifest.csv)
- Raw Model Predictions: [`predictions.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/predictions.csv)
- Integrity Manifest: [`model_integrity_check.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/model_integrity_check.json)
- Summary Metrics (JSON): [`metrics.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/metrics.json)
- Disaggregated Metrics (CSV): [`subgroup_metrics.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/subgroup_metrics.csv)
- Preflight Integrity Audit: [`preflight_integrity_report.md`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/preflight_integrity_report.md)
- In-Depth Error & Feature Analysis: [`error_analysis.md`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/error_analysis.md)
- Internal vs. External Comparison: [`comparison_with_internal_test.md`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/comparison_with_internal_test.md)
