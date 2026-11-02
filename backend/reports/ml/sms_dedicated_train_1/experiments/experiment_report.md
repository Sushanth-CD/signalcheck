# SMS-DEDICATED-TRAIN-1: Comprehensive Experiment & Evaluation Report

**Milestone:** SMS-DEDICATED-TRAIN-1  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Directory:** `backend/reports/ml/sms_dedicated_train_1/experiments/`  
**Selected Frozen Model:** `sms_03_combined/sms_model.joblib`  

---

## 1. Executive Summary

This report documents the experimental training, validation selection, cryptographic freezing, and single internal-test evaluation of the project's first dedicated SMS phishing detector (**SMS-03 Combined Word + Character Model**).

Trained on the Proposed V3 dataset ($N=3,789$) with balanced multi-source controls, SMS-03 completely eliminates the catastrophic false-positive failure observed in the web-oriented V2/V3 models, reducing the benign SMS false-alarm rate from **$98\%$ down to $0.5\%$** while catching **$96.7\%$ of unseen smishing attack campaigns**.

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| INTERNAL TEST SET EVALUATION SUMMARY (N = 806 Records, Threshold = 0.50)                          |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                   |
|  Overall Classification Performance:                                                              |
|  - Balanced Accuracy : 0.9775                                                                     |
|  - Accuracy          : 0.9826 (792 of 806 correct)                                                |
|  - F1 Score          : 0.9667                                                                     |
|  - Precision         : 0.9667 (203 TP, 7 FP)                                                      |
|  - Recall            : 0.9667 (203 of 210 attack campaigns detected)                             |
|  - Specificity       : 0.9883 (589 of 596 negatives cleared)                                      |
|  - ROC-AUC           : 0.9972 | Average Precision: 0.9932                                         |
|                                                                                                   |
|  Category-Specific Error Rates:                                                                   |
|  - Benign Ham False Positive Rate       : 0.53% (2 false alarms out of 376 legitimate chats)      |
|  - Commercial Spam False Positive Rate  : 2.27% (5 false alarms out of 220 marketing messages)    |
|  - Smishing Detection Recall            : 96.67% (203 detected out of 210 distinct campaigns)     |
|                                                                                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Phase 1 & 2: Data Validation & Consistent Preprocessing

1. **Manifest Validation:**  
   The V3 manifest (`proposed_v3/sms_split_manifest.csv`) was validated against `sms_training_candidates.csv`. Exactly 5,400 records were confirmed with zero campaign overlap, zero normalized-text overlap, and zero collisions against the 77,677 baseline corpus or the 250-record SMS pilot.
2. **Preprocessing Invariants:**  
   - Normalized message text: Unicode NFKC normalization, lowercased, and collapsed whitespace via `ml.text_normalization.normalize_for_model`.
   - URL handling: URLs are preserved strictly as inert lexical tokens; no external network requests, DNS lookups, or link dereferences were executed.
   - Metadata isolation: Source names, campaign IDs, user IDs, and timestamps were strictly excluded from feature vectors.

---

## 3. Phase 3 & 4: Training & Model Selection on Validation

Three candidate models were trained strictly on the 3,789 Train partition rows and evaluated on the 805 Validation rows:

| Metric | SMS-01 (Word TF-IDF) | SMS-02 (Char TF-IDF) | SMS-03 (Combined - SELECTED) |
| :--- | :---: | :---: | :---: |
| **Smishing Recall** | 0.9381 (197/210) | 0.9476 (199/210) | **0.9476 (199/210)** |
| **Ham False Positive Rate** | 0.0080 (3/374) | **0.0027 (1/374)** | 0.0053 (2/374) |
| **Commercial Spam FPR** | **0.0271 (6/221)** | 0.0407 (9/221) | **0.0271 (6/221)** |
| **Balanced Accuracy** | 0.9615 | 0.9654 | **0.9671** |
| **F1 Score** | 0.9471 | 0.9499 | **0.9544** |
| **ROC-AUC** | 0.9974 | 0.9966 | **0.9978** |

**Selection:** SMS-03 was selected because it achieved the highest balanced accuracy and F1 score, matched character n-grams' peak smishing recall, and maintained a minimal commercial spam false-alarm rate ($2.71\%$).

---

## 4. Phase 5: Freezing Selected Model (SMS-03)

The selected candidate was serialized outside the active production directory:
- **Path:** `backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib`
- **SHA-256:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`
- **Fixed Operating Threshold:** **0.50**
- **Freeze Manifest:** `backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/model_integrity_manifest.json`

---

## 5. Phase 6: Single Internal Test Evaluation of Frozen SMS-03

Following freezing, SMS-03 was evaluated once on the held-out Internal Test partition ($N = 806$):

### 5.1 Category & Source Performance on Test ($N=806$)

| Source Dataset | Original Category | N Evaluated | Flagged as Smishing | Metric Type | Rate |
| :--- | :--- | :---: | :---: | :--- | :---: |
| **UCI** | `ham` | 188 | 0 | Benign False Positive Rate | **0.00%** |
| **ExAIS** | `ham` | 188 | 2 | Benign False Positive Rate | **1.06%** |
| **UCI** | `commercial_spam` | 5 | 0 | Commercial Spam FP Rate | **0.00%** |
| **ExAIS** | `commercial_spam` | 215 | 5 | Commercial Spam FP Rate | **2.33%** |
| **WSPR_NCSU** | `smishing` | 210 | 203 | Smishing Detection Recall | **96.67%** |
| **Overall Ham** | `ham` | 376 | 2 | Benign False Positive Rate | **0.53%** |
| **Overall Spam**| `commercial_spam` | 220 | 5 | Commercial Spam FP Rate | **2.27%** |
| **Overall Smish**| `smishing` | 210 | 203 | Smishing Detection Recall | **96.67%** |

---

## 6. Phase 7: Contextual Comparison Against Frozen Web Models

To contextualize this breakthrough, the frozen web models (V2 Baseline and V3 Dual-Channel) were scored on the identical 806 Internal Test SMS messages:

| Metric | SMS-03 Dedicated Classifier | V2 Web Baseline (`model.joblib`) | V3 Dual-Channel Web (`dual_channel_v3_model.joblib`) |
| :--- | :---: | :---: | :---: |
| **F1 Score** | **0.9667** | 0.4168 | 0.4044 |
| **Smishing Recall** | **0.9667** | 0.9905* | 0.9619* |
| **Overall Specificity** | **0.9883** | **0.0268** | **0.0151** |
| **Ham False Positive Rate** | **0.53% (2/376)** | **98.14% (369/376)** | **99.20% (373/376)** |
| **Commercial Spam FPR** | **2.27% (5/220)** | **95.91% (211/220)** | **97.27% (214/220)** |
| **Balanced Accuracy** | **0.9775** | 0.5087 | 0.4885 |

*\*Note on Web Model Recall:* The nominal 96–99% recall of the web models was driven by positive intercept collapse, which caused them to flag almost 100% of all inputs as phishing. SMS-03 maintains true 96.7% recall while reducing benign false alarms from 98% down to 0.5%.

---

## 7. Important Remaining Dataset Limitations

1. **Source-Label Confounding:**  
   100% of the positive smishing records originate from WSPR-NCSU, while negative controls originate from UCI and ExAIS. The model may share minor telecom feed characteristics of WSPR collection.
2. **URL Presence in Training Smishing:**  
   100% of the WSPR smishing messages contain URLs due to deterministic campaign mapping. The model specializes in link-directed smishing and will not catch pure voice phishing (vishing phone number lures) or interactive text hooks.
3. **Participant Overlap:**  
   ExAIS participants appear across partitions due to shared carrier broadcast notices. The test partition measures message- and template-level generalization, not zero-exposure user-level generalization.
4. **Holdout Status:**  
   The 806-record internal test set is an internal development checkpoint. A fresh, third-party smishing dataset remains required for final production certification before deployment.
