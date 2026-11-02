# Model Comparison: SMS-01, SMS-02, and SMS-03 on Validation

**Milestone:** SMS-DEDICATED-TRAIN-1 Phase 4  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/experiments/model_comparison.md`  
**Evaluation Partition:** Proposed V3 Validation Partition ($N = 805$)  

---

## 1. Executive Summary

Three dedicated SMS phishing classifiers were trained strictly on the Proposed V3 Train partition ($N=3,789$) using identical binary labels (`smishing = 1`, `ham = 0`, `commercial_spam = 0`) and evaluated on the held-out Validation partition ($N=805$):

1. **SMS-01: Word TF-IDF + Logistic Regression** (word n-grams 1–2, 25k features)
2. **SMS-02: Character TF-IDF + Logistic Regression** (char_wb n-grams 3–5, 50k features)
3. **SMS-03: Combined Word + Character FeatureUnion + Logistic Regression** (hybrid 75k features)

---

## 2. Validation Performance Matrix (Decision Threshold = 0.50)

| Evaluation Metric | SMS-01 (Word) | SMS-02 (Char) | SMS-03 (Combined - SELECTED) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 0.9727 | 0.9739 | **0.9764** |
| **Precision** | 0.9563 | 0.9522 | **0.9614** |
| **Recall (Smishing Sensitivity)** | 0.9381 (197/210) | **0.9476 (199/210)** | **0.9476 (199/210)** |
| **Specificity (Overall Negative)** | 0.9849 | 0.9832 | **0.9866** |
| **F1 Score** | 0.9471 | 0.9499 | **0.9544** |
| **Balanced Accuracy** | 0.9615 | 0.9654 | **0.9671** |
| **ROC-AUC** | 0.9974 | 0.9966 | **0.9978** |
| **Average Precision (PR-AUC)** | 0.9926 | 0.9901 | **0.9939** |
| **Fit Time** | **0.45s** | 2.73s | 3.72s |

---

## 3. Disaggregated Category False-Positive Rates on Validation

| Category | Total Samples | SMS-01 False Alarms | SMS-02 False Alarms | SMS-03 False Alarms (SELECTED) |
| :--- | :---: | :---: | :---: | :---: |
| **Benign Ham (`ham`)** | 374 | 3 (**0.80% FPR**) | **1 (0.27% FPR)** | 2 (**0.53% FPR**) |
| **Commercial Spam (`commercial_spam`)** | 221 | 6 (**2.71% FPR**) | 9 (4.07% FPR) | 6 (**2.71% FPR**) |
| **Confirmed Smishing (`smishing`)** | 210 | 197 (**93.81% Recall**) | **199 (94.76% Recall)**| **199 (94.76% Recall)** |

---

## 4. Source Disaggregation on Validation

| Subgroup (Source $\times$ Category) | N Evaluated | SMS-01 Flagged | SMS-02 Flagged | SMS-03 Flagged | Metric Interpretation |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **UCI Ham** | 187 | 0 (0.00%) | 0 (0.00%) | **0 (0.00%)** | Benign False Positive Rate |
| **ExAIS Ham** | 187 | 3 (1.60%) | 1 (0.53%) | **2 (1.07%)** | Benign False Positive Rate |
| **UCI Commercial Spam** | 5 | 0 (0.00%) | 0 (0.00%) | **0 (0.00%)** | Commercial Spam FP Rate |
| **ExAIS Commercial Spam** | 216 | 6 (2.78%) | 9 (4.17%) | **6 (2.78%)** | Commercial Spam FP Rate |
| **WSPR Smishing** | 210 | 197 (93.81%) | 199 (94.76%) | **199 (94.76%)** | Smishing Detection Recall |

---

## 5. Architectural Trade-Off Analysis

1. **SMS-01 (Word TF-IDF):**  
   - *Strengths:* Ultra-fast training (0.45s), low memory, lowest commercial spam FPR (2.71%).  
   - *Weakness:* Lowest smishing recall (93.81%, misses 13 campaigns). Misses obfuscated or short-token variants.
2. **SMS-02 (Character TF-IDF):**  
   - *Strengths:* Highest raw recall (94.76%), lowest ham FPR on ExAIS (0.53%).  
   - *Weakness:* Slightly elevated commercial spam false positive rate (4.07%, 9 marketing messages falsely flagged).
3. **SMS-03 (Combined FeatureUnion):**  
   - *Strengths:* Achieves the best of both worlds: matches SMS-02's peak smishing recall (**94.76%**, 199/210) while achieving SMS-01's low commercial spam FPR (**2.71%**, 6/221) and an exceptionally low benign ham FPR (**0.53%**, 2/374).  
   - Highest overall Balanced Accuracy (**0.9671**), F1 score (**0.9544**), and ROC-AUC (**0.9978**).
