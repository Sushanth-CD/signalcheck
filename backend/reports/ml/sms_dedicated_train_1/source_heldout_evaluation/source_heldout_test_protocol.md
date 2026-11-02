# Source-Held-Out Evaluation Protocol: Frozen SMS-03 Phishing Classifier

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation Benchmark  
**Evaluation Target:** Frozen SMS-03 Combined Classifier ([`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib))  
**Target SHA-256:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`  
**Status:** Protocol Specification & Benchmark Design (No Inference Performed)  
**Date:** November 2026  

---

## 1. Objective and Evaluation Premise

The SMS-03 model was trained exclusively on smishing from the modern **WSPR-NCSU** gateway dataset and negative controls from **UCI** and **ExAIS**. In the internal test evaluation, SMS-03 demonstrated exceptional performance ($F_1 = 0.9667$, Specificity $= 98.83\%$).

However, the internal test had a structural limitation: **100% of its positive smishing test instances were link-bearing and originated from WSPR-NCSU**.

This protocol defines an untouched, source-held-out evaluation benchmark using the **Mishra & Soni SMS Phishing Dataset** to answer two critical research questions:
1. **Source Independence:** Does SMS-03 generalize to smishing lures collected independently of WSPR-NCSU?
2. **Modality & Link Independence:** How does SMS-03 perform on smishing lures that do **not** contain web URLs (e.g., telephone callback lures, premium rate SMS, conversational scams), which constitute ~78% of Mishra & Soni's smishing cohort?

---

## 2. Cohort Sizing and Sampling Design

The recommended target benchmark specified:
- 200 Smishing messages
- 200 Benign Ham messages
- 100 Commercial Spam messages
- **Total:** 500 messages

### Availability Check Against Eligible Cohort
From our independence screening ([`eligible_source_cohort.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/eligible_source_cohort.csv)), the pristine, unpolluted counts are:
- **Eligible Smishing Available:** **526** unique messages ($\ge 200$, target easily met).
- **Eligible Commercial Spam Available:** **435** unique messages ($\ge 100$, target easily met).
- **Eligible Benign Ham Available:** **3,713** unique messages ($\ge 200$, target easily met).

### Stratified Sampling Specification
To prevent selection bias while ensuring balanced coverage across link modalities, sampling from `eligible_source_cohort.csv` must follow fixed random seeds (`SEED = 20261102`):

```
+---------------------------------------------------------------------------------------------------+
| PROPOSED 500-MESSAGE SOURCE-HELDOUT BENCHMARK                                                     |
+---------------------------------------------------------------------------------------------------+
|  1. Malicious Smishing: N = 200                                                                   |
|     - URL-bearing smishing: 44 messages (proportional to ~22% natural rate)                       |
|     - Linkless smishing (callback/SMS lures): 156 messages (proportional to ~78% natural rate)    |
|                                                                                                   |
|  2. Benign Personal Ham: N = 200                                                                  |
|     - Uniform random sample from 3,713 eligible non-UCI ham records                               |
|                                                                                                   |
|  3. Commercial Marketing Spam: N = 100                                                            |
|     - URL-bearing spam: 27 messages                                                               |
|     - Linkless spam: 73 messages                                                                  |
|                                                                                                   |
|  TOTAL BENCHMARK SIZE: N = 500 records                                                            |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Strict Integrity and Isolation Rules

1. **Frozen Artifact Invariance:** The model artifact [`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib) must remain byte-identical. SHA-256 hash `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df` must be re-verified before and after execution.
2. **Frozen Operating Threshold:** All metrics must be computed strictly at the frozen decision threshold of **0.50**. Threshold tuning on this evaluation set is strictly prohibited.
3. **No Retraining or Fitting:** No record from Mishra & Soni shall ever be added to model training matrices or hyperparameter tuning loops.
4. **Permanent Quarantine of Pilot:** The TEXT-EVAL-1 250-record pilot remains untouched and independent.
5. **No Inference in Current Turn:** No model inference was executed during this planning phase.

---

## 4. Evaluation Metrics and Subgroup Reporting Plan

When authorized, the source-held-out evaluation will compute and log:

### Primary Metrics
- **Overall Binary Accuracy**
- **Balanced Accuracy**
- **Smishing Recall (Sensitivity)**: Primary measure of cross-source phishing detection.
- **Benign Ham Specificity & FPR**: Must remain $\ge 98\%$ to confirm low false alarms on genuine text.
- **Commercial Spam FPR**: Key measure of the model's ability to separate malicious attacks from aggressive advertising.
- **Precision, F1 Score, ROC-AUC, and PR-AUC**.

### Mandatory Subgroup Disaggregations
To diagnose failure modes, performance must be broken down by:
1. **Link Modality:** URL-present ($N=81$) vs URL-absent ($N=419$).
2. **Attack Type:** Callback/Phone-oriented smishing vs Link-oriented smishing.
3. **Message Length Tiers:** Short ($\le 70$ chars), Standard (71–140 chars), Long ($> 140$ chars).
