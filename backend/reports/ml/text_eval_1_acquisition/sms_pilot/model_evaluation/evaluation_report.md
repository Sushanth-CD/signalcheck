# TEXT-EVAL-1 SMS Pilot: Independent Model Evaluation Report

**Evaluation Date:** 2026-11-02  
**Project:** `C:\Projects\cyber-security-awareness-platform`  
**Evaluation Scope:** 250 Independent SMS Messages (Cohort A: 100 Smishing, Cohort B: 100 Ham, Cohort C: 50 Commercial Spam)  
**Location:** `backend/reports/ml/text_eval_1_acquisition/sms_pilot/model_evaluation/`  

---

## Executive Summary

As part of the **TEXT-EVAL-1** milestone, the project's frozen phishing detection models (**V2 Baseline**, **V3 Dual-Channel**, **V3 Content-Only**, and **V3 URL-Only**) were evaluated on 250 independently acquired and screened SMS messages.

Prior to inference, all model weights and feature extractors were cryptographically verified against the project freeze manifest (`model_implementation_freeze_manifest.json`), passing with zero discrepancies. Zero models were altered, calibrated, or retrained.

### Key Finding: Severe Cross-Modality Failure
The evaluation establishes an empirical conclusion: **Our existing models, trained on web page HTML and long-form email text, exhibit near-total specificity collapse when evaluated on short plain-text SMS messages.**

```
Primary Benchmark (100 Smishing vs 100 Benign Ham, Threshold = 0.50):
Model              Recall      Specificity    Precision    F1        Balanced Acc
─────────────────────────────────────────────────────────────────────────────────
V2 Baseline        0.9900      0.0400         0.5077       0.6712    0.5150
V3 Dual-Channel    0.9900      0.0200         0.5025       0.6667    0.5050
V3 Content-Only    0.9800      0.1600         0.5385       0.6950    0.5700
V3 URL-Only*       0.9900      0.0909         0.9083       0.9474    0.5405
─────────────────────────────────────────────────────────────────────────────────
*V3 URL-Only evaluated strictly on messages with extractable URLs (100 Smishing vs 11 Ham).
```

While nominal recall appears near 99%, this is driven by severe model bias: the absence of familiar HTML tokens causes the model's logistic decision score to collapse to its intercept, producing estimated phishing probabilities $> 0.50$ for almost all short texts (e.g., V2 baseline probability on empty/short text is $\approx 0.613$).

---

## 1. Primary Benchmark: Smishing vs. Benign Ham

The primary benchmark tests the model's ability to differentiate confirmed malicious smishing lures (Cohort A, $N=100$) from legitimate conversational SMS messages (Cohort B, $N=100$).

### 1.1 Detailed Metric Breakdown

| Metric | V2 Baseline | V3 Dual-Channel | V3 Content-Only | V3 URL-Only (URL Subset)* |
| :--- | :--- | :--- | :--- | :--- |
| **Total Evaluated** | 200 | 200 | 200 | 111 (100 Pos, 11 Neg) |
| **True Positives (TP)** | 99 | 99 | 98 | 99 |
| **False Positives (FP)** | 96 | 98 | 84 | 10 |
| **True Negatives (TN)** | 4 | 2 | 16 | 1 |
| **False Negatives (FN)** | 1 | 1 | 2 | 1 |
| **Recall (Sensitivity)** | **0.9900** | **0.9900** | **0.9800** | **0.9900** |
| **Specificity** | **0.0400** | **0.0200** | **0.1600** | **0.0909** |
| **Precision** | 0.5077 | 0.5025 | 0.5385 | 0.9083 |
| **F1 Score** | 0.6712 | 0.6667 | 0.6950 | 0.9474 |
| **Balanced Accuracy** | 0.5150 | 0.5050 | 0.5700 | 0.5405 |
| **ROC-AUC** | 0.7856 | 0.7703 | 0.6562 | 0.6864 |
| **Average Precision** | 0.8022 | 0.8071 | 0.6474 | 0.9459 |

*Note on V3 URL-Only:* Because 89 of the 100 legitimate ham messages contain no URLs, V3 URL-Only was only evaluated on the 111 samples where candidate URLs were extractable. Out of the 11 URL-bearing legitimate SMS, 10 were falsely flagged as phishing.

---

## 2. All-Cohorts Benchmark & Commercial Spam Audit

In real-world SMS feeds, security systems encounter both benign personal messages and high-volume commercial marketing spam (which is annoying but non-credential-harvesting).

### 2.1 Commercial Spam False Positive Rate (Cohort C, $N=50$)

| Model | N Evaluated | False Positives (Flagged as Phishing) | Commercial Spam FP Rate |
| :--- | :--- | :--- | :--- |
| **V2 Baseline** | 50 | 49 | **98.00%** |
| **V3 Dual-Channel** | 50 | 48 | **96.00%** |
| **V3 Content-Only** | 50 | 45 | **90.00%** |
| **V3 URL-Only** | 18 (URL Subset) | 16 | **88.89%** |

### 2.2 Smishing vs. Non-Smishing (Ham + Spam, $N=250$)

When evaluated against all negative samples (100 Ham + 50 Spam = 150 Negatives):

| Model | Evaluated | TP | FP | TN | FN | Recall | Specificity | Precision | F1 | Balanced Acc |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **V2 Baseline** | 250 | 99 | 145 | 5 | 1 | 0.9900 | **0.0333** | 0.4057 | 0.5756 | 0.5117 |
| **V3 Dual-Channel** | 250 | 99 | 146 | 4 | 1 | 0.9900 | **0.0267** | 0.4041 | 0.5739 | 0.5083 |
| **V3 Content-Only** | 250 | 98 | 129 | 21 | 2 | 0.9800 | **0.1400** | 0.4317 | 0.5994 | 0.5600 |
| **V3 URL-Only** | 129 | 99 | 26 | 3 | 1 | 0.9900 | **0.1034** | 0.7920 | 0.8800 | 0.5467 |

---

## 3. Subgroup Analyses

### 3.1 URL-Bearing vs. URL-Absent Subgroups
- **Cohort A (Smishing):** 100% of samples bear URLs due to deterministic campaign mapping.
- **Cohort B (Ham):** 11% bear URLs; 89% are URL-absent.
- **Cohort C (Spam):** 36% bear URLs; 64% are URL-absent.

On the URL-absent subset (Cohort B and C, $N=121$), models rely purely on token content:
- V2 flagged 117 of 121 (FP rate 96.7%).
- V3 Dual flagged 118 of 121 (FP rate 97.5%).
- V3 Content flagged 105 of 121 (FP rate 86.8%).

### 3.2 Short vs. Long Messages
Splitting at the pilot median length (129 characters):
- **Short Messages (<129 chars, $N=125$):**
  - V2 Specificity on Ham: **0.0323**
  - V3 Dual Specificity on Ham: **0.0161**
- **Long Messages ($\ge 129$ chars, $N=125$):**
  - V2 Specificity on Ham: **0.0526**
  - V3 Dual Specificity on Ham: **0.0263**

In both length regimes, specificity remains below 6%, demonstrating that token sparsity across the entire SMS length distribution triggers the positive intercept pathology.

---

## 4. Key Error Case Studies

### 4.1 False Negatives (Missed Smishing)
- **Serial 32 (`ucezef.com/GJuWoYQ`):**
  - Missed by V2 Baseline ($P = 0.4012$). Bare URL without text; word-level TF-IDF found zero recognized vocabulary. Correctly detected by V3 Dual ($P = 0.8038$) and V3 URL-Only ($P = 0.7850$) via character n-grams.
- **Serial 15 (`Postal reminder: Please handle the wrong address...`):**
  - Missed by V3 Dual ($P = 0.4766$). Slashed/truncated URL failed candidate extraction; URL channel score was null, depressing the joint prediction below 0.50.
- **Serial 44 & 45 (`MOJO order delivered...`, `PayPal: Your account has been flagged...`):**
  - Missed by V3 Content-Only ($P = 0.4556$ and $P = 0.4359$). Content extractor stripped the URL, leaving behind phrases that lacked sufficient weight on web-trained content features.

### 4.2 False Positives (Harmless Ham Flagged as Smishing)
- **Serial 101 (`Dai  <#>  naal eruku.`):** V2 $P = 0.6983$, V3 Dual $P = 0.8012$.
- **Serial 110 (`Thanks a lot for your wishes on my birthday...`):** V2 $P = 0.7334$, V3 Dual $P = 0.7185$.
- **Serial 201 (`Sexy Singles are waiting for you!...`):** V2 $P = 0.6225$, V3 Dual $P = 0.7328$.

---

## 5. Architectural Conclusions & Next Steps

1. **Definitive Finding:** Our existing frozen models (trained on HTML web pages and long-form email text) cannot be applied to SMS or plain-text messages. Doing so produces a ~98% false-alarm rate on benign messages.
2. **FastAPI Guardrail:** The backend API must explicitly reject plain-text SMS input or route it through a modality gate rather than exposing the HTML/dual-channel endpoints directly to SMS traffic.
3. **Modality Specialization:** Evaluating independent datasets confirms the necessity of developing dedicated smishing and short-text classifiers trained on actual mobile message distributions.
