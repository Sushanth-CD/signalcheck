# Training Readiness Decision: GO for SMS-05 Model Training

**Milestone:** SMS-05 — Multi-Source, Linkless-Aware SMS Classifier  
**Dataset Target:** `sms05_split_manifest.csv` ($N = 8,735$)  
**Target Architectures:** SMS-05-A, SMS-05-B, SMS-05-C, SMS-05-D  
**Decision Date:** November 2026  
**Status:** Training Authorization Approved  

---

## 1. Formal Authorization: GO

**Formal Decision: GO for model training and architectural exploration using the newly prepared `dataset_v1` partition manifest.**

This decision is substantiated by complete verification of all training prerequisites:
1. **Reconciliation Complete:** All accounting ambiguities from earlier reports are resolved. Over 98.58% of English IMC records are confirmed genuine SMS text.
2. **Balanced Linkless Smishing Integrated:** Positive training data contains an exact **50/50 balance** of URL-bearing ($N = 1,190$) and linkless smishing ($N = 1,190$), guaranteeing that SMS-05 will be directly exposed to telephone callback scams, WhatsApp redirects, and family impersonation text.
3. **Multi-Source Negative Controls Protected:** 3,500 ham messages and 1,835 commercial spam messages from three independent repositories (ExAIS, UCI, Mishra & Soni) are integrated, preventing single-source overfitting.
4. **Leakage & Independence Screening Passed:** Zero collisions against diagnostic holdouts (the 250-message pilot and 500-message benchmark). Zero cross-partition leakage across the 8,145 group components.
5. **Frozen Baseline Preserved:** SMS-03 SHA-256 (`8dd043a3b832...`) remains byte-for-byte intact.

---

## 2. Gate Verification Checklist

| Gate Check Requirement | Status | Audit Findings |
| :--- | :---: | :--- |
| **1. Diagnostic Holdout Isolation** | **PASSED** | 250 pilot + 100 WSPR pilot campaigns + 500 Mishra benchmark completely quarantined. |
| **2. Multi-Source Positive Sourcing** | **PASSED** | Smishing sourced across WSPR-NCSU ($1,400$), IMC 2025 ($1,674$), and Mishra ($326$). |
| **3. Balanced URL Modality** | **PASSED** | Exactly 1,700 URL-bearing and 1,700 linkless smishing records (1,190/1,190 in Train). |
| **4. Negative Control Robustness** | **PASSED** | ExAIS ($2,718$), UCI ($1,282$), and Mishra ($1,335$) prevent source confounding. |
| **5. Group Component Protection** | **PASSED** | 8,145 connected components assigned without a single cross-partition split. |
| **6. ExAIS Overlap Documented** | **PASSED** | 20 users shared across splits; template-level generalization explicitly declared. |
| **7. Input Metadata Isolation** | **PASSED** | Feature pipelines restricted strictly to `sanitized_message_text`. |

---

## 3. Authorized Next Steps: Model Experimentation

With dataset preparation concluded, authorization is granted to execute the four planned model experiments defined in `sms_05_model_experiment_plan.md`:

1. **SMS-05-A:** Word TF-IDF (1–2 n-grams) + L2 Logistic Regression.
2. **SMS-05-B:** Character TF-IDF (3–5 char_wb n-grams) + L2 Logistic Regression.
3. **SMS-05-C:** Combined Word + Character FeatureUnion + L2 Logistic Regression.
4. **SMS-05-D:** Structured Two-Channel Model (Content FeatureUnion + Explicit Structural Metadata Channels).

All models will be fitted on the **Training partition ($N = 6,123$)** and evaluated against the **Validation partition ($N = 1,305$)** at the frozen operating threshold of **0.50**.
