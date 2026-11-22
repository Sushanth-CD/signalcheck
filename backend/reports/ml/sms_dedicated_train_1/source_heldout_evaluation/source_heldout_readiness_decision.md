# Source-Held-Out Evaluation Readiness Decision: GO

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation Investigation  
**Candidate Evaluation Corpus:** Mishra & Soni SMS Phishing Dataset (Mendeley Data 2022)  
**Target Model:** Frozen SMS-03 Combined Classifier ([`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib))  
**Target Digest:** `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`  
**Decision Date:** November 2026  

---

## 1. Formal Decision: GO

**Formal Decision: GO for a dedicated, source-held-out external evaluation of the frozen SMS-03 classifier on the screened Mishra & Soni cohort.**

The investigation has confirmed that:
1. The original 3-class ground-truth labels (**Ham**, **Commercial Spam**, **Smishing**) have been successfully recovered from primary source metadata without reliance on the collapsed binary labels of `combined_reduced.json`.
2. A rigorous cryptographic and near-duplicate independence screening was conducted against all SMS-03 partitions (Train, Validation, Internal Test) and the 250-record diagnostic pilot.
3. All leaking, near-duplicate, and ambiguous records have been identified, quantified, and completely purged from the eligible evaluation cohort.
4. The remaining eligible cohort contains ample pristine records (**526 Smishing**, **435 Commercial Spam**, **3,713 Ham**), fully satisfying the target benchmark requirements (200 Smishing, 100 Commercial Spam, 200 Ham).
5. The cryptographic SHA-256 integrity of the frozen model [`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib) has remained strictly unaltered throughout the entire audit.

---

## 2. Gate Verification Summary

| Gate Requirement | Status | Audit Findings |
| :--- | :---: | :--- |
| **1. Primary Label Recovery** | **PASSED** | Recovered raw 5,971 records: 4,844 Ham, 638 Smishing, 489 Spam. Casing inconsistencies normalized. |
| **2. Cryptographic Independence** | **PASSED** | 1,119 exact SHA-256 collisions against SMS-03 training/validation/test partitions and the pilot were identified and excluded. |
| **3. Near-Duplicate Independence** | **PASSED** | SimHash $\le 3$ with Character 5-gram Jaccard $\ge 0.90$ identified and excluded an additional 13 near-duplicate records. |
| **4. Internal Ambiguity Purge** | **PASSED** | 31 normalized text hashes carrying conflicting raw annotations (`spam` vs `smishing`) were permanently quarantined. |
| **5. Cohort Sufficiency** | **PASSED** | 4,674 eligible unique records remain. Smishing count (526) exceeds the 200-sample target by $+163\%$. |
| **6. Model Integrity Preservation** | **PASSED** | Pre-investigation SHA-256: `8dd043a3b832...` <br> Post-investigation SHA-256: `8dd043a3b832...` (Byte-for-byte identical). |
| **7. Zero Inference Execution** | **PASSED** | No model scoring, inference, threshold tuning, or weight modification was performed. |

---

## 3. Key Research Insights & Evaluation Expectations

### 3.1 Addressing the Link-Bearing Bias
In SMS-DEDICATED-TRAIN-1, 100% of the positive training instances originated from WSPR-NCSU and contained extractable web URLs. In contrast, **only 22.05% of Mishra & Soni smishing messages contain extractable URLs** (116 with URLs, 410 without URLs).

Evaluating SMS-03 on this benchmark will directly test:
- How effectively character sub-word n-grams (3–5) and word n-grams (1–2) detect phone callback lures, banking fraud keywords, urgency triggers, and brand impersonation without relying on embedded web links.

### 3.2 Resolving Nuisance Commercial Spam Separation
In the internal test, commercial spam was predominantly represented by ExAIS. Mishra & Soni provides 435 clean commercial spam messages collected from European and Indian carriers. This benchmark will provide the first cross-source confirmation that SMS-03 maintains a low false positive rate on aggressive marketing copy.

---

## 4. Operational Next Steps (Upon User Authorization)

1. **Benchmark Extraction:** Draw the fixed 500-message stratified benchmark (200 Smishing, 200 Ham, 100 Commercial Spam) from [`eligible_source_cohort.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/eligible_source_cohort.csv) using random seed `20261102`.
2. **Frozen Model Execution:** Score the 500 benchmark messages through the frozen [`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib) strictly at operating threshold `0.50`.
3. **Disaggregated Metric Computation:** Generate full classification matrices disaggregated by link presence, message length, and telephone callback lures.
4. **Deliver Report:** Produce `source_heldout_evaluation_report.md` documenting the model's cross-source generalization capabilities.
