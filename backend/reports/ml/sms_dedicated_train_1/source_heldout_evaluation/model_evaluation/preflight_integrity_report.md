# Preflight Integrity Report: Mishra & Soni Source-Held-Out Benchmark

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation  
**Benchmark Target:** 500-Record Source-Held-Out Benchmark  
**Evaluation Target:** Frozen SMS-03 Combined Classifier (`sms_model.joblib`)  
**Audit Date:** November 2026  
**Status:** Preflight Checks Complete & 100% Passed  

---

## 1. Benchmark Composition & Sampling Audit

The benchmark cohort was deterministically extracted from [`eligible_source_cohort.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/eligible_source_cohort.csv) using random seed `20261102` with sequential near-duplicate pruning.

### Category Distribution
| Category | Target Count | Actual Selected Count | Selection Status | Ground Truth Binary Label |
| :--- | :---: | :---: | :---: | :---: |
| **Smishing** | 200 | **200** | **MATCH** | `1` (Positive) |
| **Ham (Benign Control)** | 200 | **200** | **MATCH** | `0` (Negative) |
| **Commercial Spam Control** | 100 | **100** | **MATCH** | `0` (Negative) |
| **Total Benchmark** | **500** | **500** | **MATCH** | — |

---

## 2. Modality & Length Distribution Audit

### 2.1 URL-Present vs. URL-Absent Distribution
The sampling adhered strictly to the empirical prevalence in the parent Mishra & Soni release:

| Category | Target URL-Bearing | Selected URL-Bearing | Target Linkless | Selected Linkless | Total |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Smishing** | 44 | **44 (22.0%)** | 156 | **156 (78.0%)** | **200** |
| **Commercial Spam** | 27 | **27 (27.0%)** | 73 | **73 (73.0%)** | **100** |
| **Benign Ham** | — | **5 (2.5%)** | — | **195 (97.5%)** | **200** |
| **Total Benchmark** | — | **76 (15.2%)** | — | **424 (84.8%)** | **500** |

### 2.2 Benign Ham Message-Length Tiers
Ham sampling was stratified across length tiers matching the eligible pool:
- **Short ($\le 70$ chars):** **127 records** ($63.5\%$)
- **Medium (71–140 chars):** **53 records** ($26.5\%$)
- **Long ($> 140$ chars):** **20 records** ($10.0\%$)
- **Total Ham:** **200 records** ($100.0\%$)

---

## 3. Cryptographic and Near-Duplicate Independence Verification

The selected 500 records underwent exhaustive isolation screening:

```
+---------------------------------------------------------------------------------------------------+
| PREFLIGHT ISOLATION AUDIT MATRIX (N = 500)                                                        |
+---------------------------------------------------------------------------------------------------+
|  Check 1: Unique Source Row IDs                                     | 500 / 500 (100% Unique)     |
|  Check 2: Unique Normalized Text SHA-256 Hashes                     | 500 / 500 (100% Unique)     |
|  Check 3: Internal Confirmed Near-Duplicates (SimHash<=3 & Jac>=0.90)| 0 pairs (Zero collision)    |
|  Check 4: Exact SHA-256 Collisions against SMS-03 Splits (N=5,400)   | 0 records (Zero leakage)    |
|  Check 5: Near-Duplicate Collisions against SMS-03 Splits (N=5,400) | 0 records (Zero leakage)    |
|  Check 6: Exact SHA-256 Collisions against Diagnostic Pilot (N=250) | 0 records (Zero leakage)    |
|  Check 7: Near-Duplicate Collisions against Diagnostic Pilot (N=250)| 0 records (Zero leakage)    |
|  Check 8: Untouched Status (Never used in training/tuning)          | CONFIRMED                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 4. Preflight Decision

All 8 preflight gate checks passed. The 500-message benchmark ([`benchmark_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/benchmark_manifest.csv)) represents an untouched, leak-free, source-held-out evaluation cohort.
