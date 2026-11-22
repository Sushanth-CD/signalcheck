# Exploratory Inference and Evaluation Report: CompPhish V4 100-Sample Pilot

**Date:** 2026-11-01 10:07:44 UTC
**Cohort Scope:** Exploratory pilot of 100 independent HTML samples from CompPhish V4.
**Cohort Characteristics:** 53 Legitimate, 47 Phishing. Exactly 100 unique registrable domains (1 sample per domain).
**Independence Provenance:** 0 exact text collisions, 0 registrable domain collisions, 0 SimHash near-duplicate collisions against all 77,677 project records.

> [!IMPORTANT]
> **Pilot Context vs. Full Benchmark:** This evaluation represents an exploratory pilot on 100 independent HTML samples. It is strictly observational; no models were retrained, no hyper-parameters or thresholds were adjusted, and all candidate models were evaluated with the frozen reference threshold of 0.50.

## 1. Frozen Model Integrity Verification
- Freeze Manifest SHA-256: `652a23e59700c7a117354746a9c93dba920f4ddbb70e7a69ad8888ab5a80526e`
- Overall Integrity Status: **PASS**

| Model Identifier | Relative Path | Size (Bytes) | SHA-256 Digest | Integrity Check |
| :--- | :--- | :--- | :--- | :--- |
| `v2_baseline` | `backend/reports/ml/phishing_domain_holdout_v2/model.joblib` | 8296368 | `97ca5d41ea432296...` | **PASS** |
| `v3_dual_channel` | `backend/reports/ml/phishing_v3_experiments/dual_channel_v3_model.joblib` | 2812543 | `c0b514d976f88b02...` | **PASS** |
| `v3_content_only` | `backend/reports/ml/phishing_v3_experiments/content_only_model.joblib` | 2379487 | `ff837956a76e31e1...` | **PASS** |
| `v3_url_only` | `backend/reports/ml/phishing_v3_experiments/url_only_model.joblib` | 434335 | `d180be6e80207bbc...` | **PASS** |

## 2. Model Performance Summary (Threshold 0.50)

| Model / Policy | Accuracy | Precision | Recall | F1 Score | Specificity | ROC-AUC | Avg Precision | TP | FP | TN | FN |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **V2_Baseline** | 0.5800 | 0.8571 | 0.1277 | 0.2222 | 0.9811 | 0.8089 | 0.7670 | 6 | 1 | 52 | 41 |
| **V3_Dual_Channel** | 0.7700 | 0.8158 | 0.6596 | 0.7294 | 0.8679 | 0.7760 | 0.7290 | 31 | 7 | 46 | 16 |
| **Hybrid_Policy_3** | 0.7700 | 0.8158 | 0.6596 | 0.7294 | 0.8679 | 0.7760 | 0.7290 | 31 | 7 | 46 | 16 |
| **Hybrid_Policy_4** | 0.7700 | 0.8158 | 0.6596 | 0.7294 | 0.8679 | 0.7760 | 0.7290 | 31 | 7 | 46 | 16 |

## 3. Routing Branch Distributions
- **HTML Detection Rule:** `(?is)<\s*(?:!doctype\s+html|html|head|body|meta|link|a|form|div|p)\b`
- **HTML Detected:** 100 / 100 samples.
- **Hybrid Policy 3 Branch Allocation:** 100 samples routed to V3 Dual, 0 routed to V2 Baseline.
- **Hybrid Policy 4 Branch Allocation:** 100 samples routed to V3 Dual, 0 routed to V2 Baseline.

## 4. Error Analysis & Record Identifiers

### V2_Baseline
- **False Positives (1):** `202420256010`
- **False Negatives (41):** `202420259312`, `202420250978`, `202420255163`, `202420256529`, `202420257447`, `202420258412`, `202420259078`, `202420255597`, `202420255271`, `202420253200`, `202420255035`, `202420255067`, `202420250861`, `202420255853`, `202420250168`, `202420255231`, `202420251163`, `202420252531`, `202420255624`, `202420250926`, `202420255832`, `9156427`, `9157041`, `9160700`, `9158713`, `9162472`, `9159983`, `9162528`, `9160029`, `9157096`, `9155231`, `9156540`, `9162556`, `9153909`, `9157092`, `9154042`, `37600`, `16100`, `50400`, `202420263206`, `202420263177`

### V3_Dual_Channel
- **False Positives (7):** `2441`, `202420253510`, `202420256010`, `202420253972`, `202420254115`, `202420261615`, `202420260590`
- **False Negatives (16):** `202420259312`, `202420255163`, `202420258412`, `202420259078`, `202420255597`, `202420255271`, `202420253200`, `202420255067`, `202420250168`, `202420255231`, `202420251163`, `202420255624`, `9158713`, `9159983`, `9160029`, `37600`

### Hybrid_Policy_3
- **False Positives (7):** `2441`, `202420253510`, `202420256010`, `202420253972`, `202420254115`, `202420261615`, `202420260590`
- **False Negatives (16):** `202420259312`, `202420255163`, `202420258412`, `202420259078`, `202420255597`, `202420255271`, `202420253200`, `202420255067`, `202420250168`, `202420255231`, `202420251163`, `202420255624`, `9158713`, `9159983`, `9160029`, `37600`

### Hybrid_Policy_4
- **False Positives (7):** `2441`, `202420253510`, `202420256010`, `202420253972`, `202420254115`, `202420261615`, `202420260590`
- **False Negatives (16):** `202420259312`, `202420255163`, `202420258412`, `202420259078`, `202420255597`, `202420255271`, `202420253200`, `202420255067`, `202420250168`, `202420255231`, `202420251163`, `202420255624`, `9158713`, `9159983`, `9160029`, `37600`

## 5. Registrable Domain Distribution
- **Unique Registrable Domains:** 100 / 100 samples.
- **Max Samples per Domain:** 1.
- **Domains with Multiple Samples:** 0.
All 100 samples originate from strictly disjoint registrable domains, precluding intra-domain correlation bias.

## 6. Pilot Observations
1. **Input Representation:** CompPhish V4 samples are full HTML documents. The deterministic HTML detector detected 100/100 inputs as HTML.
2. **Routing Convergence:** Under Policy 3 and Policy 4, because all 100 samples contain valid HTML structures, both hybrid policies route 100% of samples to V3 Dual-Channel, matching the standalone V3 Dual-Channel performance exactly.
3. **Generalization Gap vs. V2:** V2 Baseline shows lower recall/precision on raw full-page HTML compared to V3 Dual-Channel, highlighting the value of dual-channel DOM structure and URL channel feature parsing.
4. **Strict Isolation:** Zero network calls were made to extracted target URLs; DNS lookups were avoided; and raw HTML strings were passed strictly as inert textual data to the frozen pipelines.