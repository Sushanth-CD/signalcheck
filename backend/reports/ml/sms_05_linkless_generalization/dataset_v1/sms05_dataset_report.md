# SMS-05 Dataset Preparation & Partitioning Report

**Milestone:** SMS-05 — Multi-Source, Linkless-Aware SMS Classifier  
**Dataset Version:** `dataset_v1`  
**Candidate Manifest:** [`sms05_candidate_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_candidate_manifest.csv) ($N = 8,735$)  
**Split Manifest:** [`sms05_split_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_split_manifest.csv)  
**Date:** November 2026  
**Status:** Dataset Assembly, Grouping, Partitioning, and Integrity Checks Complete  

---

## 1. Executive Summary & Design Achievements

The **SMS-05 Development Dataset** resolves the fatal limitations diagnosed during the SMS-03 source-held-out evaluation:
1. **Balanced 50/50 URL Modality in Positive Smishing:** Exactly **1,700 URL-bearing smishing messages** and **1,700 linkless smishing messages** ($N = 3,400$ total positives).
2. **Multi-Source Positive Diversity:** The positive class is no longer dominated by WSPR-NCSU. It integrates **WSPR-NCSU** ($N = 1,400$), **ACM IMC 2025** ($N = 1,674$), and **Mishra & Soni Remaining** ($N = 326$).
3. **Multi-Source Negative Control Robustness:** The negative class ($N = 5,335$) balances **ExAIS Ham & Spam** ($N = 2,718$), **UCI Ham & Spam** ($N = 1,282$), and **Mishra & Soni Remaining Ham & Spam** ($N = 1,335$).
4. **Permanent Quarantine of Diagnostic Benchmarks:** Zero overlap with the 250-record pilot, the 500-record held-out benchmark, or any of the 100 pilot campaigns.
5. **Zero Cross-Partition Leakage:** Exactly **0** group or text collisions across Train, Validation, and Test partitions.

```
+---------------------------------------------------------------------------------------------------+
| SMS-05 CANDIDATE DATASET AT A GLANCE (N = 8,735)                                                  |
+---------------------------------------------------------------------------------------------------+
|  * Positive Smishing Class: 3,400 records (38.92%)                                                |
|    - URL-Bearing Smishing: Exactly 1,700 records (50.0% of positives)                             |
|    - Linkless Smishing: Exactly 1,700 records (50.0% of positives)                                 |
|                                                                                                   |
|  * Negative Classes: 5,335 records (61.08%)                                                       |
|    - Benign Personal Ham: 3,500 records (40.07% of dataset)                                       |
|    - Commercial Marketing Spam: 1,835 records (21.01% of dataset)                                 |
|                                                                                                   |
|  * Partition Distribution (Exact 70 / 15 / 15 Stratification):                                    |
|    - Training (70.10%): 6,123 records (2,380 Smishing | 2,450 Ham | 1,293 Spam)                    |
|    - Validation (14.94%): 1,305 records (510 Smishing | 524 Ham | 271 Spam)                       |
|    - Internal Test (14.96%): 1,307 records (510 Smishing | 526 Ham | 271 Spam)                    |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Granular Source and Category Distribution

From [`source_category_modality_distribution.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/source_category_modality_distribution.csv):

| Source Repository | Ground Truth Category | Binary Label | URL-Bearing (N) | Linkless (N) | Total Records | % of Dataset |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **WSPR-NCSU** | Smishing (Gateway Verified) | 1 | 1,400 | 0 | 1,400 | 16.03% |
| **Mishra & Soni 2022** | Smishing (Callback / Shortcodes)| 1 | 72 | 254 | 326 | 3.73% |
| **IMC 2025 (`reportsmishing`)**| Smishing (WhatsApp / Lures) | 1 | 228 | 1,446 | 1,674 | 19.16% |
| **ExAIS Mobile Users (1–20)** | Benign Personal Ham | 0 | 0 | 1,250 | 1,250 | 14.31% |
| **ExAIS Mobile Users (1–20)** | Commercial Marketing Spam | 0 | 0 | 1,468 | 1,468 | 16.81% |
| **UCI SMS Spam Collection** | Benign Personal Ham | 0 | 0 | 1,250 | 1,250 | 14.31% |
| **UCI SMS Spam Collection** | Commercial Marketing Spam | 0 | 0 | 32 | 32 | 0.37% |
| **Mishra & Soni 2022** | Benign Transactional Ham | 0 | 34 | 966 | 1,000 | 11.45% |
| **Mishra & Soni 2022** | Commercial Marketing Spam | 0 | 87 | 248 | 335 | 3.84% |
| **TOTAL CANDIDATES** | — | — | **1,821 (20.8%)** | **6,914 (79.2%)** | **8,735** | **100.00%** |

---

## 3. Partitioning Quality & Stratification Matrix

The 8,735 records were grouped into **8,145 connected components** (merging exact text hashes, WSPR campaigns, and SimHash near-duplicate clusters) and stratified across partitions without splitting any group.

Detailed in [`sms05_split_summary.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_split_summary.json):

```
+---------------------------------------------------------------------------------------------------+
| PARTITION BALANCE ACROSS EVALUATION DIMENSIONS                                                    |
+---------------------------------------------------------------------------------------------------+
| Dimension                    | Training (70%)        | Validation (15%)      | Internal Test (15%)  |
+------------------------------+-----------------------+-----------------------+----------------------+
| Total Instances              | 6,123 (70.10%)        | 1,305 (14.94%)        | 1,307 (14.96%)       |
| Positive Smishing (Total)    | 2,380 (70.00%)        | 510 (15.00%)          | 510 (15.00%)         |
|   — URL-Bearing Smishing     | 1,190 (70.00%)        | 255 (15.00%)          | 255 (15.00%)         |
|   — Linkless Smishing        | 1,190 (70.00%)        | 255 (15.00%)          | 255 (15.00%)         |
| Benign Personal Ham          | 2,450 (70.00%)        | 524 (14.97%)          | 526 (15.03%)         |
| Commercial Marketing Spam    | 1,293 (70.46%)        | 271 (14.77%)          | 271 (14.77%)         |
| Unique Group Components      | 5,701 groups          | 1,222 groups          | 1,222 groups         |
| Group Cross-Leakage          | 0 groups leaked       | 0 groups leaked       | 0 groups leaked      |
| Text Hash Cross-Leakage      | 0 hashes leaked       | 0 hashes leaked       | 0 hashes leaked      |
+---------------------------------------------------------------------------------------------------+
```

---

## 4. Evidentiary Independence & Exclusion Ledger

From [`sms05_exclusion_summary.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_exclusion_summary.csv) and [`sms05_independence_screening.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_independence_screening.json):

Every external and internal leakage risk was systematically neutralized:
1. **Permanent Diagnostic Pilot Quarantine:** All 250 pilot records and their 100 WSPR campaigns are completely excluded from the candidate pool.
2. **Permanent Source-Held-Out Benchmark Quarantine:** All 500 records from the Mishra & Soni held-out evaluation are completely excluded.
3. **IMC Near-Match Template Purge:** 3 rows matching the benchmark template (*"Dear Customer your pyatm wallet..."*, Jaccard $= 0.9018$) were permanently quarantined.
4. **IMC Uncurated Spam Quarantine:** All 1,173 rows labeled as `spam` in IMC were excluded from positive smishing candidates due to ambiguity between commercial advertising and fraud.
5. **OCR Degradation Exclusions:** 85 short/placeholder rows and 221 screenshot OCR stubs were purged.

---

## 5. ExAIS Participant Overlap Notice

As required by governance guidelines:
- **Participant Distribution:** ExAIS records are contributed by 20 distinct users.
- **Cross-Partition Overlap:** 19 of the 20 users appear in both Training and Validation; all 20 appear in both Training and Test.
- **Operational Meaning:** While zero exact messages or SimHash templates leak between partitions, the ExAIS cohort measures **template-, message-, and campaign-level generalization**, but **NOT** unseen-user holdout generalization. This boundary must accompany all model reporting.

---

## 6. Deliverables Reference

All manifests and audit files are verified on disk in [`backend/reports/ml/sms_05_linkless_generalization/dataset_v1/`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1):
- Candidate Manifest ($N = 8,735$): [`sms05_candidate_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_candidate_manifest.csv)
- Partition Split Manifest ($N = 8,735$): [`sms05_split_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_split_manifest.csv)
- Group Assignments ($8,145$ groups): [`sms05_group_assignments.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_group_assignments.csv)
- Exclusion Summary: [`sms05_exclusion_summary.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_exclusion_summary.csv)
- Partition Distribution Matrix: [`source_category_modality_distribution.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/source_category_modality_distribution.csv)
- Partition Summary (JSON): [`sms05_split_summary.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_split_summary.json)
- Independence Screening (JSON): [`sms05_independence_screening.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_independence_screening.json)
