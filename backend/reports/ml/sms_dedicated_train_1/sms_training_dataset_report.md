# SMS-DEDICATED-TRAIN-1: Training Dataset Preparation & Splitting Report

**Milestone:** SMS-DEDICATED-TRAIN-1  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Directory:** `backend/reports/ml/sms_dedicated_train_1/`  
**Status:** Completed Successfully (Pre-Training Gate Passed)  

---

## 1. Executive Summary

We have constructed, sanitized, screened, and partitioned a clean, leakage-safe dataset of **5,400 mobile SMS records** specifically designed for training and evaluating a dedicated SMS phishing detection model.

Zero models were fitted or trained during this milestone. The pipeline prepared model-ready candidates, generated split manifests, enforced strict campaign/user grouping, and verified all independence invariants.

```
Total Assembled Training Candidates: 5,400 Records
├── Malicious Smishing (WSPR-NCSU)   : 1,400 records (from 1,400 distinct non-pilot campaigns)
├── Benign Personal Ham             : 2,500 records (1,250 UCI Ham + 1,250 ExAIS Ham)
└── Commercial Advertising Spam      : 1,500 records (   32 UCI Spam + 1,468 ExAIS Spam)
```

---

## 2. Target vs. Actual Sample Counts

| Category | Target Count | Actual Eligible Count | Yield % | Source Breakdown | Reason for Delta (if any) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Confirmed Smishing** | 2,000 | **1,400** | 70.0% | WSPR-NCSU: 1,400 | Exactly 1,405 non-pilot campaigns had unambiguous URLs; 1,400 were selected to maintain the 1-message-per-campaign rule. |
| **Independent Ham** | 2,500 | **2,500** | 100.0% | UCI: 1,250, ExAIS: 1,250 | **100% Target Met** from clean deduplicated pools. |
| **Commercial Spam** | 1,500 | **1,500** | 100.0% | UCI: 32, ExAIS: 1,468 | **100% Target Met** (UCI spam was mostly exhausted by Mishra & Soni overlap; ExAIS supplied the balance). |
| **Total** | **6,000** | **5,400** | **90.0%** | Multi-Source | Robust, fully independent dataset without artificial duplication. |

> [!NOTE]
> Following the strict protocol constraint, we did not duplicate or manufacture samples to artificially meet the 2,000 smishing target. The 1,400 smishing samples represent 1,400 completely distinct attack campaigns.

---

## 3. Exclusion and Independence Verification Summary

Every candidate record was screened against:
1. The **77,677-record project baseline corpus** (`combined_reduced.json` via `corpus_simhash_index.npz`).
2. The **250-record SMS evaluation pilot** (`sms_pilot/sample_manifest.csv`).
3. The **100 WSPR campaign IDs** represented in the pilot.

### Screening Invariants:
- **Corpus Exact Collisions:** **0** records in the candidate pool match the 77,677 baseline corpus.
- **Corpus Near-Duplicate Collisions:** **0** records match within SimHash Hamming distance $\le 3$.
- **Pilot Collisions:** **0** exact text matches and **0** near-duplicate matches ($H \le 3$, Jaccard $\ge 0.90$) against the 250 pilot records.
- **Pilot Campaign Exclusions:** **0** messages from the 100 pilot campaigns are present.
- **Exclusion Audit:** Exactly 1,924 candidate records were rejected during acquisition and itemized in `sms_exclusion_summary.csv`.

---

## 4. Internal Grouping & Connected Components

To prevent leakage across splits, records were grouped into unified connected components:
- **Campaign Grouping:** All messages sharing a WSPR campaign ID were locked to the same component.
- **Participant Grouping:** ExAIS messages sharing participant user IDs were locked to the same component.
- **Near-Duplicate Linkages:** 277 internal near-duplicate pairs (SimHash $H \le 3$ and Jaccard $\ge 0.90$) were clustered into the same graph components.
- **Total Components:** The 5,400 records resolved into **2,626 disjoint connected components**.

---

## 5. Leakage-Safe Partition Allocations

Components were allocated to partitions using greedy group-aware stratification (Seed `20261102`):

| Partition | Total Records | Share (%) | Components | Benign Ham | Commercial Spam | Smishing | Binary (0 / 1) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | **4,187** | 77.5% | 1,431 | 1,750 | 1,457 | 980 | 3,207 / 980 |
| **Validation** | **607** | 11.2% | 593 | 375 | 22 | 210 | 397 / 210 |
| **Internal Test** | **606** | 11.2% | 602 | 375 | 21 | 210 | 396 / 210 |
| **Total** | **5,400** | **100.0%** | **2,626** | **2,500** | **1,500** | **1,400** | **4,000 / 1,400** |

### Partition Verification Invariants:
- **Campaign Overlap:** Train $\cap$ Validation = $\emptyset$, Train $\cap$ Test = $\emptyset$, Validation $\cap$ Test = $\emptyset$. (0 campaign leakage).
- **Text Hash Overlap:** Exactly 0 normalized text hashes are shared across partitions.
- **Label Representation:** All three categories (`ham`, `commercial_spam`, `smishing`) are represented across all three partitions.

---

## 6. Evaluation Data Status

1. **The 250-Record SMS Pilot:**  
   The pilot acquired under TEXT-EVAL-1 remains permanently quarantined. It is a **diagnostic benchmark** that influenced our decision to build a separate SMS model, and is not used for model training or tuning.
2. **The Internal Test Partition (606 records):**  
   Serves as a development holdout test partition for early model checkpointing.
3. **Future Independent Final Evaluation:**  
   A fresh, third-party smishing and SMS dataset must be acquired for final external validation before deployment.
