# Final Training Gate Verification: Proposed V2 Partition Manifest

**Milestone:** SMS-DEDICATED-TRAIN-1 Final Training Gate Verification  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Inspected Manifest:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v2/sms_split_manifest.csv`  
**Audit Status:** Final Verification Completed  

---

## 1. ExAIS Participant Overlap Analysis

A key objective of this audit was to determine the exact participant representation across the proposed V2 partitions.

### Quantitative Participant Distribution:
- **Total ExAIS Records in Manifest:** 2,718 records (across 20 participants, `USER 1` to `USER 20`).
- **Unique Participants in Training:** **20 participants** (all 20 represented).
- **Unique Participants in Validation:** **19 participants** (`USER 1`–`4`, `6`–`19`, `20`; `USER 5` has 0 validation rows).
- **Unique Participants in Internal Test:** **20 participants** (all 20 represented).

### Participant Overlap Across Splits:
- **Train – Validation Participant Overlap:** **19 participants** (95.0%).
- **Train – Internal Test Participant Overlap:** **20 participants** (100.0%).
- **Validation – Internal Test Participant Overlap:** **19 participants** (95.0%).
- **Percentage of ExAIS Records from Multi-Partition Participants:** **100.00%** (2,718 / 2,718 records).

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| EXAIS PARTICIPANT INDEPENDENCE EVALUATION                                                         |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                   |
|  Participant Disaggregation Status:                                                               |
|  - The Proposed V2 split does NOT enforce strict participant-level holdout.                       |
|  - In Proposed V2, participant locking was relaxed because 17 of the 20 participant files shared   |
|    identical public telecom broadcast notices (creating a monolithic 2,621-record megacomponent).|
|  - While exact messages and near-duplicate templates are 100% quarantined across splits,          |
|    individual mobile users have distinct messages distributed across Train, Val, and Test.       |
|                                                                                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Source-Level Distribution: Partition × Source × Original Category

The proposed V2 split resolves the commercial spam starvation observed in V1, providing balanced, statistically significant sample sizes for all categories.

### Exact Cross-Tabulation Matrix:

| Partition | Source Dataset | Original Ground-Truth Category | Record Count | Share of Partition |
| :--- | :--- | :--- | :--- | :--- |
| **Train** | UCI | `ham` | 502 | 13.28% |
| **Train** | UCI | `commercial_spam` | 14 | 0.37% |
| **Train** | ExAIS | `ham` | 1,248 | 33.02% |
| **Train** | ExAIS | `commercial_spam` | 1,036 | 27.41% |
| **Train** | WSPR_NCSU | `smishing` | 980 | 25.93% |
| **Train Subtotal** | **All Sources** | **All Categories** | **3,780** | **100.00% (70.0% of Total)** |
| **Validation** | UCI | `ham` | 374 | 46.17% |
| **Validation** | UCI | `commercial_spam` | 9 | 1.11% |
| **Validation** | ExAIS | `ham` | 1 | 0.12% |
| **Validation** | ExAIS | `commercial_spam` | 216 | 26.67% |
| **Validation** | WSPR_NCSU | `smishing` | 210 | 25.93% |
| **Validation Subtotal**| **All Sources** | **All Categories** | **810** | **100.00% (15.0% of Total)** |
| **Internal Test** | UCI | `ham` | 374 | 46.17% |
| **Internal Test** | UCI | `commercial_spam` | 9 | 1.11% |
| **Internal Test** | ExAIS | `ham` | 1 | 0.12% |
| **Internal Test** | ExAIS | `commercial_spam` | 216 | 26.67% |
| **Internal Test** | WSPR_NCSU | `smishing` | 210 | 25.93% |
| **Test Subtotal** | **All Sources** | **All Categories** | **810** | **100.00% (15.0% of Total)** |
| **Grand Total** | **Multi-Source** | **Multi-Category** | **5,400** | **100.00%** |

### Evaluation Subgroup Adequacy:
- **Commercial Spam in Validation:** Increased from **22 records (V1) to 225 records (V2)** (216 ExAIS Spam + 9 UCI Spam). This sample size is statistically sufficient to reliably tune thresholds for a targeted commercial spam false-alarm rate.
- **Ham in Validation:** Balanced at **375 records** (374 UCI Ham + 1 ExAIS Ham).
- **Smishing in Validation:** Balanced at **210 records** from 210 distinct WSPR campaigns.
- *Source Asymmetry Note:* Because UCI spam was largely contaminated by Mishra & Soni (only 32 total clean records available), commercial spam in validation is predominantly driven by ExAIS ($96\%$). Conversely, because ExAIS ham was largely chained to training broadcast clusters, validation ham is predominantly driven by UCI ($99.7\%$).

---

## 3. Independent Near-Duplicate Leakage Verification

An exhaustive pairwise near-duplicate check was executed across all 5,400 manifest rows using the project's standard 64-bit character 5-gram SimHash implementation:
1. **Candidate Retrieval ($H \le 3$):** Exactly **1,116 pairwise candidate matches** were identified within the corpus.
2. **Confirmed Near-Duplicates ($H \le 3$ AND Jaccard $\ge 0.90$):** Exactly **1,114 pairs** were confirmed as near-duplicate templates.
3. **Cross-Partition Collisions:**
   - **Cross-Partition Candidates ($H \le 3$):** **0** candidate pairs cross partition boundaries.
   - **Cross-Partition Confirmed Near-Duplicates ($H \le 3$ & $J \ge 0.90$):** **0** confirmed pairs cross partition boundaries.
- **Finding:** Every single confirmed near-duplicate template is locked entirely within its respective partition. Zero template leakage exists across Train, Validation, and Test.

---

## 4. Verification of Other Structural Invariants

| Invariant Verification Gate | Expected Value | Observed Manifest Value | Verification Status |
| :--- | :--- | :--- | :--- |
| **Total Record Count** | Exactly 5,400 | 5,400 | **PASS** |
| **Partition Allocation** | 3,780 Train / 810 Val / 810 Test | 3,780 Train (70.0%) / 810 Val (15.0%) / 810 Test (15.0%) | **PASS** |
| **Category Totals** | 2,500 Ham / 1,500 Spam / 1,400 Smish | 2,500 Ham / 1,500 Spam / 1,400 Smishing | **PASS** |
| **Serial Uniqueness** | Exactly 5,400 unique IDs | 5,400 unique serial numbers (each record appears once) | **PASS** |
| **WSPR Campaign Overlap** | Zero campaigns shared across splits | Train (980) $\cap$ Val (210) $\cap$ Test (210) = $\emptyset$ | **PASS** |
| **Exact Normalized Hash Overlap**| Zero text hashes shared across splits | Train $\cap$ Val = $\emptyset$, Train $\cap$ Test = $\emptyset$, Val $\cap$ Test = $\emptyset$ | **PASS** |
| **Overlap with 77,677 Corpus** | Zero exact text hash collisions | Exactly 0 collisions against `corpus_simhash_index.npz` | **PASS** |
| **Overlap with 250 Pilot** | Zero exact collisions & 0 pilot campaigns| Exactly 0 pilot hash collisions; 0 pilot campaign collisions | **PASS** |

---

## 5. Final Formal Decision

> [!IMPORTANT]
> **FINAL DECISION: B. CONDITIONAL GO FOR TRAINING.**
> 
> Authorization is granted to proceed with model training on the **Proposed V2 split manifest** (`sms_split_manifest.csv`) under the following documented conditions:
> 
> 1. **Authorized Scope:**  
>    Model training is permitted strictly using the Train partition (`3,780` records in `proposed_v2/sms_split_manifest.csv`). Model evaluation and threshold tuning are permitted on Validation (`810` records).
> 2. **Documented Limitation 1: Participant Overlap (ExAIS):**  
>    Due to the necessity of breaking the 2,621-record broadcast megacomponent, ExAIS participants are present across Train, Validation, and Test. Although all exact texts and near-duplicate templates are 100% quarantined, the internal test set measures **message-level generalization**, not strict zero-exposure user-level generalization.
> 3. **Documented Limitation 2: Source Asymmetry in Validation:**  
>    Validation ham is $99.7\%$ UCI-derived, while validation commercial spam is $96\%$ ExAIS-derived. Subgroup evaluations must report UCI and ExAIS performance separately.
> 4. **Documented Limitation 3: Diagnostic Independence:**  
>    The internal test partition (810 records) must be described as an **internal development holdout**. A fresh, independent third-party smishing dataset (outside WSPR and ExAIS) remains required for final external acceptance before production deployment.
