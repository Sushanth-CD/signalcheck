# Final Partition Recommendation: Adoption of Proposed V3

**Milestone:** SMS-DEDICATED-TRAIN-1 Final Recommendation  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v3/`  
**Decision Authority:** Lead Machine Learning & Security Review  

---

## 1. Comparative Synthesis of Partition Candidates

| Dimension | Initial V1 Partition | Proposed V2 Partition | Proposed V3 Partition (SELECTED) |
| :--- | :--- | :--- | :--- |
| **Validation Spam Count** | 22 records (**Severe Starvation**) | **225 records** (Adequate) | **221 records** (Adequate) |
| **Validation Ham Balance** | 371 UCI / 4 ExAIS (**Severe Skew**) | 374 UCI / 1 ExAIS (**Severe Skew**) | **187 UCI / 187 ExAIS (Exact 50/50!)** |
| **Test Ham Balance** | 375 UCI / 0 ExAIS (**Severe Skew**) | 374 UCI / 1 ExAIS (**Severe Skew**) | **188 UCI / 188 ExAIS (Exact 50/50!)** |
| **Total Components** | 2,626 (contains megacomponent) | 4,801 granular components | **4,801 granular components** |
| **Largest Component Size** | 2,621 records | 14 records | **14 records** |
| **Campaign Overlap** | 0 (Strict Holdout) | 0 (Strict Holdout) | **0 (Strict Holdout)** |
| **Exact-Text Overlap** | 0 (Strict Holdout) | 0 (Strict Holdout) | **0 (Strict Holdout)** |
| **Near-Duplicate Overlap**| 0 (Strict Holdout) | 0 (Strict Holdout) | **0 (Strict Holdout)** |
| **Target Proportions** | 77.5% / 11.2% / 11.2% | 70.0% / 15.0% / 15.0% | **70.2% / 14.9% / 14.9%** |

---

## 2. Definitive Recommendation: ADOPT PROPOSED V3

> [!IMPORTANT]
> **FORMAL RECOMMENDATION: PROCEED WITH PROPOSED V3 FOR MODEL TRAINING.**
> 
> The Proposed V3 partition manifest (`proposed_v3/sms_split_manifest.csv`) is formally recommended for exploratory model development. It achieves:
> 1. **Complete Elimination of Source Asymmetry on Ham:** Validation and testing evaluate an exact 50/50 mixture of Western English SMS (UCI) and contemporary African carrier/academic SMS (ExAIS).
> 2. **Adequate Commercial Spam Volume:** 221 validation spam records enable precise false-alarm threshold tuning.
> 3. **Mathematical Invariant Compliance:** Exactly zero campaign overlap, zero text overlap, zero near-duplicate leakage, and zero pilot contamination.

---

## 3. Explicit Remaining Limitations to Acknowledge

1. **ExAIS Participant Overlap:**  
   Because telecom operators broadcast identical notices to multiple users, individual user inboxes span across partitions. The internal test set measures **message and template generalization**, not strict unseen-user generalization.
2. **Positive-Class Source Confounding:**  
   100% of smishing messages currently originate from WSPR-NCSU. While campaigns are strictly held out, all positive examples share WSPR feed characteristics.
3. **URL Presence in Smishing:**  
   100% of WSPR smishing messages contain URLs due to deterministic campaign mapping. The model will specialize in link-bearing smishing.
4. **Holdout Status:**  
   The 806-record internal test partition is an internal development holdout. A fresh external dataset must be acquired for final production acceptance.
