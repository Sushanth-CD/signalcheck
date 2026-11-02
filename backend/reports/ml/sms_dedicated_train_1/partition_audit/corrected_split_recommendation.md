# Corrected Partition Strategy & Proposed V2 Manifest Recommendation

**Milestone:** SMS-DEDICATED-TRAIN-1 Partition Quality Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v2/`  

---

## 1. Recommendation: Transition to Proposed V2 Grouping

To enable realistic false-positive evaluation for commercial marketing spam while maintaining airtight leakage safety, we propose **Proposed V2 Splitting**.

### 1.1 Independence Invariant Definitions for V2:
1. **WSPR Smishing:** Every distinct attack campaign ID is locked to exactly one partition. (Zero campaign leakage across train, val, and test).
2. **Exact Normalized Texts:** Identical message texts (including shared carrier broadcast SMS) are locked to the same partition. (Zero exact text leakage across partitions).
3. **Near-Duplicate Templates:** Character 5-gram SimHash pairs with Hamming distance $\le 3$ and Jaccard similarity $\ge 0.90$ are clustered into the same component. (Zero template leakage across partitions).
4. **Participant Isolation:** Distinct conversational messages belonging to distinct participants remain independent unless linked by an identical public broadcast.

---

## 2. Comparison of Initial V1 vs. Proposed V2 Partitions

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| PARTITION BALANCE COMPARISON: INITIAL V1 vs. PROPOSED V2                                          |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                   |
|  INITIAL V1 PARTITION (Severely Skewed):                                                          |
|  - Train (4,187 records)     : 1,750 Ham (41.8%) | 1,457 Commercial Spam (34.8%) | 980 Smishing   |
|  - Validation (607 records)  :   375 Ham (61.8%) |    22 Commercial Spam ( 3.6%) | 210 Smishing   |
|  - Internal Test (606 records:   375 Ham (61.9%) |    21 Commercial Spam ( 3.5%) | 210 Smishing   |
|                                                                                                   |
|  PROPOSED V2 PARTITION (Balanced 70% / 15% / 15% Stratification Across All Categories):           |
|  - Train (3,780 records)     : 1,750 Ham (46.3%) | 1,050 Commercial Spam (27.8%) | 980 Smishing   |
|  - Validation (810 records)  :   375 Ham (46.3%) |   225 Commercial Spam (27.8%) | 210 Smishing   |
|  - Internal Test (810 records:   375 Ham (46.3%) |   225 Commercial Spam (27.8%) | 210 Smishing   |
|                                                                                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

### Key Improvements in Proposed V2:
1. **Adequate Spam Representation in Validation:** Commercial spam increases from **22 records to 225 records**, providing a statistically meaningful sample to measure commercial spam false-alarm rates.
2. **Exact Proportion Preservation:** Each of the three original categories achieves an exact 70% / 15% / 15% allocation:
   - Ham (2,500 total): 1,750 Train (70%) / 375 Val (15%) / 375 Test (15%).
   - Commercial Spam (1,500 total): 1,050 Train (70%) / 225 Val (15%) / 225 Test (15%).
   - Smishing (1,400 total): 980 Train (70%) / 210 Val (15%) / 210 Test (15%).
3. **Rigorous Leakage Invariants Verified:**
   - Campaign overlap between partitions: **0**.
   - Text hash overlap between partitions: **0**.
   - Near-duplicate overlap between partitions: **0**.
   - Pilot collisions: **0**.

---

## 3. Preservation of Original Split Manifest

In compliance with project directives:
- The initial split manifest remains preserved untouched as **Version 1** at:  
  `backend/reports/ml/sms_dedicated_train_1/sms_split_manifest.csv`
- The proposed corrected split manifest is generated under a new versioned directory:  
  `backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v2/sms_split_manifest.csv`
- Supporting metadata is stored in `proposed_v2/sms_split_summary.json`.
