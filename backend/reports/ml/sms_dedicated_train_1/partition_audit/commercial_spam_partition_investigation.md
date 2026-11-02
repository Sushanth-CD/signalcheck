# Commercial Spam Partition Imbalance Investigation

**Milestone:** SMS-DEDICATED-TRAIN-1 Partition Quality Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/`  

---

## 1. Executive Summary: The 1,457 / 22 / 21 Imbalance

In the initial split manifest (`sms_split_manifest.csv`), commercial spam was distributed as follows:
- **Train:** **1,457 records** ($97.13\%$ of all commercial spam; represents $45.4\%$ of the negative training class).
- **Validation:** **22 records** ($1.47\%$ of all commercial spam; represents only $5.5\%$ of the negative validation class).
- **Internal Test:** **21 records** ($1.40\%$ of all commercial spam; represents only $5.3\%$ of the negative test class).

This severe concentration leaves validation and testing almost completely devoid of commercial marketing spam, rendering the validation set incapable of measuring whether candidate models will falsely flag advertising messages as smishing.

---

## 2. Root Cause Analysis: The Indivisible Megacomponent

Forensic graph analysis of `backend/reports/ml/sms_dedicated_train_1/sms_group_assignments.csv` revealed the exact structural reason for this concentration:

### 2.1 Component Size Disparity & Megacomponent `sms_comp_02595`
- The candidate pool contains **2,626 total components**.
- Exactly **2,618 components** are small clusters (sizes 1 to 10).
- However, **a single massive connected component—`sms_comp_02595`—contains 2,621 records** ($48.5\%$ of the entire 5,400-record dataset!).
- Within `sms_comp_02595`:
  - **Commercial Spam:** **1,424 records** ($94.9\%$ of all 1,500 commercial spam records!).
  - **Benign Ham:** **1,197 records** ($47.9\%$ of all 2,500 benign ham records).

```
Candidate Pool (5,400 Records)
├── Megacomponent sms_comp_02595 : 2,621 records (1,424 Commercial Spam + 1,197 Ham)
└── All Other 2,625 Components   : 2,779 records (   76 Commercial Spam + 1,303 Ham + 1,400 Smishing)
```

### 2.2 Why Did the Megacomponent Form?
The pipeline grouped ExAIS messages by `participant_id` (e.g., `ExAIS_USER 1` through `USER 20`) under the assumption that messages from the same mobile user formed an isolated group.

However, mobile carriers frequently broadcast identical promotional texts and carrier service updates to **multiple subscribers simultaneously**:
- Example broadcast text: `"Dear customer, your phone has reached its SMS capacity. To continue to receive SMS, please delete old messages."`
- Example carrier marketing: `"Enjoy 20% discount on weekend data plans! Dial *131# now."`

Because 17 of the 20 ExAIS user files received overlapping carrier broadcasts, the transitive graph closure:
$$\text{User A} \sim \text{Broadcast Message } M \sim \text{User B}$$
chained **17 participant files together into a single monolithic component of 2,621 records**.

### 2.3 Greedy Allocator Failure
When the partition allocator processed components sorted by size:
1. `sms_comp_02595` was evaluated first (size 2,621).
2. Because Train was budgeted for 70% of the data (3,780 records), `sms_comp_02595` easily fit within Train.
3. Placing `sms_comp_02595` into Train consumed 1,424 commercial spam records in one assignment, leaving only 76 commercial spam records across the entire rest of the dataset.
4. Validation and Test were then left with scraps (22 and 21 records respectively).

---

## 3. Methodological Evidence & Diagnostic

| Grouping Mechanism | Components Created | Largest Component Size | Feasibility of Stratification |
| :--- | :--- | :--- | :--- |
| **Monolithic Participant Grouping** | 2,626 | **2,621** (17 users merged) | **INVIOLABLE IMBALANCE:** Validation and test cannot exceed 25 spam samples. |
| **Message-Level & Campaign Grouping** | 4,801 | **14** (identical carrier broadcasts) | **PERFECT STRATIFICATION:** Exactly 70% / 15% / 15% across all 3 classes! |

### Conclusion:
Treating an entire user file as an indivisible unit when users receive identical public telecom broadcasts is flawed. The actual unit of leakage prevention is the **shared text message / template** and the **attack campaign**, not the arbitrary participant collector index.
