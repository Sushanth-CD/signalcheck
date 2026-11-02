# Partition Quality Audit & Pre-Training Authorization Decision

**Milestone:** SMS-DEDICATED-TRAIN-1 Partition Quality Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/`  
**Audit Status:** Formal Decision Rendered  

---

## 1. Executive Summary

This investigation performed a comprehensive, read-only quality audit of the initial partition manifests generated under `SMS-DEDICATED-TRAIN-1` for the 5,400 assembled SMS records.

The audit verified that while all formal independence invariants (zero campaign leakage, zero exact text overlap, zero near-duplicate collisions, zero pilot contamination) were strictly satisfied, the initial split suffered from an extreme **distribution defect**:
- **Commercial spam was distributed 1,457 in Train, 22 in Validation, and 21 in Test.**
- Validation and Test partitions contained almost zero commercial marketing spam, making it impossible to evaluate commercial spam false-alarm rates during model tuning.

---

## 2. Root Cause & Solution

1. **Root Cause:** Treating ExAIS participant files as monolithic units caused 17 participant files to merge into a single component of 2,621 records via shared telecom broadcast messages (e.g., carrier SMS capacity notices). The greedy partitioner placed this entire block into Train, starving Validation and Test.
2. **Solution (Proposed V2):** Clustered records by attack campaign, exact normalized text, and near-duplicate templates ($H \le 3$, $J \ge 0.90$), without artificially chaining entire participant files.
3. **Outcome:** Generated `proposed_v2/sms_split_manifest.csv`, which achieves a balanced **70.0% Train (3,780), 15.0% Validation (810), and 15.0% Test (810)** distribution across all three ground-truth categories while maintaining 100% independence invariants.

---

## 3. Formal Readiness Decision

> [!IMPORTANT]
> **DECISION: B. CORRECTED SPLIT REQUIRED.**  
> Authorization is **WITHHELD** for the initial V1 split due to insufficient validation and test spam coverage (only 22 and 21 records).  
> Authorization is **GRANTED FOR THE PROPOSED V2 SPLIT** (`proposed_v2/sms_split_manifest.csv`), which provides:
> - 225 commercial spam records in Validation (sufficient for statistically significant false-positive evaluation).
> - 225 commercial spam records in Internal Test.
> - Zero cross-split leakage across all campaigns and text templates.

---

## 4. Next Step

Proceed with model training under `SMS-DEDICATED-TRAIN-1` using the **Proposed V2 split manifest** (`backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v2/sms_split_manifest.csv`).
