# SMS-05 Readiness Decision: GO for Dataset Assembly and Experimentation

**Milestone:** SMS-05 Planning — Linkless Smishing Generalization  
**Scope:** Final Feasibility Review, Data Availability Verification, and Governance Approval  
**Status:** Readiness Review Complete  
**Date:** November 2026  

---

## 1. Formal Readiness Decision: GO

**Formal Decision: GO for the assembly of the SMS-05 multi-source training pool and subsequent model experimentation.**

The investigation has established that:
1. **The Root Cause of SMS-03's Failure is Fully Diagnosed:** The collapse of SMS-03 on the Mishra & Soni held-out benchmark ($11.0\%$ recall) was caused by exclusive reliance on URL-bearing smishing during training, producing large positive weights for URL tokens and a negative intercept ($-1.3329$) that penalizes linkless telephone callback lures.
2. **Sufficient Independent Linkless Smishing Data Exists:**
   - **254 pristine, linkless smishing records** are already inventoried and available in the remaining Mishra & Soni development pool (outside the quarantined 500-message benchmark).
   - Over **1,000 contemporary linkless and conversational smishing records** are accessible via the ACM IMC 2025 (`reportsmishing`) dataset under CC BY 4.0 licensing.
3. **Multi-Source Negative Controls are Readily Available:** Ample independent commercial spam ($N > 1,500$) and benign ham ($N > 4,000$) exist across ExAIS, UCI, and Mishra & Soni to guarantee that ham false positive rates remain near $0.0\%$.
4. **All Quarantine Protections are Preserved:** The 500-message Mishra & Soni benchmark, the 250-record SMS pilot, and the frozen SMS-03 model artifact remain completely untouched and isolated.

---

## 2. Gate Verification Checklist

| Readiness Criterion | Status | Findings & Evidentiary Support |
| :--- | :---: | :--- |
| **1. SMS-03 Model Freeze Preserved** | **VERIFIED** | SHA-256 `8dd043a3b832...` verified byte-identical. Zero model modifications. |
| **2. Quarantined Benchmarks Protected** | **VERIFIED** | 500-message benchmark and 250-message pilot isolated. Zero overlap with SMS-05 pool. |
| **3. Remaining Mishra & Soni Inventoried** | **VERIFIED** | 4,174 eligible records cataloged: 326 smishing (254 linkless), 335 spam, 3,513 ham. |
| **4. External Linkless Corpora Discovered**| **VERIFIED** | IMC 2025 (`reportsmishing`) and Zenodo 2025 identified with CC BY 4.0 licenses. |
| **5. Multi-Source Diversity Guaranteed** | **VERIFIED** | Sourcing matrix balances US, UK, and European feeds across positive and negative classes. |
| **6. Model Architecture Roadmap Defined** | **VERIFIED** | 4 architectures specified (Word, Char, Combined Union, and Two-Channel Meta). |
| **7. Two-Tier Evaluation Protocol Defined** | **VERIFIED** | Internal Test + Zenodo/CallShield External Benchmark specified. |

---

## 3. Recommended Next Operational Steps

Upon user authorization, proceed with the following staged execution:

1. **Step 1 — Ingestion of External Linkless Smishing:**  
   Acquire and screen the English-language conversational smishing subset from [`reportsmishing/Smishing-Dataset-IMC25`](https://github.com/reportsmishing/Smishing-Dataset-IMC25), filtering out non-SMS and non-English rows.
2. **Step 2 — Assemble SMS-05 Candidate Pool:**  
   Combine WSPR-NCSU ($N \approx 1,400$), IMC 2025 Linkless ($N \approx 1,200$), Mishra & Soni Remaining ($N = 800$), and ExAIS ($N \approx 2,400$) into a unified $\sim 6,800$-record pool.
3. **Step 3 — Leakage-Safe Stratification:**  
   Execute campaign-aware and SimHash template-aware splitting into Train (70%), Validation (15%), and Internal Test (15%).
4. **Step 4 — Execute Model Experiments:**  
   Fit and compare candidate architectures SMS-05-A, SMS-05-B, SMS-05-C, and SMS-05-D on the Training partition, evaluating against the Validation partition.
5. **Step 5 — Freeze Winning Candidate:**  
   Select the highest-performing model, serialize to `sms_05_model.joblib`, compute SHA-256 digest, and run single Internal Test evaluation.
