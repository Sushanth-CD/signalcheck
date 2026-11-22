# Readiness Decision: GO for Ingesting ACM IMC 2025 `reportsmishing`

**Milestone:** SMS-05 Pilot Acquisition & Forensic Inspection  
**Candidate Dataset:** `reportsmishing/Smishing-Dataset-IMC25`  
**License:** Creative Commons Attribution 4.0 International (CC BY 4.0)  
**Evaluated Target:** SMS-05 Training Dataset Preparation  
**Decision Date:** November 2026  

---

## 1. Formal Readiness Decision: GO

**Formal Decision: GO for integrating the official ACM IMC 2025 `reportsmishing` dataset as a primary positive training source for the SMS-05 classifier.**

This forensic pilot acquisition confirms that:
1. **The Dataset Consists of Genuine SMS Text:** Over **98.6%** of the English records represent actual mobile text messages extracted from user screenshots or direct copy-pastes, not user commentary or forum discussion.
2. **Abundant Linkless Smishing is Confirmed:** The dataset contains **8,560 unique, pristine linkless smishing messages** in English, fully surpassing the SMS-05 target requirement of 1,200 records by **$+613\%$**.
3. **High Scam Diversity:** It captures conversational attack vectors that were completely absent from WSPR-NCSU, including "Hey Mum/Dad" family impersonation ($N = 240$), telephone callback traps ($N = 3,427$), WhatsApp redirects ($N = 168$), and conversational wrong-number lures ($N = 275$).
4. **Complete Training Independence:** The dataset has **zero collisions** against the training, validation, or test partitions of SMS-03, zero collisions against the 250-record diagnostic pilot, and zero collisions against the project's baseline 77,677-record corpus.
5. **Strict Benchmark Isolation:** Exactly one near-duplicate template matching the quarantined 500-record Mishra & Soni benchmark (*"pyatm wallet KYC"*, 3 instances in IMC) was identified and permanently purged.
6. **Open Academic Licensing:** The CC BY 4.0 license is fully verified in the repository.

---

## 2. Gate Verification Summary

| Pilot Gate Check | Status | Evidentiary Findings |
| :--- | :---: | :--- |
| **1. Official Artifact Verification** | **PASSED** | Commit SHA `a6175560...` verified. File size 9,462,365 bytes. SHA-256 `1bbd1e9e...` verified. |
| **2. Record Typology Classification** | **PASSED** | 21,769 actual SMS messages, 221 OCR stubs, 85 unusable short/placeholder, 4 warning posts. |
| **3. Linkless Volume Sufficiency** | **PASSED** | 8,560 unique linkless smishing messages available (exceeds 1,200 target). |
| **4. Language & Provenance Separation**| **PASSED** | English cohort (22,078 rows) strictly isolated. Non-English rows cataloged separately. |
| **5. Independence Screening** | **PASSED** | Zero overlap with SMS-03 splits or pilot. 3 benchmark near-matches quarantined. |
| **6. Non-Disclosure & Privacy** | **PASSED** | Personally identifying phone numbers and account numbers pre-sanitized with semantic tags. |
| **7. Zero Model Modification** | **PASSED** | Frozen SMS-03 SHA-256 `8dd043a3...` verified byte-identical. No inference executed. |

---

## 3. Recommended Next Operational Steps

Upon user authorization, proceed immediately with the **SMS-05 training data assembly**:
1. Draw **1,200 unique linkless English smishing records** and **1,000 unique URL-bearing English smishing records** from [`eligible_smishing_candidates.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/reportsmishing_pilot/eligible_smishing_candidates.csv).
2. Merge with the **254 remaining Mishra & Soni linkless records** and **1,400 WSPR-NCSU URL campaigns**.
3. Pair with **3,400 negative controls** (ExAIS Ham & Spam, Mishra & Soni Remaining Ham & Spam, UCI Ham).
4. Execute campaign-aware and SimHash-aware splitting into Train (70%), Validation (15%), and Internal Test (15%).
5. Train and compare candidate models **SMS-05-A**, **SMS-05-B**, **SMS-05-C**, and **SMS-05-D**.
