# Inventory of Remaining Mishra & Soni Records

**Milestone:** SMS-05 Planning — Linkless Smishing Generalization  
**Investigation Scope:** Inventory of Eligible Records Outside the 500-Message Quarantined Benchmark  
**Status:** Audit Complete  
**Date:** November 2026  

---

## 1. Executive Summary

In the preceding milestone, a 500-message source-held-out benchmark was extracted from the **Mishra & Soni SMS Phishing Dataset** ([`benchmark_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/model_evaluation/benchmark_manifest.csv)). In accordance with experimental integrity standards, those 500 records are **permanently quarantined** and will never be used for training, validation, or threshold selection.

This inventory quantifies all **4,174 eligible records** from [`eligible_source_cohort.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/source_heldout_evaluation/eligible_source_cohort.csv) that were **not** included in the 500-message benchmark.

```
+---------------------------------------------------------------------------------------------------+
| REMAINING MISHRA & SONI INVENTORY AT A GLANCE (N = 4,174)                                         |
+---------------------------------------------------------------------------------------------------+
|  * Total Eligible Cohort: 4,674 unique records                                                    |
|  * Permanently Quarantined Benchmark: 500 records                                                 |
|  * Remaining Unused Records: 4,174 unique records                                                 |
|                                                                                                   |
|  Disaggregated Breakdown:                                                                         |
|    - Malicious Smishing: 326 records (254 Linkless | 72 URL-bearing)                              |
|    - Commercial Marketing Spam: 335 records (243 Linkless | 92 URL-bearing)                       |
|    - Benign Ham: 3,513 records (3,342 Linkless | 171 URL-bearing)                                 |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Category & URL Presence Distribution

Every remaining record is uniquely indexed by its original `source_row_id` and normalized text SHA-256 hash. Zero records in this remaining inventory collide with any partition of SMS-03 (Train, Validation, Internal Test), the 250-record diagnostic pilot, or the 500-record quarantined benchmark.

| Category | URL-Absent (Linkless) | URL-Present (Regex) | Total Remaining | % of Remaining Category |
| :--- | :---: | :---: | :---: | :---: |
| **Malicious Smishing** | **254** | **72** | **326** | 7.81% |
| **Commercial Spam** | **243** | **92** | **335** | 8.03% |
| **Benign Ham** | **3,342** | **171** | **3,513** | 84.16% |
| **Total Remaining** | **3,839 (91.98%)** | **335 (8.02%)** | **4,174** | 100.00% |

### Critical Finding: Linkless Smishing Availability
The remaining pool contains **254 pristine, linkless smishing records** (77.9% of remaining smishing). These represent social engineering lures directing the victim to premium telephone numbers (`090...`, `087...`), shortcodes (`88039`, `87066`), or direct replies.

---

## 3. Original Label & Feature Flag Integrity

The remaining records preserve their original annotation casing and primary feature flags:

| Category | Original Raw Label | Count | Original `PHONE` Flag (`yes`) | Original `EMAIL` Flag (`yes`) |
| :--- | :--- | :---: | :---: | :---: |
| **Smishing** | `Smishing` | 316 | 258 | 5 |
| | `smishing` | 10 | 9 | 1 |
| **Commercial Spam** | `spam` | 320 | 199 | 11 |
| | `Spam` | 15 | 9 | 0 |
| **Benign Ham** | `ham` | 3,513 | 6 | 0 |
| **Total** | — | **4,174** | **481** | **17** |

Notably, **81.9% of the remaining smishing lures (267 / 326)** explicitly carry the original `PHONE = yes` indicator, confirming that they are telephone-callback social engineering attacks.

---

## 4. Message Length Distributions

Length statistics across the remaining cohorts:

| Category | Count | Mean Length | Std Dev | Median (50%) | 75th % | Max Length |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Smishing** | 326 | 144.2 chars | 33.6 chars | 147.0 chars | 157.0 chars | 387 chars |
| **Commercial Spam** | 335 | 136.2 chars | 34.3 chars | 143.0 chars | 155.5 chars | 379 chars |
| **Benign Ham** | 3,513 | 70.3 chars | 53.0 chars | 53.0 chars | 92.0 chars | 910 chars |

### Length Tier Breakdown
- **Short ($\le 70$ chars):** Ham: 2,231 | Spam: 15 | Smishing: 7
- **Medium (71–140 chars):** Ham: 932 | Spam: 138 | Smishing: 113
- **Long ($> 140$ chars):** Ham: 350 | Spam: 182 | Smishing: 206

---

## 5. Linguistic Characteristics and Social Engineering Lures

Manual and regex analysis of the remaining 254 linkless smishing records reveals distinct social engineering archetypes:
1. **Premium Rate Callback Prompts:**  
   *"<Forwarded from 448712404000>Please CALL 08712404000 immediately as there is an urgent message waiting for you"*
2. **Fabricated Lottery & Prize Claims:**  
   *"You have won a guaranteed £200 award or even £1000 cash to claim UR award call free on 08000407166"*
3. **Shortcode Action Lures:**  
   *"UR awarded a City Break and could WIN a £200 Summer Shopping spree every WK. Txt STORE to 88039"*
4. **Dating & Social Impersonation:**  
   *"You have an active secret admirer who wants to contact you. Call 09058094597 to hear your message"*

---

## 6. Utilization Strategy for SMS-05

- **Availability:** 254 linkless smishing + 72 URL-bearing smishing + 243 linkless commercial spam are available.
- **Role in SMS-05:** These records provide the **foundational training seed** to teach SMS-05 the lexical tokens and sub-word n-grams of telephone callback and shortcode lures without touching the quarantined 500-message benchmark.
