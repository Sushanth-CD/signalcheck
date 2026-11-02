# Training Partition Audit: SMS Representation in Frozen Models

**Report Milestone:** SMS Model Readiness Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Inspected Split Manifest:** `backend/reports/ml/phishing_domain_extraction_v2/domain_holdout_split_v2/split_manifest.csv`  
**Inspected Baseline Manifest:** `backend/reports/ml/text_phishing_baseline/split_manifest.csv`  

---

## 1. Executive Summary

This audit determines whether mobile text and SMS records participated in the training, validation, and testing partitions of the project's existing frozen phishing detection models (**V2 Baseline**, **V3 Dual-Channel**, **V3 Content-Only**, and **V3 URL-Only**).

The audit confirms that **the domain-grouping protocol designed to prevent domain leakage systematically purged virtually all short plain-text messages from the training partition.**

---

## 2. Partition Cross-Tabulation: Modality vs. Allocation

In `backend/reports/ml/phishing_domain_extraction_v2/domain_holdout_split_v2/split_manifest.csv`, records were assigned to partitions based on connected components of high-confidence registrable destination domains.

### Cross-Tabulation of Inferred Input Type by Partition:

| Partition | Total Records | URL Records | HTML Records | Plain Text Records | Email Records | SMS Share (%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Train (Model Fitting)** | **9,481** | 8,239 | 1,028 | **202** | 12 | **2.13%** |
| **Validation** | 2,032 | 1,523 | 382 | **112** | 15 | **5.51%** |
| **Test** | 2,032 | 1,521 | 374 | **134** | 3 | **6.59%** |
| **`quarantined_data_quality`** | 16,160 | 2,408 | 9,798 | **2,876** | 1,078 | 17.80% |
| **`no_destination_cohort`** | 47,324 | 27,376 | 4,069 | **15,504** | 375 | **32.76%** |
| **`uncertain_destination`** | 647 | 128 | 107 | 101 | 311 | 15.61% |
| **`excluded_empty_text`** | 1 | 0 | 0 | 0 | 0 | 0.00% |
| **Total** | **77,677** | **41,195** | **15,758** | **18,929** | **1,794** | **24.37%** |

---

## 3. Analysis of SMS Exclusion Mechanism

### 3.1 The Destination Key Prerequisite
To prevent test leakage, the V2/V3 protocol required every record in the primary cohort to possess an extractable destination key (`registrable:<domain>` or `ip:<address>`).
- Normal conversational SMS messages (e.g., *"I'm running 5 minutes late"*, *"Thanks for the birthday card"*) do not contain URLs.
- As a direct consequence, **15,504 out of 18,929 plain text records (81.9%) were assigned to `no_destination_cohort` and completely excluded from model training.**
- Another 2,876 plain text records were sequestered in `quarantined_data_quality` due to commercial promotional flags.

### 3.2 The Remaining 202 "Plain Text" Training Records
Of the 9,481 records that actually trained the models:
- 8,239 (86.9%) were bare URLs.
- 1,028 (10.8%) were webpage HTML bodies.
- Only 202 (2.13%) were categorized as plain text, and almost all of these 202 records were text snippets that happened to contain embedded HTTP URLs.
- Exactly **13 records** matching the UCI / Mishra & Soni SMS dataset were present in the training partition.

---

## 4. Leakage and Partition Integrity Findings

1. **Campaign and Source Grouping:**  
   The domain-held-out split successfully prevented domain-level leakage for web URLs, but did **not** group SMS records by source dataset, mobile carrier campaign, or conversational thread.
2. **Cross-Partition Duplicate Leakage:**  
   Because 1,872 UCI SMS records were placed in `no_destination_cohort`, while 13 were in Train, 33 in Validation, and 31 in Test, identical or near-duplicate conversational templates (e.g., student greetings, standard operator notices) exist across partitions.
3. **Implication for Model Evaluation:**  
   The frozen models were never trained to distinguish benign conversational text from malicious lures. They were trained almost exclusively on web URLs and HTML DOM trees, explaining why SMS inputs trigger default intercept predictions.
