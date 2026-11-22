# SMS Training Data Inventory

**Report Milestone:** SMS Model Readiness Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Inspected Source:** `backend/data/raw/combined_reduced.json` (77,677 total records)  

---

## 1. Executive Summary

This audit investigates the presence, distribution, and label semantics of short-message and SMS records in the project's primary raw dataset (`combined_reduced.json`).

The raw JSON file contains 77,677 records with a binary schema (`label: int`, `text: str`), where `0` designates benign/ham and `1` designates phishing/malicious. Forensic analysis reveals that **short-message records are heavily present in the raw corpus**, but were almost entirely sequestered away from the training partition of the frozen models.

```
Total Raw Corpus Records: 77,677
├── URLs (Bare links, domain strings)      : 41,195 (53.0%)
├── Plain Text (Short messages, SMS, notes): 18,929 (24.4%)
├── HTML (Rendered web bodies, DOM tags)   : 15,758 (20.3%)
└── Email (MIME structures, headers)       :  1,794 ( 2.3%)
```

---

## 2. Character Length Distribution of `combined_reduced.json`

The raw corpus exhibits extreme multimodal length dispersion:

| Character Length Range | Record Count | Percentage of Corpus | Dominant Modality |
| :--- | :--- | :--- | :--- |
| **< 50 characters** | 29,713 | 38.3% | Bare URLs, domain apexes, single-word strings |
| **50 – 160 characters** | 15,092 | 19.4% | **Standard SMS messages**, short URL queries |
| **160 – 500 characters** | 5,584 | 7.2% | Extended SMS, short email bodies |
| **> 500 characters** | 27,288 | 35.1% | Full HTML DOM trees, detailed email messages |
| **Total** | **77,677** | **100.0%** | Comprehensive Multi-Source Corpus |

---

## 3. Disaggregated Source Analysis: Mishra & Soni and UCI SMS

### 3.1 Mishra & Soni SMS Phishing Dataset (Mendeley Data 2022)
- **Original Composition:** 5,971 messages (4,844 Ham, 638 Smishing, 489 Spam).
- **Ingestion Provenance:** Ingested into `combined_reduced.json` via the Hugging Face compilation `ealvaradob/phishing-dataset`.
- **Original Labels vs. Project Mapping:**
  - Original Mishra & Soni distinguished 3 classes: Ham, Smishing, and Commercial Spam.
  - In `combined_reduced.json`, both **Smishing** and **Commercial Spam** were collapsed into label `1` (phishing), while **Ham** was mapped to label `0`.
- **Methodological Vulnerability:**  
  Collapsing nuisance commercial spam into label `1` introduced a severe label conflation artifact: marketing messages like *"Text AGE to 150p per minute"* were labeled as security threats rather than non-malicious nuisance advertising.

### 3.2 UCI SMS Spam Collection Overlap
- **Corpus Overlap:** 5,159 unique texts from the 5,574-record UCI SMS Spam Collection were matched against `combined_reduced.json`.
- Over 2,000 UCI records are embedded directly within the raw corpus, confirming the DIFrauD benchmark warning (Boumber & Verma, 2023) that Mishra & Soni heavily duplicated the UCI collection.

### 3.3 Partitioning Audit: Was Mishra & Soni Used to Train the Frozen Models?
To determine whether Mishra & Soni records actually trained the frozen models, we cross-referenced their source indices with `backend/reports/ml/phishing_domain_extraction_v2/domain_holdout_split_v2/split_manifest.csv`:

| `domain_holdout_v2` Partition | UCI / Mishra & Soni Matches | Description & Significance |
| :--- | :--- | :--- |
| **Train (`9,481` rows)** | **13** | **Only 13 SMS records** trained V2, V3 Dual, V3 Content, and V3 URL! |
| **Validation (`2,032` rows)** | 33 | 33 records held out in validation |
| **Test (`2,032` rows)** | 31 | 31 records held out in test |
| **Quarantined (`16,160` rows)** | 48 | Excluded due to promotional ambiguity or graph conflict |
| **`no_destination_cohort` (`47,324` rows)** | **1,872** | **95.6% of SMS records were quarantined from training!** |

> [!IMPORTANT]
> **Definitive Finding:**  
> The frozen models were **NOT** trained on an SMS corpus. Because the V2/V3 domain-held-out protocol required a high-confidence registrable domain destination key to enter the primary cohort, **47,324 records with no extractable apex domain (including >95% of SMS messages) were relegated to `no_destination_cohort` and excluded from model fitting.**  
> Out of 9,481 training representatives, exactly **13 records** were derived from UCI / Mishra & Soni. The frozen models are web-page classifiers that have effectively never seen mobile text messages.

---

## 4. Metadata Availability & Exact Duplication

1. **Source Metadata Availability:**  
   The raw `combined_reduced.json` retains no column headers for origin dataset, timestamp, sender, or telecom attributes. Source identity is inferable only by text hash lookup against parent repositories.
2. **Exact Duplicate Counts:**  
   In `combined_reduced.json`, there are 77,412 unique normalized hashes across 77,677 rows (265 exact duplicate records, largely repeated short greeting strings and domain redirects).
3. **URL Presence in SMS:**  
   Across the 18,929 plain text messages, 88.5% contain zero candidate URLs, explaining why models dependent on URL feature extraction fail completely.
