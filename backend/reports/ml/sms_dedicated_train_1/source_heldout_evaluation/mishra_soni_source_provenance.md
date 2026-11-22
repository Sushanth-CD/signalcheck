# Mishra & Soni SMS Phishing Dataset: Provenance and Architecture Review

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation Investigation  
**Investigation Scope:** Original Provenance, Dataset Structure, Upstream Compilation, and Licensing Terms  
**Status:** Read-Only Audit Complete  
**Date:** November 2026  

---

## 1. Executive Summary

This provenance audit establishes the bibliographic origin, upstream compilation history, architectural structure, and redistribution licensing of the **Mishra & Soni SMS Phishing Dataset**.

The primary objective is to evaluate whether the original Mishra & Soni corpus can serve as a valid **source-held-out evaluation benchmark** for our newly frozen SMS phishing classifier ([`sms_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib)), which was trained exclusively on smishing from WSPR-NCSU and negative controls from UCI and ExAIS.

```
+---------------------------------------------------------------------------------------------------+
| MISHRA & SONI (MENDELEY DATA 2022) AT A GLANCE                                                    |
+---------------------------------------------------------------------------------------------------+
|  * Official Release: "SMS PHISHING DATASET FOR MACHINE LEARNING AND PATTERN RECOGNITION"          |
|  * Authors: Sandhya Mishra and Devpriya Soni (Jaypee Institute of Information Technology)         |
|  * Repository / DOI: 10.17632/f45bkkt8pr.1 on Mendeley Data (Published June 2022)                 |
|  * Total Raw Records: 5,971 text messages                                                         |
|  * Original Classes: 3 distinct classes (Ham: 4,844 | Smishing: 638 | Spam: 489)                   |
|  * Upstream Absorption: Ingested into ealvaradob/phishing-dataset (combined_reduced.json)         |
|  * License: Creative Commons Attribution 4.0 International (CC BY 4.0)                           |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Bibliographic & Origin Details

### 2.1 Authorship and Research Group
- **Principal Researchers:** Sandhya Mishra and Devpriya Soni
- **Affiliation:** Department of Computer Science and Engineering & Information Technology, Jaypee Institute of Information Technology (JIIT), Noida, Uttar Pradesh, India.
- **Permanent DOI:** [`10.17632/f45bkkt8pr.1`](https://doi.org/10.17632/f45bkkt8pr.1)
- **Archive Platform:** Mendeley Data (Elsevier BV), Version 1, Released June 2022.

### 2.2 Original Collection Methodology
According to the published metadata and companion analysis:
1. **Benign Ham Acquisition:** The authors sourced the vast majority of their benign ham messages directly from the classic Almeida & Gómez Hidalgo (2011/2012) **UCI SMS Spam Collection**.
2. **Commercial Spam Acquisition:** Sourced from public spam repositories and the UCI Spam collection.
3. **Smishing Acquisition:** Unlike modern automated gateway feeds (such as WSPR-NCSU), Mishra & Soni compiled SMS phishing lures by converting images and screenshots of smishing alerts gathered from cybersecurity forums, social media reports, fraud warning blogs, and web feeds into text using OCR and Python scripts.

---

## 3. Upstream Compilation History: `ealvaradob/phishing-dataset`

A critical aspect of project provenance is how Mishra & Soni entered the repository:
1. In 2024, Esteban Alvarado released [`ealvaradob/phishing-dataset`](https://huggingface.co/datasets/ealvaradob/phishing-dataset) on Hugging Face, combining 4 disparate data sources:
   - Enron & Kaggle email dataset (>18,000 emails)
   - Mendeley Mishra & Soni SMS dataset (5,971 messages)
   - Harisudhan411 URL dataset (800,000 URLs)
   - Mendeley Website HTML dataset (30,000 web pages)
2. This Hugging Face compilation became our project's baseline training file: [`backend/data/raw/combined_reduced.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/data/raw/combined_reduced.json) (77,677 total records).
3. **The Conflation Flaw:** As documented in earlier audits, `ealvaradob/phishing-dataset` collapsed all non-ham text types into binary labels:
   - `Ham` $\rightarrow$ `0`
   - `Commercial Spam` $\rightarrow$ `1`
   - `Smishing` $\rightarrow$ `1`
4. This conflation made it impossible to distinguish nuisance commercial marketing from active malicious smishing using `combined_reduced.json` alone. Recovering the true original 3-class distribution required accessing the direct primary release.

---

## 4. Schema and Attribute Inspection

The original primary release contains 5,971 records structured across 5 columns:

| Column Name | Data Type | Null Count | Description & Value Domain |
| :--- | :--- | :---: | :--- |
| `LABEL` | String | 0 | Ground truth class: `ham` ($N=4,844$), `Smishing` ($N=616$), `smishing` ($N=22$), `spam` ($N=466$), `Spam` ($N=23$). |
| `TEXT` | String | 0 | Full raw message text (untruncated). |
| `URL` | String | 0 | Binary flag indicating presence of an embedded web link (`No`: 5,764, `yes`: 207). |
| `EMAIL` | String | 0 | Binary flag indicating presence of an email address (`No`: 5,952, `yes`: 19). |
| `PHONE` | String | 0 | Binary flag indicating presence of a telephone callback number (`No`: 5,127, `yes`: 844). |

---

## 5. Licensing and Research Rights

- **License:** **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
- **Terms:** Permits sharing, copying, redistributing, adapting, remixing, transforming, and building upon the material for any purpose, including commercial and academic research, provided appropriate credit is given to the original authors.
- **Redistribution & Compliance:** Fully compliant with our research-use protocols. No proprietary non-disclosure restrictions apply.
