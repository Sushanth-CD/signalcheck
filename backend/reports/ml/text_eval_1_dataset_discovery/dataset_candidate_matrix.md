# Dataset Candidate Matrix

**Milestone:** TEXT-EVAL-1 (Independent Plain-Text and Message Modality Evaluation)  
**Scope:** Dataset Discovery, Provenance Verification, and Screening Feasibility Matrix  
**Status:** Research & Planning Only (Read-Only)  
**Date:** November 2026  

---

## 1. Candidate Dataset Matrix

| Dataset Identifier | Primary Focus | Publisher / Origin | Publication Year | Total Records | Class Distribution | Phishing vs Generic Spam Labeled? | URLs in Messages | Original Text Available? | License / Access | Suitability & Independence Risk | Overall Rank |
| :--- | :--- | :--- | :---: | :---: | :--- | :---: | :---: | :---: | :--- | :--- | :---: |
| **Mishra & Soni (Mendeley Data)** (`10.17632/f45bkkt8pr.1`) | SMS & Smishing | Jaypee Institute of Information Technology (S. Mishra, D. Soni) | 2022 | 5,971 | 4,844 Ham (81.1%), 638 Smishing (10.7%), 489 Spam (8.2%) | **Yes (3-class: Ham, Spam, Smishing)** | Yes (Boolean flag + embedded links) | Yes (CSV with raw `TEXT`) | CC BY 4.0 (Open) | **High Risk:** Constitutes the SMS component of `ealvaradob/phishing-dataset` (`combined_reduced.json`), our primary training corpus. Partial overlap guaranteed. | **Candidate with Strict Screening** |
| **WSPR-NCSU SMS Phishing (IEEE S&P 2024)** | Modern Smishing Infrastructure | NC State Univ. (A. Nahapetyan, B. Reaves et al.) | 2024 | ~300k messages across 1,000+ campaigns | 100% Malicious / Phishing (Gateway verified by VT / APWG) | **Yes (Phishing specific)** | Yes (Campaign-mapped URLs) | Yes (GitHub repository) | Open Research / Citation required | **Excellent Independence:** Collected 2022–2024 from live SMS gateways. Zero chance of inclusion in legacy training corpora. Requires external benign baseline. | **Rank 1 (Phishing SMS)** |
| **UCI SMS Spam Collection (Almeida & Gómez Hidalgo)** | Generic Mobile Spam & Ham | Univ. of Campinas / Univ. of São Paulo (T. Almeida, J. M. Gómez Hidalgo) | 2011 / 2012 | 5,574 | 4,827 Ham (86.6%), 747 Spam (13.4%) | **No (Binary: Ham vs Spam)** | Yes (Some spam has URLs, others phone numbers) | Yes (Raw text format) | CC BY 4.0 | **Moderate Risk:** Classic benchmark. Widely scraped into online aggregators. Spam is commercial/promotional, not explicitly phishing. Excellent benign ham source. | **Rank 2 (Benign Ham Baseline)** |
| **IMC 2025 User Smishing (`reportsmishing`)** | Real-world User Smishing | ACM IMC 2025 Research Team | 2025 | Thousands of user reports | 100% Smishing reports | **Yes (Smishing specific)** | Yes | Yes (CSV on GitHub) | Open Research | **High Independence:** Very recent (2024–2025). High ecological validity, reflects contemporary consumer-targeted SMS lures. | **Rank 2 (Phishing SMS)** |
| **Zenodo Phishing Email Curated Datasets (`10.5281/zenodo.8339691`)** | Multi-Source Email (Enron, Nazario, SpamAssassin, CEAS) | Univ. of Idaho / Fort Hays State (A. I. Champa, M. F. Zibran et al.) | 2024 (Data 1995–2022) | 11 CSV files (>100k emails) | Multi-corpus: Enron (Ham), Nazario (Phishing), SpamAssassin (Ham/Spam), etc. | **Yes (Per sub-file: Ham, Phishing, Spam)** | Yes (URLs in body) | Yes (Standardized CSV with body) | CC BY 4.0 | **High Risk:** Contains Enron and Nazario, which were the exact sources for `combined_reduced.json`. Substantial leakage guaranteed if unpartitioned. | **Candidate with High Quarantine Risk** |
| **IWSPA-AP (2018 / 2020 Anti-Phishing Task)** | Email Phishing & Benign | Univ. of Houston (ReDAS Lab) / ACM CODASPY | 2018 / 2020 | ~10,000 emails per task | Realistic imbalanced: ~90% Benign, ~10% Phishing | **Yes (Phishing vs Benign)** | Yes (Bodies and full MIME) | Yes (Text bodies available) | Academic Use (V1 open on GitHub; V2 requires NDA) | **Moderate Independence:** Independent anti-phishing competition benchmark. Realistic class imbalance. V1 bodies readily accessible. | **Rank 1 (Email)** |
| **SpamAssassin Public Corpus (Official Apache)** | Email Spam & Legitimate | Apache Software Foundation | 2002–2006 | ~6,000 emails | 4,150 Ham (`easy_ham`, `hard_ham`), 1,897 Spam | **No (Generic Spam vs Ham)** | Yes | Yes (Raw mbox/eml format) | Apache / Public Domain | **High Risk:** The standard baseline used in dozens of aggregated datasets; high probability of near-duplicate collision with `combined_reduced.json`. | **Rank 3 (Email)** |

---

## 2. Evaluation Suitability Ranking

### Top Recommendation for SMS Modality:
1. **Malicious Phishing/Smishing:** **WSPR-NCSU SMS Phishing (IEEE S&P 2024)**.  
   *Justification:* Verified by VirusTotal and APWG at carrier gateways; collected 2022–2024; mapped to campaigns; completely independent of our 2020–2022 training data.
2. **Benign / Legitimate Baseline:** **UCI SMS Spam Collection (Ham subset, $N = 4,827$)**.  
   *Justification:* Gold-standard benign human SMS messages from NUS SMS Corpus and Caroline Tagg thesis. Must undergo SimHash screening.

### Top Recommendation for Email Modality:
1. **IWSPA-AP (Anti-Phishing Shared Task Benchmark)**.  
   *Justification:* Purpose-built for anti-phishing text evaluation with natural class imbalance, verified phishing labels, and isolated evaluation splits.
2. **Zenodo Curated Email Collection (Champa et al., 2024) - Selected External Cohorts:**  
   *Justification:* Provides cleanly formatted CSVs with message body text. However, must **exclude Enron.csv and Nazario.csv** (which match our training sources) and strictly use independent sub-corpora (such as CEAS 2008 and Nigerian Fraud).
