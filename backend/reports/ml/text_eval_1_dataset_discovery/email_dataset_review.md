# Email Dataset Review

**Milestone:** TEXT-EVAL-1  
**Scope:** In-Depth Provenance, Format Verification, and Independence Analysis of Candidate Email Datasets  
**Status:** Read-Only Technical Review  
**Date:** November 2026  

---

## 1. Executive Summary

Evaluating phishing detection models on email text requires realistic email corpora that represent both benign corporate/personal correspondence and deceptive phishing lures. Because our base training corpus (`combined_reduced.json`) drew heavily from classic email sources, ensuring **strict source independence** is the single greatest methodological challenge in email evaluation.

This review evaluates the three most prominent public email benchmark options:
1. **IWSPA-AP (Anti-Phishing Shared Task Benchmark)**
2. **Zenodo Curated Phishing Email Datasets (Champa et al., 2024)**
3. **Apache SpamAssassin Public Corpus**

---

## 2. Deep Dive: Candidate Email Corpora

```
+---------------------------------------------------------------------------------------------------+
| CANDIDATE EMAIL DATASETS AT A GLANCE                                                              |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  1. IWSPA-AP (Anti-Phishing Shared Task 2018 / 2020)                                              |
|     - Size: ~10,000 emails per version | Realistic imbalanced ratio (~90% benign, ~10% phishing)  |
|     - Provenance: ACM CODASPY / ReDAS Lab (Univ. of Houston)                                      |
|     - Formats: Clean message bodies (plain text & HTML stripped) and full headers                 |
|     - Independence: EXCELLENT (Separate shared task benchmark, unbundled from Hugging Face)       |
|                                                                                                   |
|  2. Zenodo Phishing Email Curated Collection (Champa et al., 2024 - DOI: 10.5281/zenodo.8339691)   |
|     - Size: 11 distinct CSV sub-corpora (>100,000 emails)                                        |
|     - Subsets: Enron, Nazario, SpamAssassin, CEAS 2008, Ling, Nigerian Fraud, TREC 2005           |
|     - Formats: Standardized CSV (`sender`, `receiver`, `date`, `subject`, `body`, `label`)        |
|     - Independence: MIXED / DANGEROUS (Enron & Nazario match our training sources; CEAS is fresh)|
|                                                                                                   |
|  3. Apache SpamAssassin Public Corpus (2002–2006)                                                 |
|     - Size: ~6,000 raw MIME emails (`easy_ham`, `hard_ham`, `spam`)                               |
|     - Provenance: Apache Software Foundation                                                      |
|     - Independence: POOR (Heavily re-used and included in multiple training aggregators)          |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

### 2.1 Candidate 1: IWSPA-AP (Anti-Phishing Shared Task Benchmark)

- **Official Title:** International Workshop on Security and Privacy Analytics – Anti-Phishing Shared Task (IWSPA-AP).
- **Organizers & Institutions:** ReDAS Lab, University of Houston, co-located with ACM Conference on Data and Applications Security and Privacy (CODASPY).
- **Publication Years:** 2018 (V1.0) and 2020 (V2.0).
- **Dataset Composition & Scale:**
  - Designed explicitly to evaluate NLP and ML algorithms on phishing detection under realistic operational conditions.
  - Features an **unbalanced class distribution** reflecting enterprise mail flow: approximately **$90\%$ Benign (Ham)** and **$10\%$ Phishing**.
  - Total volume: ~10,000 emails in the benchmark task.
- **Data Formats Available:**
  - Provided in two parallel tracks:
    1. **Body-Only Track:** Clean, extracted message body text (with HTML tags stripped or retained, suitable for pure text classifiers).
    2. **Full-Header Track:** Complete RFC 2822 email messages with full transmission headers (`Received`, `DKIM`, `SPF`, `From`, `Subject`).
- **Phishing vs. Generic Spam:**
  - Focuses exclusively on **deceptive phishing** (credential theft, impersonation, CEO fraud, malicious attachment lures). Non-malicious commercial spam is separated or filtered out.
- **Independence & Evaluation Feasibility:**
  - **Independence: EXCELLENT.** IWSPA-AP was maintained as a closed shared task competition corpus. It was **NOT** bundled into the `ealvaradob/phishing-dataset` repository on Hugging Face.
  - V1.0 data and associated participant baseline scripts are publicly available on GitHub.

---

### 2.2 Candidate 2: Zenodo Phishing Email Curated Collection (Champa et al., 2024)

- **Official Title:** Phishing Email Curated Datasets
- **Authors & Institutions:** Arifa Islam Champa, Md Fazle Rabbi, Minhaz F. Zibran (University of Idaho / Fort Hays State University).
- **DOI & Platform:** [10.5281/zenodo.8339691](https://doi.org/10.5281/zenodo.8339691) on Zenodo (March 2024).
- **Reference Papers:**
  - *Curated datasets and feature analysis for phishing email detection with machine learning*, IEEE ICMI 2024.
  - *Why phishing emails escape detection: A closer look at the failure points*, ISDFS 2024.
- **Dataset Structure & Available Files:**
  - The repository compiles 11 distinct public email sub-datasets into a standardized CSV schema (`sender`, `receiver`, `date`, `subject`, `body`, `label`):
    1. `Enron.csv` (Benign corporate emails from Enron)
    2. `Nazario.csv` & `Nazario_5.csv` (Jose Nazario phishing corpus)
    3. `SpamAssasin.csv` (Apache SpamAssassin corpus)
    4. `CEAS_08.csv` (Collaboration Against Spam 2008 conference corpus)
    5. `Ling.csv` (Linguistics mailing list corpus)
    6. `Nigerian_Fraud.csv` & `Nigerian_5.csv` (419 advance-fee fraud emails)
    7. `TREC_05.csv` (TREC 2005 spam track)
- **Critical Finding — Training Corpus Contamination Risk:**
  - > [!WARNING]
    > **SOURCE LEAKAGE AUDIT:**
    > As confirmed in our investigation of `ealvaradob/phishing-dataset`, the email subset of our training file `backend/data/raw/combined_reduced.json` was constructed from **Enron** (supplying the benign emails) and **Nazario** (supplying the phishing emails).
    > 
    > If we evaluate against `Enron.csv` or `Nazario.csv` from this Zenodo collection, we would be re-testing records that directly overlap with our V2 training partition.
    > 
    > **Safe Path Forward:** The Zenodo collection remains valuable **provided that we strictly quarantine `Enron.csv` and `Nazario.csv`**, and utilize only the genuinely independent sub-corpora:
    > - `CEAS_08.csv` (Independent conference benchmark)
    > - `Nigerian_Fraud.csv` (High-deception advance-fee phishing/fraud)

---

### 2.3 Candidate 3: Apache SpamAssassin Public Corpus

- **Official Source:** Apache SpamAssassin project archives.
- **Period:** 2002–2006.
- **Scale:** ~6,000 messages.
- **Composition:** `easy_ham` (2,500), `hard_ham` (250), `spam` (500), `spam_2` (1,397).
- **Limitations:**
  - Very old (over 20 years old). Text styling, formatting, and link conventions do not reflect contemporary email lures (e.g., modern cloud redirects, CSS button layouts, QR codes).
  - Heavy overlap with secondary datasets; extensively duplicated across public repositories.
  - Does not distinguish generic commercial spam from targeted phishing.

---

## 3. Comparative Summary & Recommendation for Email

| Dataset | Provenance & Quality | Message Format | Independence from Training | Recommended Role in TEXT-EVAL-1 |
| :--- | :---: | :---: | :---: | :--- |
| **IWSPA-AP (Shared Task)** | High (ACM CODASPY / ReDAS) | Plain text bodies & full MIME | **100% Independent** | **Primary Email Benchmark (Rank 1)** |
| **Zenodo CEAS 2008 Sub-Corpus** | High (Champa et al., IEEE 2024) | Standardized CSV with `body` | **Independent (Non-Enron/Nazario)** | **Secondary Email Benchmark (Rank 2)** |
| **Zenodo Enron & Nazario Subsets** | High | Standardized CSV | **SEVERE COLLISION (In training data)** | **Quarantined (Used for leakage audit)** |
| **SpamAssassin Public Corpus** | Moderate | Raw MIME | Poor / Generic Spam | Not recommended for standalone phishing eval |
