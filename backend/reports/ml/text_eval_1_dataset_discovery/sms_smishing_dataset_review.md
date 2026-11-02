# SMS and Smishing Dataset Review

**Milestone:** TEXT-EVAL-1  
**Scope:** In-Depth Provenance, Label Verification, and Independence Analysis of Candidate SMS Datasets  
**Status:** Read-Only Technical Review  
**Date:** November 2026  

---

## 1. Executive Summary

Mobile text phishing (smishing) represents a critical attack vector for social engineering. Evaluating existing phishing models on SMS messages requires datasets that distinguish **genuine smishing (credential harvesting, malicious APK drops, fraudulent payment prompts)** from **commercial advertising spam** and **benign transactional messages (OTPs, personal chats)**.

This review investigates four candidate SMS corpora, verifies their origin and license, and analyzes their overlap risk with our existing 77,677-record training corpus (`combined_reduced.json`).

---

## 2. Deep Dive: Candidate SMS Corpora

```
+---------------------------------------------------------------------------------------------------+
| CANDIDATE SMS / SMISHING DATASETS AT A GLANCE                                                     |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  1. WSPR-NCSU SMS Phishing (IEEE S&P 2024)                                                        |
|     - Size: ~300,000 messages | 1,000+ campaigns                                                  |
|     - Labels: 100% Malicious Smishing (Gateway-verified by VT & APWG)                            |
|     - Period: 2022 - 2024 | Provenance: NC State WSPR Lab                                        |
|     - Independence: EXCELLENT (Postdates our training corpus)                                     |
|                                                                                                   |
|  2. Mishra & Soni SMS Phishing Dataset (Mendeley Data 2022)                                        |
|     - Size: 5,971 messages | Labels: 4,844 Ham, 638 Smishing, 489 Spam                           |
|     - Distinguishes: 3-class (Ham vs Spam vs Smishing) with URL boolean flags                     |
|     - Independence: CRITICAL LEAKAGE WARNING (Integrated into combined_reduced.json)             |
|                                                                                                   |
|  3. UCI SMS Spam Collection (Almeida & Gómez Hidalgo 2011/2012)                                   |
|     - Size: 5,574 messages | Labels: 4,827 Ham, 747 Spam (Binary)                                |
|     - Provenance: Tiago Almeida (Univ. Campinas) & J. M. Gómez Hidalgo                            |
|     - Independence: MODERATE (Spam is generic; Ham is gold-standard benign SMS)                   |
|                                                                                                   |
|  4. IMC 2025 User-Reported Smishing (`reportsmishing`)                                           |
|     - Size: Thousands of consumer reports | Labels: Real-world Smishing                           |
|     - Period: 2024 - 2025 | Provenance: ACM IMC 2025                                              |
|     - Independence: EXCELLENT (Contemporary, active consumer lures)                              |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

### 2.1 Candidate 1: WSPR-NCSU SMS Phishing Dataset (IEEE S&P 2024)

- **Official Title:** On SMS Phishing Tactics and Infrastructure
- **Authors & Research Group:** Aleksandr Nahapetyan, Sathvik Prasad, Kevin Childs, Adam Oest, Yeganeh Ladwig, Alexandros Kapravelos, Bradley Reaves (WSPR Lab, North Carolina State University).
- **Publication Venue & Year:** IEEE Symposium on Security and Privacy (S&P), 2024.
- **Repository / Source:** [https://github.com/wspr-ncsu/sms-phishing](https://github.com/wspr-ncsu/sms-phishing)
- **Dataset Composition & Scale:**
  - Contains hundreds of thousands of raw SMS messages collected from mobile carrier gateways.
  - Sourced from feeds continuously verified as malicious phishing by VirusTotal and the Anti-Phishing Working Group (APWG).
  - Organized into over 1,000 distinct phishing campaigns with first-seen/last-seen timestamps and target brand taxonomy.
- **Label Semantics:**
  - Exclusively malicious SMS phishing (`100% smishing`).
  - Does not contain generic promotional marketing or non-malicious commercial spam.
- **Message Content & Link Characteristics:**
  - Includes full raw message text.
  - Contains modern evasive URLs (shorteners like `bit.ly`, `tinyurl`, dynamic DNS, cloud redirects, spoofed bank login paths).
  - Also captures message templates and telephone callback lures without embedded links.
- **Licensing & Research Rights:**
  - Open research artifact hosted on GitHub for academic reproducibility.
- **Independence & Evaluation Feasibility:**
  - **Independence: EXCELLENT.** Collected between 2022 and 2024, strictly postdating the creation of our project's base training corpus (`combined_reduced.json` was compiled prior to mid-2022).
  - **Requirement:** Because this dataset contains solely malicious smishing, it must be paired with an independent benign SMS baseline (e.g., UCI SMS Ham) for balanced evaluation.

---

### 2.2 Candidate 2: Mishra & Soni SMS Phishing Dataset (Mendeley Data 2022)

- **Official Title:** SMS PHISHING DATASET FOR MACHINE LEARNING AND PATTERN RECOGNITION
- **Authors & Institution:** Sandhya Mishra and Devpriya Soni (Jaypee Institute of Information Technology, Noida, India).
- **DOI & Platform:** [10.17632/f45bkkt8pr.1](https://doi.org/10.17632/f45bkkt8pr.1) on Mendeley Data (Published 2022).
- **Dataset Composition & Scale:**
  - Total records: **5,971 messages**.
  - **Ham (Benign):** 4,844 messages ($81.1\%$).
  - **Smishing (Malicious Phishing):** 638 messages ($10.7\%$).
  - **Spam (Generic Commercial):** 489 messages ($8.2\%$).
- **Label Definitions:**
  - Explicitly separates **Smishing** (aimed at stealing credentials, financial fraud, impersonating banks/delivery) from **Spam** (unsolicited commercial offers, lottery notices) and **Ham** (normal personal and transactional text).
  - Accompanied by extracted boolean flags: `URL` ($0/1$), `EMAIL` ($0/1$), `PHONE` ($0/1$).
- **Critical Finding — Independence & Training Corpus Collision:**
  - > [!CAUTION]
    > **CRITICAL DATASET LEAKAGE IDENTIFIED:**
    > Investigation of `ealvaradob/phishing-dataset` (the official Hugging Face source from which our training file `backend/data/raw/combined_reduced.json` was constructed) confirms that its SMS sub-dataset was directly imported from the Mishra & Soni Mendeley dataset (matching the exact counts of 5,971 total, 4,844 ham, 638 smishing, 489 spam).
    > 
    > Consequently, **the Mishra & Soni dataset CANNOT be used as an independent evaluation benchmark without strict, comprehensive deduplication.** Evaluating models on this dataset without filtering would violate evaluation integrity, as hundreds of these messages are already in our V2 training and validation partitions.

---

### 2.3 Candidate 3: UCI SMS Spam Collection (Almeida & Gómez Hidalgo 2011/2012)

- **Official Title:** SMS Spam Collection
- **Creators:** Tiago A. Almeida (Federal University of São Carlos / University of Campinas) and José María Gómez Hidalgo.
- **Reference Paper:** *Contributions to the Study of SMS Spam Filtering: New Collection and Results*, ACM DocEng 2011.
- **Official Repository:** UCI Machine Learning Repository (`id=228`).
- **Dataset Composition & Scale:**
  - Total records: **5,574 messages**.
  - **Ham (Benign):** 4,827 messages ($86.6\%$).
  - **Spam:** 747 messages ($13.4\%$).
- **Sub-Source Breakdown:**
  - Grumbletext UK user spam forum (425 spam).
  - National University of Singapore SMS Corpus (3,375 ham).
  - Caroline Tagg's PhD thesis SMS corpus (450 ham).
  - SMS Spam Corpus v.0.1 Big (1,002 ham, 322 spam).
- **Clarification on "Tiago Smishing Dataset":**
  - The phrase "Tiago smishing dataset" referred to in earlier prompts is a misnomer in colloquial literature referencing **Tiago A. Almeida's UCI SMS Spam Collection**.
  - It is **NOT** a dedicated "smishing" dataset. The labels are strictly binary: `ham` and `spam`.
  - While some spam messages in this corpus involve fake claims and fraudulent lottery lures, many are generic unsolicited SMS advertisements.
- **Suitability:**
  - The **Ham subset (4,827 messages)** remains the premier, widely accepted benchmark for benign, natural SMS messages. It is an ideal negative control for false positive testing.

---

### 2.4 Candidate 4: IMC 2025 User-Reported Smishing (`reportsmishing`)

- **Official Title:** Fishing for Smishing: Understanding SMS Phishing Infrastructure and Strategies by Mining Public User Reports
- **Publication Venue & Year:** ACM Internet Measurement Conference (IMC), 2025.
- **Repository / Source:** [https://github.com/reportsmishing/Smishing-Dataset-IMC25](https://github.com/reportsmishing/Smishing-Dataset-IMC25)
- **Dataset Composition:**
  - Curated collection of user-reported real-world SMS phishing attempts (`final_dataset_output.csv`).
  - Contains message text, reporting dates, target service tags, and sender identifiers.
- **Independence & Relevance:**
  - Excellent temporal independence (2024–2025). High real-world fidelity reflecting contemporary mobile social engineering tactics (package re-delivery scams, bank security alerts, toll payment scams).

---

## 3. Comparative Summary & Recommendation for SMS

| Dataset | Provenance Quality | Phishing Specificity | Independence from Training | Recommended Role in TEXT-EVAL-1 |
| :--- | :---: | :---: | :---: | :--- |
| **WSPR-NCSU (2024)** | High (IEEE S&P, carrier gateway) | High (100% phishing) | **100% Independent (2022–2024)** | **Primary Malicious Smishing Test Cohort** |
| **UCI SMS Ham (2011)** | High (UCI, academic thesis) | N/A (Benign only) | Moderate (Needs SimHash check) | **Primary Benign Ham Control Cohort** |
| **IMC 2025 Smishing** | High (ACM IMC 2025) | High (User reports) | **100% Independent (2024–2025)** | **Secondary / Validation Smishing Cohort** |
| **Mishra & Soni (2022)** | High (Mendeley Data) | High (3-class) | **Severe Collision (In training data)** | **Quarantined (Used only for leakage audit)** |
