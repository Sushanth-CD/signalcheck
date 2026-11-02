# SMS Source Inventory & Eligibility Assessment

**Milestone:** SMS-DEDICATED-TRAIN-1  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Directory:** `backend/reports/ml/sms_dedicated_train_1/`  

---

## 1. Candidate Source Overview

| Candidate Dataset | Raw Messages | Original Labels | Recoverable Semantics | Training Eligibility | Overlap Status with Baseline / Pilot |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WSPR-NCSU Phishing (2024)** | 68,029 messages across 35,128 campaigns | Gateway-verified smishing | High-threat malicious credential theft, fake delivery, banking smishing | **ELIGIBLE (Primary Smishing)** | Zero baseline corpus overlap; 100 pilot campaigns explicitly quarantined |
| **UCI SMS Spam Collection (2011)** | 5,574 messages | `ham` (4,827), `spam` (747) | Conversational benign chat (`ham`), commercial marketing (`spam`) | **CONDITIONALLY ELIGIBLE** | Severe baseline corpus overlap (Mishra & Soni); eligible only after exact/SimHash deduplication |
| **ExAIS SMS Dataset (2023)** | 5,240 messages | `ham` (2,890), `spam` (2,350) | Conversational personal chat (`ham`), commercial carrier promotions (`spam`) | **ELIGIBLE (Primary Benign & Spam)** | Fully independent of baseline; user metadata stripped; 100 pilot samples quarantined |
| **Mishra & Soni (2022)** | 5,971 messages | `ham` (4,844), `smishing` (638), `spam` (489) | Reconstructed 3-class ground truth | **INELIGIBLE / QUARANTINED** | Embedded directly inside 77,677 corpus; project labels conflated spam with smishing |

---

## 2. In-Depth Source Evaluation

### 2.1 Source 1: WSPR-NCSU SMS Phishing (IEEE S&P 2024)
- **Provenance:** North Carolina State University WSPR Lab (Aleksandr Nahapetyan et al.).
- **License:** Permissive MIT License.
- **Label Semantics:** 100% confirmed smishing verified by telecom network telemetry, APWG, and VirusTotal.
- **Sampling Strategy:** 1 message per distinct campaign.
- **Pilot Isolation:** All 100 campaign IDs represented in the 250-record SMS pilot were quarantined (`pilot_campaign_exclusion`).
- **Eligible Yield:** Exactly **1,400 messages** from **1,400 distinct attack campaigns** were selected.

### 2.2 Source 2: UCI SMS Spam Collection
- **Provenance:** Tiago Almeida & José María Gómez Hidalgo (ACM DocEng 2011).
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0).
- **Label Semantics:** Binary (`ham` vs. `spam`).
- **Overlap & Deduplication:** Over 2,000 records collided with Mishra & Soni in `combined_reduced.json` and were pruned.
- **Eligible Yield:**
  - `ham`: **1,250 clean independent records** passed exact SHA-256 and SimHash screening.
  - `commercial_spam`: **32 clean independent records** passed screening (almost all UCI spam had collided with Mishra & Soni).

### 2.3 Source 3: ExAIS SMS Spam Dataset
- **Provenance:** Federal University of Agriculture, Abeokuta (Alli et al., 2023).
- **License:** Research attribution.
- **Privacy & Telecom Sanitization:** Raw CSVs contained carrier metadata, user participant IDs (`USER 1` to `USER 20`), and carrier timestamps. All header metadata was discarded; only the message text and ground-truth label were extracted.
- **Label Semantics:** Nigerian carrier marketing (`spam`) and personal chats (`ham`).
- **Eligible Yield:**
  - `ham`: **1,250 records** across participants.
  - `commercial_spam`: **1,468 records** across participants.

### 2.4 Source 4: Mishra & Soni (Quarantined)
- **Status:** **QUARANTINED FROM DEVELOPMENT DATA.**
- **Reason:** Mishra & Soni records formed the contaminated portion of `combined_reduced.json`. Because original project labels naively mapped commercial spam to phishing, and because extensive overlap with UCI exists, these records are excluded from the development pool to guarantee clean label semantics.
