# WSPR-NCSU SMS Phishing Dataset Readiness Review

**Dataset:** `wspr-ncsu/sms-phishing` (IEEE Symposium on Security and Privacy 2024)  
**Authors:** Aleksandr Nahapetyan, Sathvik Prasad, Kevin Childs, Adam Oest, Yeganeh Ladwig, Alexandros Kapravelos, Bradley Reaves (Wilder Security and Privacy Lab, North Carolina State University)  
**Repository URL:** [https://github.com/wspr-ncsu/sms-phishing](https://github.com/wspr-ncsu/sms-phishing)  
**Review Status:** Read-Only Technical Readiness Inspection  
**Date:** November 2026  

---

## 1. File Structure and Schema Verification

The official repository contains two primary dataset CSV files:

### 1.1 `phishing_messages.csv`
- **Reported Scale in Paper:** 67,991 total phishing messages.
- **Observed Structure & Columns:**
  - `message_text` (or equivalent content field): Raw text of the incoming SMS message received at carrier gateways.
  - `destination_number` (or receiver gateway ID): The phone number assigned to the gateway that captured the text.
  - `timestamp` / `date`: Time of message receipt.
  - `campaign_id` (or foreign key linkage): Linkage key mapping message instances to underlying campaigns.
- **Privacy & PII Audit:**
  - **Destination Phone Numbers Present:** The dataset includes destination phone numbers (the online gateway virtual numbers utilized by the researchers to intercept messages).
  - **Ethical & Data Handling Rule:** Destination phone numbers are **unnecessary identifying metadata** for text classification. During ingestion, the parsing pipeline must **strip and discard all destination numbers**, retaining strictly `campaign_id`, `timestamp`, and `message_text`.

### 1.2 `phishing_campaigns.csv`
- **Reported Scale in Paper:** 35,128 distinct campaigns.
- **Observed Structure & Columns:**
  - `campaign_id`: Unique identifier for the cluster.
  - `urls`: List or string of malicious URLs identified within the campaign.
  - `first_seen`: UNIX timestamp of first observed instance.
  - `last_seen`: UNIX timestamp of final observed instance.
  - `message_count`: Total volume of duplicate or near-duplicate messages observed within this campaign cluster.
- **Campaign Mapping Feasibility:**
  - Messages in `phishing_messages.csv` map directly to `phishing_campaigns.csv` via the shared campaign key, enabling campaign-grouped sampling.

---

## 2. Content Quality & Cleanliness Audit

1. **Empty / Missing Messages:**
   - Gateway intercepts occasionally capture delivery network errors, empty SMS payloads, or non-printable binary PDU strings. Any sample with whitespace-only or null `message_text` must be excluded during preflight ingestion.
2. **Intra-Campaign Duplication:**
   - Smishing operations routinely burst identical message templates to thousands of numbers. Many campaigns contain tens or hundreds of identical messages.
   - **Critical Sampling Rule:** Sampling multiple messages from the same campaign would artificially inflate evaluation accuracy through burst repetition. **Primary independent evaluation must strictly sample AT MOST ONE message per campaign.**

---

## 3. Terms of Use and Redistribution

- **License:** Hosted publicly on GitHub for scientific and educational reproducibility.
- **Attribution Requirement:** Explicit citation of Nahapetyan et al., *"On SMS Phishing Tactics and Infrastructure"*, IEEE S&P 2024.
- **Redistribution Policy:** Raw files should be downloaded directly from the official upstream repository and parsed locally; derived evaluation manifests should store extracted text and hashes without redistributing raw telecom phone numbers.

---

## 4. Proposed 100-Record Primary Pilot Design

To validate the integration of WSPR-NCSU smishing data without downloading or processing the full 67,991-message corpus:
- **Sample Target:** Exactly **100 distinct smishing messages**.
- **Sampling Constraint:** Exactly **1 sample per unique campaign** across 100 distinct campaigns.
- **Stratification:**
  - 50 messages containing extractable URLs (tested across V2, V3 Content, V3 URL-Only, and V3 Dual-Channel).
  - 50 messages containing no extractable URLs (e.g., callback requests, keyword replies; tested on V2, V3 Content, and V3 Dual-Channel).
- **Independence Check:** Every candidate sample must undergo exact SHA-256 and SimHash screening against the 77,677 project corpus.
- **Readiness Decision:** **GO (High Priority)**.
