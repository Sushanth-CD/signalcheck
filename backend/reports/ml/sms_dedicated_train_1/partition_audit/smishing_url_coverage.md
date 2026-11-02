# WSPR-NCSU Candidate Limitation: URL Coverage Analysis

**Milestone:** SMS-DEDICATED-TRAIN-1 Partition Quality Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/`  

---

## 1. Quantitative URL Coverage in WSPR Candidates

We audited the 1,400 smishing messages selected from WSPR-NCSU:

- **Total Smishing Candidates:** 1,400 messages across 1,400 distinct attack campaigns.
- **URL-Present Smishing Messages:** **1,400 (100.0%)**.
- **URL-Absent Smishing Messages:** **0 (0.0%)**.
- **Distinct Campaigns Represented:** Exactly 1,400 distinct campaign IDs.

```
Smishing Candidate Breakdown:
├── URL-Present Smishing : 1,400 messages (1,400 unique campaigns) [100%]
└── URL-Absent Smishing  :     0 messages (    0 unique campaigns) [  0%]
```

---

## 2. Root Cause of 100% URL Presence

In the official WSPR dataset (`wspr-ncsu/sms-phishing`), messages lack an explicit foreign key column linking them directly to a campaign ID.

To enforce the non-negotiable project requirement that **every message must deterministically map to exactly one attack campaign**, the ingestion pipeline mapped candidate URLs extracted from message bodies to unambiguous single-campaign URLs.

Because a message could only be deterministically assigned to a campaign if it contained an unambiguous URL, **any message lacking an extractable URL could not be mapped to a campaign and was excluded**.

---

## 3. Operational Implications: What the Proposed Model Will and Will Not Detect

### 3.1 What the Model WILL Be Trained to Detect:
1. **Link-Directed Credential Phishing:** Attack lures impersonating banks, postal carriers (DHL, USPS, Evri, Chronopost), tax authorities, and SaaS platforms directing victims to web harvesting portals.
2. **Slashed and Obfuscated URLs:** Messages using shorteners (`bit.ly`, `tinyurl.com`, `t.co`) or punctuation evasion (`01161191684/visit: urlzs.com/g1ux5`).
3. **Conversational Pretext with Destination Links:** Delivery notices and security alerts containing urgency pretexts followed by HTTP/HTTPS destinations.

### 3.2 What the Model WILL NOT Be Trained to Detect:
1. **Pure Voice Phishing (Vishing) Lures:** Messages urging victims exclusively to call a toll-free or premium phone number (e.g., *"Urgent: Call 1-800-XXX-XXXX to unlock your debit card"*).
2. **Interactive Scam Outreach ("Wrong Number" / Pig Butchering):** Initial conversational hooks (e.g., *"Hi Anna, are we still meeting for coffee today?"*) that initiate human interaction without an immediate link.
3. **Pure Reply-Back Smishing:** Messages instructing the recipient to reply with OTP codes or personal details via SMS.

> [!IMPORTANT]
> **Architectural Transparency:**  
> The proposed SMS model is a **link-directed smishing detector**. It will provide robust protection against link-based credential phishing campaigns, but should be supplemented with conversational heuristic engines or phone-number threat intelligence to counter non-URL vishing threats.
