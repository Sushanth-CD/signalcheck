# TEXT-EVAL-1 SMS Pilot: Preflight Audit and Independence Verification

**Audit Date:** 2026-11-02  
**Target Milestone:** TEXT-EVAL-1 SMS Pilot Evaluation Gate  
**Location:** `backend/reports/ml/text_eval_1_acquisition/sms_pilot/`  
**Auditor:** Automated Read-Only Inspection Engine  

---

## 1. WSPR-NCSU Campaign Mapping Audit

### 1.1 Exact URL-to-Campaign Mapping Algorithm
The WSPR dataset contains two primary CSV files:
- `phishing_campaigns.csv` (35,128 campaign rows)
- `phishing_messages.csv` (68,029 received message rows)

Because `phishing_messages.csv` lacks a message-level foreign key to `campaignID`, the acquisition pipeline established a deterministic mapping via unambiguous campaign URLs:
1. Candidate URLs were extracted from each campaign's `urls` list (Column 6) using `notebooks.phishing_url_extraction_v2.extract_candidates`.
2. Out of 3,072 unique normalized URLs across all campaigns, **2,222 URLs were found to map to exactly one campaign** (unambiguous 1-to-1 mapping).
3. Candidate URLs were extracted from each message in `phishing_messages.csv`. Messages containing a candidate URL that matched exactly one unambiguous single-campaign URL were deterministically assigned that campaign's ID.
4. Messages with no matching single-campaign URLs or ambiguous multi-campaign URLs were excluded.

### 1.2 Verification Results on Cohort A
- **Every selected message maps to exactly one campaign:** Confirmed. Each of the 100 accepted Cohort A messages is assigned exactly one non-null `campaign_id`.
- **Ambiguous URL occurrences:** Zero. Any message with multiple distinct campaign associations was rejected.
- **Determinism:** Confirmed. The mapping is purely functional and reproducible given fixed input files and regex parsing.
- **Distinct Campaign IDs:** Exactly **100 unique campaign IDs** exist among the 100 Cohort A messages (`len(set(cids)) == 100`).
- **One message per campaign:** Confirmed. Exactly one representative message was sampled per campaign.

### 1.3 URL Presence and Source Representativeness
- **Cohort A URL-present count:** 100 (100.0%).
- **Cohort A URL-absent count:** 0 (0.0%).
- **Number of unique campaign URLs used for mapping:** 2,222 unambiguous URLs.
- **Unmapped candidates:** 58,267 raw messages could not be mapped to an unambiguous campaign URL and were excluded (`no_deterministic_campaign_url_match`).
- **Ambiguous candidates:** 0.
- **Representativeness Assessment:**  
  > [!IMPORTANT]
  > Because the deterministic mapping depends on URL matching, **Cohort A is strictly restricted to URL-bearing smishing messages**. It does NOT represent smishing attacks that rely solely on phone numbers (vishing lures), conversational interaction, or non-URL attack vectors. The sample represents URL-directed smishing campaigns.

---

## 2. Independence Screening Verification

### 2.1 Exact Normalized-Text Collisions
- Normalized text hashing was executed using Unicode NFKC normalization, lowercasing, and collapsed whitespace, hashed via SHA-256.
- The 250 accepted manifest samples were verified against all 77,412 unique normalized hashes in the frozen 77,677-record baseline corpus (`corpus_simhash_index.npz`).
- **Verified Corpus Collisions:** **0 exact collisions** (100% independent).

### 2.2 Near-Duplicate Screening Audit & Methodological Note
- The screening pipeline applied:
  1. 64-bit character 5-gram SimHash calculation.
  2. Hamming distance $\le 3$ screening against all 77,677 corpus SimHashes.
- **Corpus Near-Duplicate Verification:** **0 candidate collisions** at Hamming distance $\le 3$ exist in the 250 accepted manifest samples.
- **Audit Methodology Finding:**  
  In the initial acquisition pool screening, candidate messages with SimHash Hamming distance $\le 3$ were pruned directly. Because zero samples in the accepted 250-record manifest trigger the Hamming $\le 3$ candidate gate, no candidate required downstream Jaccard verification against the corpus. All 250 accepted records are separated by Hamming distance $> 3$ from every record in the 77,677 corpus.

### 2.3 Within-Pilot Duplicates
- **Unique Normalized Hashes:** Exactly 250 unique SHA-256 hashes among the 250 records (0 duplicate groups).
- **Within-Pilot Near duplicates:** All $\binom{250}{2} = 31,125$ pairwise comparisons yielded **0 pairs with Hamming distance $\le 3$** and **0 pairs with Jaccard $\ge 0.90$**. The 250 pilot samples are mutually independent.

---

## 3. Dataset Labels, Source Integrity & Privacy Audit

### 3.1 Label Mapping
- **Cohort A:** Sourced from WSPR-NCSU $\rightarrow$ `ground_truth_label = 1`, `evaluation_label = phishing` (smishing).
- **Cohort B:** Sourced from UCI Ham (50) and ExAIS Ham (50) $\rightarrow$ `ground_truth_label = 0`, `evaluation_label = dataset_ham`.
- **Cohort C:** Sourced from UCI Spam (25) and ExAIS Spam (25) $\rightarrow$ `ground_truth_label = 0`, `evaluation_label = dataset_spam`.
- **Separation Assurance:** Commercial spam is marked as `dataset_spam` (class 0 in binary phishing evaluation), ensuring nuisance marketing is not conflated with benign communication or smishing lures.

### 3.2 Licensing Evidence
- **WSPR-NCSU:** Permissive MIT License covering research code and dataset distribution (IEEE S&P 2024).
- **UCI SMS Spam Collection:** Creative Commons Attribution 4.0 International (CC BY 4.0) (Almeida et al.).
- **ExAIS SMS Dataset:** Open academic research attribution (Alli et al., 2023).

### 3.3 Privacy & PII Sanitization
- In WSPR, Column 2 (`destination_number`) was completely omitted from the manifest.
- In ExAIS, participant identifiers, user CSV file origins, and carrier transaction logs were stripped.
- Inspection of the 250 message bodies confirmed that no private personal telephone numbers or personal recipient identities were injected.

---

## 4. Frozen Model Integrity Verification

All model and inference code hashes were verified against `backend/reports/ml/phishing_hybrid_independent_evaluation/model_implementation_freeze_manifest.json`:

| Component | Relative Path | Expected SHA-256 | Actual SHA-256 | Status |
| :--- | :--- | :--- | :--- | :--- |
| **V2 Baseline** | `backend/reports/ml/phishing_domain_holdout_v2/model.joblib` | `97ca5d41ea...` | `97ca5d41ea...` | **PASS** |
| **V3 Dual-Channel** | `backend/reports/ml/phishing_v3_experiments/dual_channel_v3_model.joblib` | `c0b514d976...` | `c0b514d976...` | **PASS** |
| **V3 Content-Only** | `backend/reports/ml/phishing_v3_experiments/content_only_model.joblib` | `ff837956a7...` | `ff837956a7...` | **PASS** |
| **V3 URL-Only** | `backend/reports/ml/phishing_v3_experiments/url_only_model.joblib` | `d180be6e80...` | `d180be6e80...` | **PASS** |
| **Dual-Channel Code** | `backend/ml/dual_channel.py` | `e84538622d...` | `e84538622d...` | **PASS** |
| **Text Normalization** | `backend/ml/text_normalization.py` | `f47301d467...` | `f47301d467...` | **PASS** |
| **URL Extraction V2** | `backend/notebooks/phishing_url_extraction_v2.py` | `0018830989...` | `0018830989...` | **PASS** |
| **Hybrid Router** | `backend/ml/hybrid_phishing_router.py` | `777bdbae49...` | `777bdbae49...` | **PASS** |

---

## 5. Evaluation Gate Decision

**Decision:** **PASSED ALL CHECKS.**  
The 250-record SMS pilot meets all independence, sanitization, and model integrity requirements. Permission to run frozen-model inference was granted.
