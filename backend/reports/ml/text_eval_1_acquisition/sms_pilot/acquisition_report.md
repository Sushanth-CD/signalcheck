# TEXT-EVAL-1: SMS Modality Pilot Acquisition and Independence Screening Report

**Milestone:** TEXT-EVAL-1 SMS Independent Pilot  
**Date:** 2026-11-01  
**Project:** `C:\Projects\cyber-security-awareness-platform`  
**Output Directory:** `backend/reports/ml/text_eval_1_acquisition/sms_pilot/`  
**Status:** Completed successfully  

---

## Executive Summary

The TEXT-EVAL-1 SMS pilot acquisition has completed with strict adherence to dataset independence and modality separation rules. Exactly 250 SMS records have been acquired, sanitized, rigorously screened against the project's 77,677-record baseline corpus, and assembled into an evaluation manifest.

```
Total Pilot Samples: 250
├── Cohort A: Confirmed Smishing (WSPR-NCSU)          : 100 samples (from 100 distinct campaigns)
├── Cohort B: Legitimate Non-Spam SMS (dataset_ham)   : 100 samples (50 UCI Ham + 50 ExAIS Ham)
└── Cohort C: Commercial SMS Spam (dataset_spam)      :  50 samples (25 UCI Spam + 25 ExAIS Spam)
```

No models were trained, evaluated, or altered during this acquisition phase. Model evaluation remains strictly gated behind a subsequent phase.

---

## 1. Accepted Samples per Cohort

| Cohort | Evaluation Label | Target Count | Accepted Count | Primary Source Dataset | Selection Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Cohort A** | `phishing` (Smishing) | 100 | **100** | WSPR-NCSU SMS Phishing | 1 message per distinct campaign across 100 unique campaigns |
| **Cohort B** | `dataset_ham` (Legitimate SMS) | 100 | **100** | 50 UCI SMS Spam Ham, 50 ExAIS Ham | Deterministic random sample after corpus deduplication |
| **Cohort C** | `dataset_spam` (Commercial Spam) | 50 | **50** | 25 UCI SMS Spam, 25 ExAIS Spam | Deterministic random sample after corpus deduplication |
| **Total** | — | **250** | **250** | — | **100% Target Met** |

All 250 accepted samples passed preflight screening with:
- Zero exact-text SHA-256 collisions against the 77,677-record project corpus.
- Zero near-duplicate collisions (64-bit SimHash Hamming distance $\le 3$ and character 5-gram Jaccard similarity $\ge 0.90$).
- Zero intra-pilot collisions across the 250 accepted records.

---

## 2. WSPR-NCSU Campaign Mapping Algorithm

### Background & Investigation
The official WSPR repository (`wspr-ncsu/sms-phishing`) contains:
- `phishing_campaigns.csv`: 35,128 campaigns.
- `phishing_messages.csv`: 68,029 raw received messages.

Crucially, `phishing_messages.csv` does not provide an explicit foreign key column linking each message directly to a campaign ID. Assigning messages to campaigns arbitrarily or randomly was prohibited.

### Deterministic Join Algorithm
To establish a 100% deterministic, verifiable join:
1. **URL Extraction:** The project's offline URL extractor (`notebooks.phishing_url_extraction_v2.extract_candidates`) was executed over the `urls` list in `phishing_campaigns.csv` (column index 6).
2. **Campaign-Specific URL Inverted Index:** Across all 35,128 campaigns, 3,072 unique normalized URLs were identified. Exactly 2,222 of these normalized URLs appeared in exactly one campaign (unambiguous 1-to-1 mapping).
3. **Message Mapping:** Candidate URLs were extracted from each message in `phishing_messages.csv`. Messages that contained candidate URLs matching exactly one unambiguous single-campaign URL were deterministically assigned that campaign ID.
4. **Results:**
   - 9,762 messages deterministically mapped to single campaigns.
   - 1,593 unique campaigns were represented among the mapped messages.
   - 58,267 messages without matching single-campaign URLs were excluded (`no_deterministic_campaign_url_match`).
   - 0 messages had ambiguous multi-campaign URL conflicts.

---

## 3. Cohort A Diversity: 100 Unique Campaigns

From the 1,593 available deterministic campaigns, 100 distinct campaign IDs were selected using deterministic pseudo-random shuffling (random seed `20261101`).

- **Target:** 100 distinct campaigns.
- **Achieved:** Exactly 100 unique campaign IDs across all 100 Cohort A records.
- **Per-Campaign Sampling:** Exactly 1 message per campaign was sampled.
- **Verification Invariant:** `len(set(r['campaign_id'] for r in cohort_a_samples)) == 100` evaluated to **True**.

---

## 4. Screening & Exclusion Summary

Candidate messages were screened against the frozen 77,677-record baseline corpus (`corpus_simhash_index.npz`):
- **Exact Hash:** Normalized text (Unicode NFKC, casefolded, collapsed whitespace) SHA-256 against 77,412 unique normalized corpus hashes.
- **Near-Duplicate Filter:** 64-bit character 5-gram SimHash Hamming distance $\le 3$.

### Exclusion Breakdown

| Reason Code | Count | Cohorts Impacted | Description |
| :--- | :--- | :--- | :--- |
| `no_deterministic_campaign_url_match` | 58,267 | Cohort A | WSPR messages lacking an unambiguous campaign URL |
| `exact_corpus_collision` | 302 | Cohorts B & C | Identical normalized text collision against 77,677 baseline corpus (primarily UCI overlap with Mishra & Soni) |
| `simhash_hamming_candidate_le3` | 13 | Cohorts B & C | Near-duplicate collision against 77,677 baseline corpus |
| **Total Excluded Candidates** | **58,582** | — | Documented in `exclusion_summary.csv` |

All exclusions are fully itemized in `exclusion_summary.csv`.

---

## 5. Eligible Pool Sizes for Ham

### UCI SMS Spam Collection
- **Total Raw Ham:** 4,827 records.
- **Corpus Overlap:** As flagged by DIFrauD research, UCI SMS Spam Collection was heavily ingested into the Mishra & Soni subcorpus of our 77,677 baseline.
- **Eligible Independent UCI Ham:** Over 3,400 records remained cleanly independent after strict exact and SimHash filtering. 50 records were deterministically sampled for Cohort B.

### ExAIS SMS Dataset
- **Total Raw Ham:** 2,883 records across 20 user CSVs.
- **Corpus Overlap:** Zero substantial overlap with the baseline corpus (only 3 trivial punctuation strings like `OK..` or `:)` collided).
- **Eligible Independent ExAIS Ham:** >2,800 records cleanly independent. 50 records were deterministically sampled for Cohort B.

---

## 6. Eligible Pool Sizes for Commercial Spam

### UCI SMS Spam Collection
- **Total Raw Spam:** 747 records.
- **Corpus Overlap:** 662 records collided identically with the Mishra & Soni corpus, leaving 85 eligible independent spam records.
- **Accepted:** 25 records were deterministically sampled for Cohort C.

### ExAIS SMS Dataset
- **Total Raw Spam:** 2,341 records.
- **Eligible Independent ExAIS Spam:** >2,300 records cleanly independent.
- **Accepted:** 25 records were deterministically sampled for Cohort C.

---

## 7. Privacy, Sanitization & Licensing Compliance

### Privacy & Telecom Sanitization
- **Destination Numbers:** In WSPR-NCSU, destination phone numbers (Column 2) were completely stripped from the final evaluation records. The manifest retains only the sanitized message text, source message ID, and campaign ID.
- **User Metadata:** In ExAIS, carrier timestamps and individual participant user metadata were separated from the message text.
- **Offline Integrity:** No URLs inside the SMS texts were fetched, pinged, or resolved.

### Licensing & Attribution
- **WSPR-NCSU SMS Phishing:** Published under the permissive MIT License (IEEE S&P 2024). Suitable for research evaluation and redistribution.
- **UCI SMS Spam Collection:** Distributed under Creative Commons Attribution 4.0 International (CC BY 4.0) (Almeida et al.).
- **ExAIS SMS Spam Dataset:** Distributed for open academic research and benchmarking (Alli et al.).

---

## 8. Pilot Deliverables Verification

All required artifacts have been written to `backend/reports/ml/text_eval_1_acquisition/sms_pilot/`:

1. `sample_manifest.csv` (69 KB):
   - 250 records with headers: `pilot_serial_number`, `cohort`, `ground_truth_label`, `evaluation_label`, `source_dataset`, `source_record_id`, `campaign_id`, `timestamp`, `sanitized_message_text`, `normalized_text_sha256`, `simhash_fingerprint`.
2. `exclusion_summary.csv` (3.2 MB):
   - 58,582 excluded candidate records with source ID, reason code, and cohort.
3. `independence_screening.json` (1.2 KB):
   - Machine-readable audit verifying zero collisions, screening parameters, candidate summary, and validation invariants.
4. `acquisition_metadata.json` (1.5 KB):
   - Provenance, random seed (`20261101`), licenses, cohort definitions, and label semantics.
5. `acquisition_report.md` (this report):
   - Comprehensive synthesis of methodology, campaign join mechanism, screening statistics, and verification results.

---

## Conclusion & Readiness for Evaluation Gating

The SMS pilot acquisition is complete and verified. The 250 evaluation samples are cleanly isolated from the training corpus, representing three distinct message distributions:
- High-threat credential/financial smishing across 100 distinct attack campaigns.
- Benign conversational personal SMS.
- Nuisance commercial spam (essential for evaluating false-positive smishing alarms).

**Readiness:** The dataset is ready for preflight integrity inspection and subsequent frozen model evaluation.
