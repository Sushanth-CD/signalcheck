# Dataset Eligibility and Independence Audit Framework

**Document Version:** 1.0.0  
**Audit Purpose:** Define mandatory cryptographic, lexical, domain, and temporal independence checks required before any external record is admitted to the independent evaluation partition.  
**Target Policy:** Zero data leakage and zero correlation with V2/V3 training ($n = 9,481$) and validation ($n = 2,005$) representatives.

---

## 1. Cryptographic Exact-Match & Text Deduplication

Every candidate candidate record $r$ with text $T_r$ must undergo deterministic normalization:
$$N(T_r) = \text{regex\_replace}(\text{casefold}(\text{NFKC}(T_r)), \text{r"\s+"}, \text{" "}).\text{strip}()$$
$$H(T_r) = \text{SHA-256}(N(T_r))$$

### Rejection Rule 1 (Exact Hash Collision):
* Let $\mathcal{H}_{\text{train}}$ and $\mathcal{H}_{\text{val}}$ be the sets of normalized text hashes in the V2 training and validation partitions ($11,486$ distinct hashes).
* If $H(T_r) \in \mathcal{H}_{\text{train}} \cup \mathcal{H}_{\text{val}}$, the record is **REJECTED IMMEDIATELY** with reason `exact_text_collision_with_existing_corpus`.
* Additionally, check against all $77,568$ unique text hashes in `combined_reduced.json`. Any match to quarantined, uncertain, or no-destination records is also quarantined.

---

## 2. Near-Duplicate Leakage Screening (SimHash & MinHash Jaccard)

Phishing campaigns frequently generate randomized template variants (e.g., swapping a random token, timestamp, or greeting) while sharing identical body structures.

### Rejection Rule 2 (High Lexical Similarity):
* Compute 5-shingle MinHash / 64-bit SimHash over normalized word tokens.
* Candidate records exhibiting a Jaccard similarity $J(S_r, S_{\text{train}}) \ge 0.85$ or Hamming distance $\le 3$ with any training or validation record must be **EXCLUDED** under `near_duplicate_training_leakage`.

---

## 3. Registrable-Domain Holdout Verification

A core design principle of Phishing Classifier V2/V3 is unseen-destination domain generalization. Evaluating models on destination domains seen during training measures memorization rather than detection capability.

### Extraction & Normalization of Candidate Destinations:
* For each candidate record, execute `extract_candidates(record_id, text)` from `backend/notebooks/phishing_url_extraction_v2.py`.
* Query the pinned Oracle JDK Public Suffix List (`backend/ml/psl_service.py`) to extract the canonical registrable domain $D_r$ (or canonical IPv4/IPv6 literal $I_r$).

### Rejection Rule 3 (Known Training Destination Domain):
* Let $\mathcal{D}_{\text{train}}$ be the set of all accepted registrable domain keys ($38,764$ unique domains) and $\mathcal{I}_{\text{train}}$ be the set of IP keys ($208$ unique IPs) present in the training components.
* If any candidate destination domain $D_r \in \mathcal{D}_{\text{train}}$ or $I_r \in \mathcal{I}_{\text{train}}$, the record cannot be admitted as an unseen-destination benchmark.
* **Resolution:** Such records must be flagged as `known_training_domain_contamination` and placed into a secondary diagnostic cohort, never the primary independent evaluation score.

---

## 4. Temporal & Provenance Isolation

### Rejection Rule 4 (Contemporaneous or Pre-Existing Overlap):
* `combined_reduced.json` represents collections assembled prior to late 2026.
* Any dataset sourced from unverified aggregations from the same collection window (e.g., common 2018–2020 Kaggle scrapers) carries high risk of uncredited overlap.
* Preferred candidate datasets must document:
  - Timestamp of feed acquisition.
  - Active verification status (e.g., live crawler status code $200$ OK at collection time).
  - Independent label confirmation (e.g., multi-engine consensus or verified takedown notice for phishing; verified enterprise certificate / Tranco ranking for benign).

---

## 5. Label Provenance & Ground-Truth Verification

| Threat Type | Minimum Verification Standard for Independent Evaluation |
|---|---|
| **Phishing Class (Label 1)** | Confirmed by at least two independent intelligence feeds (e.g., PhishTank verified + OpenPhish + VirusTotal $\ge 5$ vendor detections) OR direct analyst inspection of credential-harvesting form elements. Unverified spam or marketing emails must NOT be labeled as phishing. |
| **Benign Class (Label 0)** | Tranco Top-10k domain destination OR verified corporate internal correspondence / verified public newsletters with valid DKIM/SPF provenance. |

---

## 6. Audit Pipeline Checklist

Before calculating independent metrics, the following automated audit script must output `ELIGIBILITY_PASS`:

```
[ ] 1. Schema Validation: Record contains unique source_id, raw_text, verified_label in {0, 1}.
[ ] 2. Cryptographic Check: Zero collisions with train/val normalized text SHA-256 hashes.
[ ] 3. Near-Duplicate Check: Zero candidates with shingle Jaccard similarity >= 0.85 to train.
[ ] 4. Domain Holdout Check: All extracted destination keys checked against JDK PSL training keys.
[ ] 5. Modality Tagging: Record deterministically tagged as HTML, short_url, or text.
[ ] 6. Zero Network Access: All preprocessing, parsing, and PSL lookups executed strictly offline.
```
