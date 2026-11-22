# Independent Dataset Candidate Review for Phishing Classifier Evaluation

**Review Date (UTC):** 2026-10-31  
**Status:** Pre-evaluation Source Review (Phase 2)  
**Scope:** Identify external phishing and benign datasets for independent, uninspected evaluation of Hybrid Policy 3 and Policy 4.

---

## 1. Baseline Corpus Context & Exclusion Boundaries

The existing models (V2 and V3 variants) were trained and validated on partitions of:
* **`backend/data/raw/combined_reduced.json`** (77,677 total records; 44,975 label 0, 32,702 label 1).
* As established in the dataset audit, `combined_reduced.json` is a composite corpus containing:
  - Webpage HTML snapshots.
  - Raw URL records (drawn from common public phishing feeds such as OpenPhish/PhishTank).
  - Newsletter, promotional spam, and plain text corpora (such as Enron spam and SMS spam).
* **Strict Independence Rule:** Any candidate dataset must be verified against all 77,677 records in `combined_reduced.json` to ensure zero training/validation contamination, zero text duplication, and zero domain holdout leakage.

---

## 2. Review of Available External Benchmark Datasets

We evaluated five prominent candidate sources against six rigorous criteria:
1. Label provenance and annotation confidence.
2. Representation of both HTML bodies and bare URLs.
3. Availability of collection timestamps and origin metadata.
4. Absence of known overlap with the training corpus.
5. Permissive research-use licensing.
6. Feasibility of domain-level leakage filtering.

| Candidate Dataset | Modality & Contents | Stated Label Schema | Provenance & Dates | Research Use Terms | Overlap Risk with Training Corpus | Suitability Rating |
|---|---|---|---|---|:---:|:---:|
| **1. Nazario Phishing Corpus (`phishing0` - `phishing3`) + Enron Clean** | Full MIME email messages (HTML, headers, body, embedded links) | Binary (1 = Phishing, 0 = Legitimate) | Curated by Jose Nazario (2005–2019); timestamped email headers. | Publicly available for cybersecurity research. | **High** (Commonly included in generic combined NLP corpora; must be deduped against `combined_reduced.json`). | **Conditional** |
| **2. Mendeley Phishing Email Dataset (Raza & Ding)** | Full email text + HTML bodies + URL links (approx. 18k emails) | Binary (1 = Phishing, 0 = Legitimate) | Curated from SpamAssassin, Nazario, and personal mailboxes (2018–2020). | CC BY 4.0 Open Access. | **Medium to High** (Contains subset of Nazario/SpamAssassin). | **Conditional** |
| **3. HuggingFace / Kaggle "Phishing Site URLs" (e.g. Taruntiwari / Siddhesh)** | URL-only CSV files (e.g., 400k+ URLs from PhishTank & Alexa) | Binary (`bad` / `good`) | Aggregated from PhishTank & Moz top domains (2020–2021). | Research / CC0 / MIT. | **High on URLs**; **Zero HTML coverage** (Unsuitable for testing HTML routing). | **Unsuitable** |
| **4. IWSPA-AP Phishing Dataset (Anti-Phishing Shared Task)** | Full email texts with embedded links, raw HTML body, and header metadata | Binary (Phishing vs. Legitimate) | Benchmarked academic challenge dataset (2018–2020) with verified ground truth. | Academic research use only. | **Low to Medium** (Strictly held out competition set). | **Highly Recommended** |
| **5. Cloned Website / Phishing Kit Corpus (e.g., Phishpedia / PhishIntention Benchmarks)** | Full HTML snapshots of landing pages and verified benign brand pages | Binary (1 = Phishing, 0 = Benign) | Collected via active crawling (2021–2024); verified ground truth against brand databases. | Open research data. | **Low** (Recent collection dates postdate training corpus). | **Highly Recommended** |

---

## 3. Recommended Multi-Source Evaluation Composition

To rigorously evaluate both routing branches (HTML content and short URL strings), the independent evaluation set should not be a single monolithic file, but a stratified evaluation bundle:

### Cohort A: Real-World HTML Email & Webpage Corpus (Testing V3 Dual Route)
* **Source:** IWSPA-AP / Academic Phishing Kit benchmark.
* **Characteristics:** Full HTML markup, visible body text, anchor links, and clean benign webpage/newsletter controls.
* **Role:** Evaluates whether V3 Dual successfully prevents boilerplate suppression on unseen real-world attacks.

### Cohort B: Recent URL-Only Feed (Testing V2 Route)
* **Source:** Recent (post-2024) verified PhishTank / OpenPhish active phishing URLs paired with Tranco / CrUX top-10k benign landing URLs.
* **Characteristics:** Pure URLs ($\le 100$ characters) without HTML wrappers.
* **Role:** Evaluates whether V2 retains its high precision and specificity on modern URL attack structures.

### Cohort C: Plain-Text / SMS Phishing (Testing Non-HTML Content Route)
* **Source:** Recent academic SMS/Messaging scam datasets with verified provenance.
* **Characteristics:** Plain text without HTML tags, containing zero or one link.
* **Role:** Confirms that routing non-HTML text to V2 behaves stably without regression.

---

## 4. Source License & Provenance Verification

1. **Attribution & Usage:** All candidate sources must carry explicit academic or open-source licenses (e.g., CC BY, MIT, or public domain).
2. **Provenance Traceability:** Every imported record must retain:
   - `original_source_id`
   - `collection_timestamp`
   - `source_url` or `source_feed`
   - `original_raw_label`
   - `licensing_reference`
3. **Privacy Assurance:** Message bodies must be audited to ensure zero personally identifiable information (PII) such as personal phone numbers, physical addresses, or user credentials before evaluation runs.
