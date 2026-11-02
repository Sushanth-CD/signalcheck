# Dataset Source Verification & Independence Audit

**Milestone:** TEXT-EVAL-1  
**Scope:** Forensic Verification of Training Corpus Origins, Contamination Risk, and Deduplication Feasibility  
**Target Project Corpus:** 77,677 records in `backend/data/raw/combined_reduced.json`  
**Status:** Read-Only Verification  
**Date:** November 2026  

---

## 1. Executive Summary: Tracing the Origins of `combined_reduced.json`

To guarantee that any new evaluation benchmark is truly independent, we conducted a forensic review of our project's base training corpus: `backend/data/raw/combined_reduced.json` (and its processed form `phishing_text_candidates.jsonl`).

```
+---------------------------------------------------------------------------------------------------+
| GENEALOGY OF PROJECT TRAINING CORPUS (combined_reduced.json)                                      |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  Source Repository: Hugging Face "ealvaradob/phishing-dataset" (Esteban Alvarado)                |
|                                                                                                   |
|  [Email Sub-Dataset] -----------------> Enron Email Corpus (Benign) + Jose Nazario Corpus (Phish) |
|  [SMS Sub-Dataset] -------------------> Sandhya Mishra & Devpriya Soni (Mendeley Data 2022)       |
|  [URL Sub-Dataset] -------------------> JPCERT, Kaggle URL aggregators, GitHub security repos    |
|  [HTML/Web Sub-Dataset] --------------> webs.json (~80,000 scraped website DOMs)                 |
|                                                                                                   |
|  Downsampling & Merging --------------> Downsampled URLs by ~95% to balance text & links          |
|  Resulting File in Project -----------> backend/data/raw/combined_reduced.json (77,677 records)   |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### Critical Provenance Revelations:
1. **The Mishra & Soni Mendeley SMS Dataset is INSIDE our training data.** The 5,971 messages (4,844 ham, 638 smishing, 489 spam) from `10.17632/f45bkkt8pr.1` were incorporated into `combined_reduced.json`. Any candidate evaluation relying on this file is contaminated.
2. **The Enron and Nazario Email Corpora are INSIDE our training data.** All models trained on `combined_reduced.json` have already seen Enron business prose and Nazario's legacy phishing lures.
3. **The "Tiago Smishing Dataset" is a Misnomer.** The dataset commonly referenced as "Tiago smishing" is actually the **UCI SMS Spam Collection** created by Tiago A. Almeida and J. M. Gómez Hidalgo (DocEng 2011). It is a binary Ham/Spam dataset, not a dedicated smishing benchmark.

---

## 2. Contamination Risk by Candidate Dataset

| Candidate Dataset | Origin / Publisher | Overlap Risk with Training Corpus | Action Required |
| :--- | :--- | :---: | :--- |
| **WSPR-NCSU SMS Phishing** | NC State Univ. (IEEE S&P 2024) | **ZERO (0%)** | **CLEARED FOR ACQUISITION & EVALUATION.** |
| **IMC 2025 User Smishing** | ACM IMC 2025 (`reportsmishing`) | **ZERO (0%)** | **CLEARED FOR ACQUISITION & EVALUATION.** |
| **UCI SMS Spam Collection (Ham)** | Almeida & Gómez Hidalgo (UCI) | **LOW / MODERATE** | **Permitted for Benign Baseline** subject to SimHash screening. |
| **Mishra & Soni SMS Phishing** | Mendeley Data (2022) | **SEVERE (100% Source Overlap)** | **REJECTED / QUARANTINED.** Cannot serve as an independent benchmark. |
| **IWSPA-AP 2018 / 2020** | ACM CODASPY / ReDAS Lab | **ZERO (0%)** | **CLEARED FOR ACQUISITION & EVALUATION.** |
| **Zenodo Curated (`CEAS_08.csv`)** | Champa et al. (IEEE 2024) | **ZERO (0%)** | **CLEARED FOR ACQUISITION & EVALUATION.** |
| **Zenodo Curated (`Enron.csv` & `Nazario.csv`)** | Champa et al. (IEEE 2024) | **SEVERE (100% Source Overlap)** | **REJECTED / QUARANTINED.** Must be excluded from test cohorts. |
| **Apache SpamAssassin Corpus** | Apache Software Foundation | **HIGH** | **REJECTED.** Generic spam and extensive duplication history. |

---

## 3. Leakage Screening Feasibility Protocol

For any candidate dataset cleared for acquisition, we have established an automated, deterministic 4-stage screening protocol against the complete 77,677 project corpus.

### Stage 1: Exact Normalized-Text SHA-256 Hashing
- Apply the project's canonical text normalization:
  ```python
  def normalize_for_screening(text: str) -> str:
      value = unicodedata.normalize("NFKC", str(text)).casefold()
      return re.sub(r"\s+", " ", value).strip()
  ```
- Reject any candidate whose `sha256(normalize_for_screening(text))` collides with any record in the 77,677-record project corpus or V2/V3 partitions.

### Stage 2: Character 5-Gram 64-bit SimHash Screening
- Construct character 5-grams:
  $$\text{shingles}(s) = \{ s[i : i+5] \mid 0 \le i \le |s| - 5 \}$$
- Compute 64-bit SimHash fingerprint using MD5/SHA-256 shingle hashing.
- Query against the persistent SimHash index (`near_duplicate_audit/corpus_simhash_index.npz` or BKTree).
- Flag all candidates with **Hamming distance $\le 3$**.

### Stage 3: Exact Shingle Jaccard Verification
- For all Hamming candidate pairs ($H \le 3$), compute exact shingle Jaccard similarity:
  $$J(A, B) = \frac{|A \cap B|}{|A \cup B|}$$
- If $J(A, B) \ge 0.90$, confirm as a near-duplicate collision and **quarantine immediately**.

### Stage 4: URL & Registrable Domain Screening
- For candidate messages containing extractable URLs, extract the candidate hostname and compute the registrable domain via Public Suffix List (PSL).
- Check against the 2,000 CompPhish V4 domains and the training domain holdout set.
- Disallow any test message whose URL points to a domain present in the model training split.

---

## 4. Metadata and Grouping Feasibility

To support statistically valid stratified evaluation without clustering bias, candidate datasets must provide sufficient metadata to build independent groups:

1. **WSPR-NCSU SMS Phishing:**
   - Provides `campaign_id`, target brand, and timestamp.
   - Allows group-stratified evaluation where all messages belonging to the same phishing campaign are kept within a single evaluation block.
2. **IWSPA-AP Email Benchmark:**
   - Provides sender headers, subject lines, and thread identifiers.
   - Enables grouping by sender domain and subject campaign tokens.
3. **UCI SMS Ham:**
   - Provides source contributor IDs (NUS corpus vs. Caroline Tagg corpus).
   - Prevents student-specific conversational clustering.
