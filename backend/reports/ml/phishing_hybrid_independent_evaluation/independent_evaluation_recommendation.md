# Independent Evaluation Recommendation & Selection Report

**Document Version:** 1.0.0  
**Date (UTC):** 2026-10-31  
**Project:** Cyber Security Awareness Platform  
**Target Review:** Source-level feasibility and selection of external independent evaluation datasets.

---

## 1. Selected Dataset Strategy

Based on our feasibility review, licensing terms, modality matching, and ground-truth confidence, we formally select the following external datasets for independent evaluation:

### Primary External Webpage Dataset: **PhreshPhish (Official Held-Out Test Split)**
* **Repository:** `phreshphish/phreshphish` on Hugging Face (arXiv: `2507.10854`).
* **Format:** Streamable Parquet / JSONL containing paired `html`, `url`, `label`, `date`, and `target`.
* **Collection Window:** 2023–2025 (strictly postdating the baseline project corpus).
* **Rationale for Selection:**
  1. Contains authentic, raw HTML DOM snapshots needed to evaluate the core hypothesis of Hybrid Policy 3/4.
  2. Offers an official, standardized test split that was never used in any part of V2 or V3 training/validation.
  3. Supports Hugging Face streaming (`streaming=True`), enabling strict sampling and local verification of a manageable cohort (e.g., 2,000–5,000 test records) without downloading dozens of gigabytes.
  4. Permissive open research access without NDAs or proprietary gating.

### Secondary External Webpage Dataset: **CompPhish V4 (Mendeley Data)**
* **Repository:** Mendeley Data DOI `10.17632/fmbs4kp9wz.4` (Richa Goenka).
* **Format:** Static downloadable ZIP archive containing raw HTML files and URL records.
* **Rationale for Selection:**
  1. Provides an independent, static secondary verification set to validate conclusions drawn from PhreshPhish.
  2. Full open CC BY 4.0 license.
* **Mandatory Limitation & Guardrail:**
  - Benign URLs in CompPhish were compiled via DataForSEO Top-1000 lists. Per project rules, ranking alone cannot prove benign status. CompPhish records must pass our secondary domain-holdout and phishing-blocklist filter before being included in evaluation metrics.

### Email / SMS Dataset: **SpamAssassin Public Mail Corpus (Raw Mails) + Academic SMS Corpus**
* **Repository:** Apache SpamAssassin Public Corpus (easy/hard ham + spam/phishing) & Academic SMS Collection.
* **Rationale for Selection:**
  1. Unrestricted open-source license (unlike IWSPA-AP 2.0, which requires formal institutional NDAs).
  2. Provides raw MIME email structures (headers, plain text, and HTML body sections) to test real-world email ingestion through the hybrid router.
* **Mandatory Limitation & Guardrail:**
  - Historical SpamAssassin messages must be audited for exact and near-duplicate collisions against `combined_reduced.json` (which incorporated legacy Enron/SpamAssassin records). Any colliding text hash will be automatically quarantined.

---

## 2. Modality Partitioning Policy

To prevent ecological fallacy and distorted metrics:
1. **Never pool distinct modalities into a single opaque score.**
2. All experimental evaluations will report independent metrics across four isolated populations:
   - **Population A:** Raw HTML Webpages ($n \approx 2,000$ from PhreshPhish Test).
   - **Population B:** Full Email MIME Bodies ($n \approx 1,000$ from verified open mail archives).
   - **Population C:** SMS / Plain Text Messages ($n \approx 1,000$).
   - **Population D:** Bare URL Strings ($n \approx 2,000$).

---

## 3. Final Recommendation

### Verdict: **CONDITIONAL GO for Dataset Acquisition**

#### Conditions to Fulfill Prior to Evaluation:
1. **Selective Streaming Acquisition Only:**
   - Do not trigger bulk archive downloads.
   - Stream the official `test` split of `phreshphish/phreshphish` via `datasets` using a dedicated sampling script.
2. **Execute Full Pre-Evaluation Independence Audit:**
   - Run the automated deduplication script against all 77,677 project records.
   - Run candidate URL destination keys against the Oracle JDK PSL and the 38,764 training registrable domains.
   - Reject any record exhibiting exact hash collisions, near-duplicate Jaccard similarity $\ge 0.85$, or known training domain keys.
3. **Keep All Evaluated Models Frozen:**
   - Verify file hashes against `model_implementation_freeze_manifest.json` prior to execution.
   - Maintain threshold 0.50 as the primary benchmark.
4. **Deferred Production Integration:**
   - Do not alter FastAPI or React code until the independent evaluation has been fully conducted and reported.
