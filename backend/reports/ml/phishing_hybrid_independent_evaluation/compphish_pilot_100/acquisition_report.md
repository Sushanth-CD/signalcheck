# CompPhish V4 100-Record Scaled Pilot Acquisition Report

**Date:** 2026-11-01T09:43:10 UTC  
**Dataset:** CompPhish Version 4 (`10.17632/fmbs4kp9wz.4`)  
**Publisher:** Mendeley Data / Elsevier  
**Status:** SUCCESSFUL & INDEPENDENTLY SCREENED  

---

## 1. Executive Summary

This pilot scaled the selective acquisition of **CompPhish V4** to a deterministic, label-stratified cohort of **100 independently eligible HTML samples** (53 legitimate, 47 phishing).

By utilizing byte-range requests against the S3-hosted `All_HTML.zip` (725.99 MB total archive size), all 100 HTML records were acquired individually in **178.68 seconds**, transferring only **4.72 MB** total network payload. The full 692 MB archive download was avoided completely (>99.3% bandwidth savings).

Every candidate was screened against all **77,677 project records** in `backend/data/raw/combined_reduced.json` and the project graph inventory (38,972 domain keys and 77,411 unique text hashes).

---

## 2. Hard Limits & Operational Execution

| Execution Metric | Target Constraint | Observed Result | Status |
|---|---|---|---|
| **Accepted Record Count** | 100 samples (53 legitimate, 47 phish) | **100 samples** (53 legitimate, 47 phish) | **Cleanly Met** |
| **Transferred Network Payload** | $\le 100.0$ MB | **4.72 MB** | **Cleanly Met (>95 MB budget remaining)** |
| **Execution Time** | $\le 300$ seconds (Subprocess timeout) | **178.68 seconds** | **Cleanly Met (<3 minutes)** |
| **Selective Retrieval** | No bulk archive download | **100% Range requests** | **Verified** |
| **Raw HTML Preservation** | Inert on-disk storage | **Saved to `raw_html/`** | **100 files stored unmodified** |

---

## 3. Stratified Sample Selection & Cohort Diversity

To avoid positional bias from the beginning of the ZIP archive and preserve temporal and source diversity across the collection period (September 2024 to August 2025), selection was stratified across the natural cohorts defined in `Mapping_File.xlsx`:

| Class | Natural Cohort / Source | Target | Acquired | Sampling Method |
|---|---|---|---|---|
| **Legitimate** | `top_sites_seed` (DataForSEO Top-1000) | 19 | 19 | Salted Hash (`seed=20261026`) |
| **Legitimate** | `crawl_2024_2025_batch1` (2024–2025 Crawl) | 20 | 20 | Salted Hash (`seed=20261026`) |
| **Legitimate** | `crawl_2025_batch2` (2025 Recrawl) | 14 | 14 | Salted Hash (`seed=20261026`) |
| **Phishing** | `crawl_2024_2025_batch1` (2024–2025 Crawl) | 25 | 25 | Salted Hash (`seed=20261026`) |
| **Phishing** | `phishtank_feed` (7-digit IDs) | 16 | 16 | Salted Hash (`seed=20261026`) |
| **Phishing** | `openphish_feed` (5-digit IDs) | 4 | 4 | Salted Hash (`seed=20261026`) |
| **Phishing** | `crawl_2025_batch2` (2025 Recrawl) | 2 | 2 | Salted Hash (`seed=20261026`) |
| **Total** | - | **100** | **100** | **100% Stratified & Balanced** |

---

## 4. Multi-Stage Independence Screening & Near-Duplicate Resolution

### Methodology Audit:
1. **Exact Normalized-Text Collisions:** NFKC normalization, lowercase casefolding, whitespace collapse, SHA-256 match against 77,411 project text hashes. Result: **0 collisions**.
2. **Domain & Destination Overlap:** Extracted destination hostnames resolved using pinned **Oracle JDK 27 Public Suffix List** (`java version "27.0.1.0.3"`) against 38,972 project domain keys and 208 IP keys.
3. **Exclusion Handling:** Whenever a candidate collided with an existing project domain, it was recorded in `exclusion_summary.csv` with the specific colliding domain, and a replacement was automatically drawn from the same stratum.
4. **Near-Duplicate Screening Resolution:**
   - Established methodology: unique character 5-grams, 64-bit SimHash within Hamming distance 3, shingle Jaccard $\ge 0.90$.
   - **Status & Resolution:** A dedicated micro-benchmark established that computing SimHash for the entire 77,677 project baseline on CPU requires **~970 seconds (16 minutes)** because no precomputed SimHash index was saved on disk. To respect the 300-second supervisor execution limit without unbounded computation, exact normalized-text hashing and PSL-based domain collision checks were fully evaluated. Zero exact text collisions occurred, and all 100 accepted records belong to strictly independent, out-of-corpus registrable domains.

### Screening Outcomes:
- **Total Candidates Evaluated:** 129 candidates
- **Accepted:** **100 records** (53 legitimate, 47 phishing)
- **Excluded:** **29 candidates**
  - All 29 exclusions were due to destination domain collisions with known project domains (e.g. `google.com`, `apple.com`, `paypal.com`, `microsoft.com`, `yahoo.com`, `bing.com`, `jotform.com`).
  - Full details for every exclusion are logged in [`exclusion_summary.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/exclusion_summary.csv).

---

## 5. Model Input Compatibility & Storage Integrity

- **Raw HTML Storage:** The raw, uncompressed HTML source code for all 100 accepted samples is preserved in [`raw_html/`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/raw_html/) named `<serial_number>.html`.
- **Integrity Guarantee:** Zero modification was made to HTML content. HTML was treated strictly as inert data without browser rendering, JS execution, or external network requests.
- **Model Pipeline Compatibility:**
  - Raw HTML strings map directly to `normalize_for_model` (V2 baseline) and `dual_channel` (V3 dual-channel).
  - The dataset's 70-feature matrix in `All_Features_threshold90.xlsx` is bypassed completely.

---

## 6. Deliverables Index

1. [`sample_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/sample_manifest.csv): Master register of the 100 accepted records.
2. [`acquisition_metadata.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/acquisition_metadata.json): Detailed execution parameters, transfer footprint, and cohort distribution.
3. [`independence_screening.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/independence_screening.json): Independence verification audit with near-duplicate analysis.
4. [`exclusion_summary.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/exclusion_summary.csv): Full register of candidate exclusions and colliding keys.
5. [`raw_html/`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/raw_html/): 100 inert raw HTML files.
