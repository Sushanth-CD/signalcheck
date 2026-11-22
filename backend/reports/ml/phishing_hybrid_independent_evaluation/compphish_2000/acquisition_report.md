# CompPhish V4 2,000-Sample Acquisition and Independence Screening Report

**Date:** 2026-11-01 10:21:11 UTC
**Target Population:** 2,000 independent samples (1,062 legitimate, 938 phishing).
**Actual Accepted:** 2000 samples (1062 legitimate, 938 phishing).
**Transferred Network Payload:** 83.63 MB (vs 250 MB ceiling; avoided 692 MB full ZIP download).
**Execution Wall-Clock Time:** 255.37 seconds.

## 1. Executive Summary
The evaluation corpus for the Cyber Security Awareness Platform hybrid classifier has been successfully scaled from the 100-sample pilot to a full **2,000-sample independent evaluation corpus**.

### Key Invariants Satisfied:
1. **Exact-Text Disjointness:** Zero normalized text collisions against the 77,677 project corpus records (`backend/data/raw/combined_reduced.json`).
2. **Domain Disjointness:** Zero registrable-domain or IP collisions against the 38,972 baseline project domain grouping keys.
3. **Near-Duplicate Disjointness:** Zero SimHash near-duplicate collisions ($H \le 3, J \ge 0.90$) against the persistent 77,677-record index.
4. **Intra-Corpus Domain Diversity:** Exactly **1999 unique registrable domains** (enforcing 1 sample per domain).
5. **Selective Retrieval:** All HTML files were acquired using HTTP Range requests over the official Mendeley S3 bucket without downloading the monolithic 692 MB archive.

## 2. Cohort Stratification & Balance

| Class | Cohort Name | Target | Accepted | Available in Pool |
| :--- | :--- | :--- | :--- | :--- |
| **Legitimate** | `crawl_2024_2025_batch1` | 392 | 392 | 3,010 |
| **Legitimate** | `top_sites_seed` | 383 | 383 | 2,938 |
| **Legitimate** | `crawl_2025_batch2` | 287 | 287 | 2,206 |
| **Phishing** | `crawl_2024_2025_batch1` | 502 | 502 | 3,858 |
| **Phishing** | `phishtank_feed` | 314 | 314 | 2,409 |
| **Phishing** | `openphish_feed` | 90 | 90 | 695 |
| **Phishing** | `crawl_2025_batch2` | 32 | 32 | 242 |

## 3. Screening & Exclusion Statistics
- **Total Candidates Examined:** 4,810
- **Accepted:** 2,000
- **Excluded:** 2,810

### Rejection Breakdown:
- `domain_collision`: **2,066**
- `intra_cohort_domain_duplicate`: **743**
- `near_duplicate_collision`: **1**

## 4. Storage & Artifact Provenance
- **Inert HTML Repository:** [`raw_html/`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/raw_html/)
- **Sample Manifest:** [`sample_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/sample_manifest.csv)
- **Independence Audit:** [`independence_screening.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/independence_screening.json)
- **Exclusion Log:** [`exclusion_summary.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/exclusion_summary.csv)
- **Metadata & Provenance:** [`acquisition_metadata.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/acquisition_metadata.json) & [`label_provenance_report.md`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/label_provenance_report.md)

The corpus is completely frozen, verified, and ready for model evaluation.