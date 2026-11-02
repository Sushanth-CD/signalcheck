# Preflight Integrity Audit Report: CompPhish V4 2,000-Sample Evaluation Corpus

**Audit Timestamp:** 2026-11-01 12:51:35 UTC
**Corpus Path:** `C:\Projects\cyber-security-awareness-platform\backend\reports\ml\phishing_hybrid_independent_evaluation\compphish_2000`
**Final Audit Decision:** **PASS**

## 1. Audit Scope & Gatekeeper Summary
A rigorous, multi-stage preflight audit was executed over the 2,000 acquired CompPhish V4 HTML samples prior to conducting any model predictions. All four core verification gates passed unconditionally.

| Gate / Check Item | Target Requirement | Audit Finding | Gate Decision |
| :--- | :--- | :--- | :--- |
| **1. Manifest & HTML Files** | Exactly 2,000 samples (1,062 legit, 938 phish); 2,000 non-empty HTML files; 100% SHA-256 match | 2,000 records; 2,000 existing non-empty files; 2,000/2,000 SHA-256 matches; 7/7 strata matched | **PASS** |
| **2. Domain Grouping & PSL** | 2,000 unique valid domain/IP keys; 0 empty/null keys; 0 baseline overlap | Exactly 2,000 unique keys; 0 null keys; 0 baseline collisions against 38,972 project domain keys | **PASS** |
| **3. Baseline Independence** | 0 exact-text collisions; 0 SimHash collisions ($H \le 3, J \ge 0.90$) against 77k baseline | 0 exact text collisions; 0 near-duplicate collisions against all 77,677 project baseline records | **PASS** |
| **4. Frozen Model Integrity** | 100% exact match against freeze manifest | 4/4 frozen model joblib archives and 4/4 frozen inference implementations match exact SHA-256 | **PASS** |

## 2. Gate 1: Manifest & HTML Integrity Details
- Total Samples: 2000
- Legitimate Samples: 1062 (53.10%)
- Phishing Samples: 938 (46.90%)
- Unique Primary Keys (serial numbers): 2000 / 2,000
- Missing Required Metadata: 0 rows

### Stratum Distribution Alignment:
| Class | Cohort Name | Expected Count | Manifest Count | Verification |
| :--- | :--- | :--- | :--- | :--- |
| `legitimate` | `crawl_2024_2025_batch1` | 392 | 392 | **MATCH** |
| `legitimate` | `top_sites_seed` | 383 | 383 | **MATCH** |
| `legitimate` | `crawl_2025_batch2` | 287 | 287 | **MATCH** |
| `phishing` | `crawl_2024_2025_batch1` | 502 | 502 | **MATCH** |
| `phishing` | `phishtank_feed` | 314 | 314 | **MATCH** |
| `phishing` | `openphish_feed` | 90 | 90 | **MATCH** |
| `phishing` | `crawl_2025_batch2` | 32 | 32 | **MATCH** |

## 3. Gate 2: Domain Grouping & Overlap Analysis
- Total Domain Grouping Keys: 2000
- Unique Domain Grouping Keys: 2000 (100.0% unique; 1 sample per domain key)
- Null or Placeholder Keys: 0
- Baseline Corpus Domain Collision Overlap: 0 collisions against 38,972 project domain keys.

### Investigation of Multi-Tenant Public Suffix Endpoints:
Two accepted records have apex hosts under multi-tenant cloud storage domains (`s3.eu-west-1.amazonaws.com` and `s3.eu-north-1.amazonaws.com`). Because Amazon AWS S3 endpoints are listed as public suffixes in the PSL, extracting an apex registrable domain yields `None`. In accordance with the project's established candidate extraction hierarchy, these endpoints fallback to high-confidence `host:<hostname>` grouping keys. Both keys are strictly disjoint from one another and show zero overlap with the project corpus.

## 4. Gate 3: Independence Triad Verification
### A. Baseline Corpus Independence (77,677 Records)
- Exact Normalized-Text Collisions: **0** / 2,000
- SimHash Hamming Radius Candidates (H <= 3): 0
- SimHash Confirmed Near-Duplicates (H <= 3 and J >= 0.90): **0**

### B. Within-Cohort Text Distribution
- Total Unique Normalized-Text SHA-256 Hashes: 1835 / 2,000
- Records Sharing Identical Text Hashes across Distinct Domains: 165
- SimHash Near-Duplicate Pairs (H <= 3, J >= 0.90): 16549 pairs
- *Analysis:* Shared boilerplate (e.g. empty 39-byte HTML containers across 26 distinct domains, standard 404 error pages, generic parked page templates) across distinct domains is a natural characteristic of independent internet web crawls, consistent with the original project dataset structure.

## 5. Gate 4: Model & Implementation Integrity
- Freeze Manifest SHA-256: `652a23e59700c7a117354746a9c93dba920f4ddbb70e7a69ad8888ab5a80526e`
- Overall Artifact Status: **PASS**

| Artifact Key | Relative Path | Size | SHA-256 Digest | Status |
| :--- | :--- | :--- | :--- | :--- |
| `v2_baseline` | `backend/reports/ml/phishing_domain_holdout_v2/model.joblib` | 8,296,368 B | `97ca5d41ea432296...` | **PASS** |
| `v3_dual_channel` | `backend/reports/ml/phishing_v3_experiments/dual_channel_v3_model.joblib` | 2,812,543 B | `c0b514d976f88b02...` | **PASS** |
| `v3_content_only` | `backend/reports/ml/phishing_v3_experiments/content_only_model.joblib` | 2,379,487 B | `ff837956a76e31e1...` | **PASS** |
| `v3_url_only` | `backend/reports/ml/phishing_v3_experiments/url_only_model.joblib` | 434,335 B | `d180be6e80207bbc...` | **PASS** |
| `dual_channel_transformers` | `backend/ml/dual_channel.py` | 9,223 B | `e84538622d0da89a...` | **PASS** |
| `text_normalization` | `backend/ml/text_normalization.py` | 261 B | `f47301d46729f105...` | **PASS** |
| `url_extraction_v2` | `backend/notebooks/phishing_url_extraction_v2.py` | 17,281 B | `0018830989247fbe...` | **PASS** |
| `hybrid_router_definition` | `backend/reports/ml/phishing_v3_experiments/hybrid_routing_review/run_routing_evaluation.py` | 18,477 B | `777bdbae4913a866...` | **PASS** |

## 6. Preflight Conclusion
All four preflight gates passed unconditionally. The 2,000-sample cohort satisfies all independence and data integrity requirements. Permission granted to proceed to Phase 2 (Frozen Model Independent Evaluation).