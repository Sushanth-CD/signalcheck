# PhreshPhish Acquisition Pilot V2 Report

**Date:** 2026-11-01 09:21:41 UTC  
**Repository:** `phreshphish/phreshphish` (Commit: `eca603e0ecd4f698f8d4d226c088659e72681239`)  
**Status:** BOUNDED EXECUTION COMPLETE & AUDITED  

---

## 1. Executive Summary & Core Feasibility Evaluation

This Pilot V2 investigated whether **selective individual-record retrieval** from the external **PhreshPhish** dataset is technically feasible without downloading full Parquet shards or the entire 48 GB test split.

### Critical Architecture Finding:
* **Selective Single-Record Retrieval is NOT Feasible on PhreshPhish Parquet Shards via HTTP:**
  The PhreshPhish dataset is packaged into 21 monolithic Parquet shards (`data/test-000.parquet` to `data/test-020.parquet`, totaling 8.55 GB compressed and ~48 GB uncompressed). In Parquet, columns are stored in contiguous row-group chunks. The `html` column accounts for **>99.8%** of the payload (~54 MB compressed / ~306 MB uncompressed per 1,000-row group).
  Because the Hugging Face Hub HTTP/fsspec transport does not support byte-range random index lookups into arbitrary row indices without streaming entire column chunks, **any attempt to extract targeted records across multiple shards inevitably requires transferring entire multi-megabyte Parquet shards**.
* **Transport-Level Byte Accounting Limitation:**
  The underlying Python `datasets` and `fsspec` HTTP streaming client does not expose native transport-level byte counters. While payload bytes of received content can be tracked accurately (2.40 MB HTML in this pilot), raw TCP-level wire transfers cannot be strictly throttled at the socket layer by the client library.

---

## 2. Hard Execution Limits & Pilot Metrics

All operations ran strictly within the bounded limits:

| Limit / Metric | Constraint Ceiling | Observed Result | Status |
|---|---|---|---|
| **Max Acquired Records** | 10 samples (5 Benign, 5 Phish) | **10 samples** (5 Benign, 5 Phish) | **Cleanly Met** |
| **Max Payload Transferred** | 100 MB | **2.40 MB** HTML payload | **Cleanly Met** |
| **Max Execution Time** | 300 seconds (Subprocess timeout) | **20.89 seconds** | **Cleanly Met (<2 minutes)** |
| **Full 77k SimHash Indexing** | Not permitted in pilot | **Skipped (reported as limitation)** | **Compliant** |
| **Bulk 48 GB Download** | Not permitted | **0 bulk archives downloaded** | **Compliant** |

---

## 3. Dataset Shard Inventory & Benchmark Provenance

- **Test Split Shards:** 21 files (`data/test-000.parquet` to `data/test-020.parquet`), total compressed size: **8.55 GB** (~48 GB uncompressed).
- **Train Split Shards:** 56 files (`data/train-000.parquet` to `data/train-055.parquet`), ~145 GB uncompressed.
- **Official Benchmark Index:**
  - Benign benchmark IDs: 90,262 samples
  - Phishing benchmark IDs: 28,476 samples
  - Total official benchmark: 118,738 samples
- **Licence:** Creative Commons Attribution 4.0 International (CC BY 4.0), restricted strictly to anti-phishing research.

---

## 4. Acquired Sample Records & Independence Audit

Each of the 10 acquired samples was verified for schema integrity (sample ID, URL, HTML, original label, capture date) and screened against the persisted project graph inventories:
- Exact text hash match against **77,411** unique normalized text hashes from `backend/data/raw/combined_reduced.json`.
- Destination domain / IP match against **38,764 registrable domains** and **208 IP keys** using the pinned **Oracle JDK 27 Public Suffix List** (`java version "27.0.1.0.3" 2026-10-25`).

### Acquired Sample Register:

| Sample ID (Prefix) | Label | Destination URL | Registrable Domain | HTML Size | Screening Status |
|---|---|---|---|---|---|
| `95954da27090...` | Benign | `https://calculatodo.com/en/count-days-between-dates` | `calculatodo.com` | 1087.6 KB | Accepted (0 collisions) |
| `424a7b0b1aec...` | Benign | `https://cooktopcove.com/2024/09/23/you-can-always-count-on-this-recipeits-the-first-thing-people-finish-at-gatherings/` | `cooktopcove.com` | 53.2 KB | Accepted (0 collisions) |
| `059bf31431cc...` | Benign | `https://my.lafarmbureau.com/insurance/home` | `lafarmbureau.com` | 41.1 KB | Accepted (0 collisions) |
| `c630a0a7b4f3...` | Benign | `https://elbow.co.uk/` | `elbow.co.uk` | 121.4 KB | Accepted (0 collisions) |
| `b84633b13b97...` | Phish | `https://ucion.zaolir.cfd/pageamazon` | `zaolir.cfd` | 9.5 KB | Accepted (0 collisions) |
| `2d0c7b9f9e9b...` | Phish | `https://defaultlimited.blob.core.windows.net/kuz-gleis4/kuz-gleis4.html` | `defaultlimited.blob.core.windows.net` | 2.6 KB | Accepted (0 collisions) |
| `c87dc98cbfcb...` | Phish | `http://trezr-bridg-begin.tem3.io` | `tem3.io` | 118.1 KB | Accepted (0 collisions) |
| `c01fc0fba315...` | Phish | `https://www.quatrocasino.ca/` | `quatrocasino.ca` | 47.2 KB | Accepted (0 collisions) |
| `4557daabce8f...` | Phish | `https://app-ledger-cloud-sso.typedream.app` | `app-ledger-cloud-sso.typedream.app` | 238.3 KB | Accepted (0 collisions) |

---

## 5. Strategic Dataset Recommendation: PhreshPhish vs. CompPhish V4

Given the architectural findings of Pilot V2:

1. **PhreshPhish Scalability Barrier:**
   Constructing a full 2,000-sample independent evaluation set (~1,520 benign, ~480 phish) from PhreshPhish would require scanning across all 21 test Parquet shards (~8.55 GB download) because the samples in the benchmark index are scattered arbitrarily throughout the shards. Without full local shard caching, repeated streaming is unreliable and network-heavy.
2. **Recommendation:**
   If downloading the ~8.55 GB compressed test Parquet shards is deemed excessive for evaluation infrastructure, **CompPhish V4** (`https://data.mendeley.com/datasets/fmbs4kp9wz/4`) should be evaluated as the alternative secondary dataset. CompPhish V4 provides discrete, structured email/URL archives with significantly lower total payload overhead.

---

## 6. Artifact Index

1. [`pilot_v2_report.md`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/phreshphish_pilot_v2/pilot_v2_report.md)
2. [`acquisition_metadata.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/phreshphish_pilot_v2/acquisition_metadata.json)
3. [`sample_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/phreshphish_pilot_v2/sample_manifest.csv)
