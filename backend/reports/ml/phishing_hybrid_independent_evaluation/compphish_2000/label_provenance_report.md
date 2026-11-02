# CompPhish V4 Label Provenance & Data Integrity Report

**Date:** 2026-11-01 10:21:11 UTC
**Cohort Scope:** Independent 2,000-sample evaluation corpus (1,062 legitimate, 938 phishing).
**Data Source:** CompPhish V4 Mendeley Release (`doi:10.17632/fmbs4kp9wz.4`).

## 1. Overview & Label Origin Disaggregation
To ensure scientific rigor during external model benchmarking, labels must not be treated as homogeneous truth. In CompPhish V4, distinct sampling mechanisms and feeds were used to assemble the legitimate controls and phishing targets.

### Natural Cohorts & Sources in the 2,000-Sample Evaluation Corpus:
1. **`top_sites_seed` (383 legitimate samples):**
   - *Origin:* Seeded from DataForSEO / Tranco Top-1000 high-traffic domain landing pages.
   - *Ground Truth Nature:* Curated commercial popularity rank. High confidence benign traffic, but biased towards portal landing pages, complex JavaScript shells, and extensive advertising networks.
2. **`crawl_2024_2025_batch1` (392 legitimate, 502 phishing samples):**
   - *Origin:* Systematic crawling between September 2024 and mid-2025 across monitored live URL feeds.
   - *Ground Truth Nature:* Contemporaneous web snapshots. Phishing samples were collected during active attacks; legitimate samples were collected from deep links of active benign domains.
3. **`crawl_2025_batch2` (287 legitimate, 32 phishing samples):**
   - *Origin:* Secondary validation crawl conducted in August 2025 to verify page status persistence.
   - *Ground Truth Nature:* Represents later-stage crawl snapshots. Demonstrates stability of legitimate landing pages vs. ephemeral phishing infrastructure.
4. **`phishtank_feed` (314 phishing samples):**
   - *Origin:* Community-verified PhishTank submissions (7-digit IDs).
   - *Ground Truth Nature:* Human-verified phishing campaigns targeting credentials, banking, and SaaS login forms.
5. **`openphish_feed` (90 phishing samples):**
   - *Origin:* Automated algorithmic feed detections from OpenPhish (5-digit IDs).
   - *Ground Truth Nature:* Live zero-day phishing telemetry detected at network perimeter.

## 2. Unresolved Label Quality Limitations & Mitigations

1. **Commercial Popularity vs. Benign Security Status:**
   - *Limitation:* Benign status in `top_sites_seed` is established by traffic volume (DataForSEO rank), not continuous manual security audits. While the top 1,000 domains are rarely malicious on their root apex, compromised subdomains or open redirects can theoretically exist.
   - *Mitigation in Evaluation:* Root apex landing pages were sampled; domain-level deduplication prevents localized skew; and all samples underwent strict PSL resolution.
2. **Ephemerality of Phishing Landing Pages:**
   - *Limitation:* Phishing URLs often succumb to takedowns within 4 to 24 hours. The HTML captured in CompPhish V4 preserves the exact response received at crawl time (including HTTP 200 attack pages, Cloudflare challenge wrappers, or parking pages).
   - *Mitigation in Evaluation:* The raw HTML is evaluated strictly as an inert textual artifact using the exact response bytes archived at the source DOI.
3. **Absence of Header Telemetry:**
   - *Limitation:* The Mendeley release provides only raw response HTML bodies and target URLs, omitting HTTP response headers (e.g., `Server`, `Set-Cookie`, `Location`, `Content-Security-Policy`).
   - *Mitigation in Evaluation:* The dual-channel architecture operates self-sufficiently on DOM structural tags and URL lexical components without relying on volatile HTTP transport headers.

## 3. Label Breakdown by Cohort in the Accepted Corpus

| Label Class | Cohort Name | Sample Count | Percentage of Class | Percentage of Total | Provenance Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Legitimate** | `top_sites_seed` | 383 | 36.1% | 19.15% | DataForSEO Top Sites |
| **Legitimate** | `crawl_2024_2025_batch1` | 392 | 36.9% | 19.60% | Primary Live Web Crawl |
| **Legitimate** | `crawl_2025_batch2` | 287 | 27.0% | 14.35% | August 2025 Followup Crawl |
| **Phishing** | `crawl_2024_2025_batch1` | 502 | 53.5% | 25.10% | Primary Monitored Feed Crawl |
| **Phishing** | `phishtank_feed` | 314 | 33.5% | 15.70% | PhishTank Community Verified |
| **Phishing** | `openphish_feed` | 90 | 9.6% | 4.50% | OpenPhish Automated Feed |
| **Phishing** | `crawl_2025_batch2` | 32 | 3.4% | 1.60% | August 2025 Phishing Snapshot |
| **Total** | **All Cohorts** | **2,000** | **-** | **100.00%** | **CompPhish V4 DOI** |
