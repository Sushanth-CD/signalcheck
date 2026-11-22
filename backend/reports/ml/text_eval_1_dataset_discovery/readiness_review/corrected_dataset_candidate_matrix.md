# Corrected Dataset Candidate Matrix

**Milestone:** TEXT-EVAL-1 Readiness Review  
**Scope:** Post-Forensic Corrections to Dataset Matrix & Overlap Deconfliction  
**Status:** Read-Only Technical Specification  
**Date:** November 2026  

---

## 1. Executive Summary

This matrix updates and corrects the initial dataset candidate discovery based on forensic source audits and explicit overlap confirmations. Most critically:
1. **UCI SMS Spam Collection Overlap:** As explicitly documented in the DIFrauD benchmark (Boumber & Verma, ReDAS Lab), the **Mishra & Soni 2022/2023 dataset contains extensive verbatim duplicates and overlapping messages from the UCI SMS Spam Collection**. Because Mishra & Soni was ingested directly into `combined_reduced.json` (our training data), **the UCI SMS dataset cannot be assumed to be independent without rigorous screening**.
2. **DIFrauD Phishing Domain Ingestion:** The email phishing configuration of DIFrauD (`redasers/difraud`) aggregates **Enron and Nazario**, which are the identical upstream sources of our project's training corpus.
3. **ExAIS_SMS Provenance:** Clarified as a 5,240-record regional African-English mobile spam corpus (FUNAAB / Onashoga et al.), representing **general spam and ham**, NOT smishing.

---

## 2. Corrected Candidate Matrix

| Dataset Identifier | Modality | Primary Focus | Claimed Records | Verified Overlap / Contamination Status | Independence Feasibility | Recommended Role | Final Status |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| **WSPR-NCSU SMS Phishing** | SMS | Confirmed Smishing | 67,991 msgs, 35,128 campaigns | **Zero overlap.** Collected 2022–2024 via carrier gateways; verified by VT/APWG. Postdates training data. | **Immediate screening pass.** | Primary Malicious Smishing Cohort | **GO** (Pilot of 100) |
| **UCI SMS Spam Collection** | SMS | Generic Ham & Spam | 5,574 msgs (4,827 ham, 747 spam) | **Substantial overlap with Mishra & Soni.** Portions exist verbatim inside our training corpus (`combined_reduced.json`). | **High collision expected.** Must screen 100% of records against 77,677 corpus; use ONLY passing ham. | Secondary Benign Ham Control (Filtered subset only) | **CONDITIONAL GO** (Post-Screening) |
| **ExAIS_SMS Spam Dataset** | SMS | Regional Spam & Ham | 5,240 msgs (2,890 ham, 2,350 spam) | **Zero known overlap.** Regional collection (FUNAAB, Nigeria). General commercial spam/ham, NOT smishing. | **Feasible.** Contains user phone/timestamp metadata that must be stripped. | Exploratory Generic Spam & Ham Cohort | **HOLD / SECONDARY** |
| **IWSPA-AP (Shared Task)** | Email | Anti-Phishing Benchmark | ~10,000 emails | **Zero overlap with `ealvaradob`.** Purpose-built competition corpus. | **Access barrier:** V2 requires NDA with ReDAS Lab; V1 requires extraction from participant repos. | Primary Independent Phishing Email Benchmark | **CONDITIONAL GO** (Pending Access Verification) |
| **DIFrauD Email Phishing** | Email | Multi-Domain Fraud | Variable subsets | **Severe overlap.** Uses Enron and Nazario as primary components. | **High collision.** Would re-test identical training records. | Quarantined / Inadmissible for primary evaluation | **NO-GO** |
| **Zenodo CEAS 2008 Sub-Corpus** | Email | Conference Email Benchmark | ~12,000 emails | **Independent conference corpus.** Not part of Enron or Nazario subsets. | **High feasibility.** Clean CSV structure; requires SimHash screening against training corpus. | Primary Legitimate & Phishing Email Baseline | **GO** (Pilot of 100) |
| **Mishra & Soni (Mendeley Data)** | SMS | 3-Class SMS Phishing | 5,971 msgs | **100% Ingested into training corpus.** Upstream source for `combined_reduced.json`. | **Severe leakage.** | Quarantined / Contaminated | **NO-GO** |
| **Zenodo Enron & Nazario Subsets**| Email | Historic Email Corpus | >50,000 emails | **100% Ingested into training corpus.** Upstream source for `combined_reduced.json`. | **Severe leakage.** | Quarantined / Contaminated | **NO-GO** |
