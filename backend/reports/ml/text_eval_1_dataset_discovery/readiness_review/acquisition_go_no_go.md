# Acquisition Go / No-Go Decision & Pilot Sizing

**Milestone:** TEXT-EVAL-1 Readiness Review  
**Scope:** Dataset Acquisition Decisions, Provenance Deconfliction, and Pilot Sizing  
**Status:** Strategic Decision Gate  
**Date:** November 2026  

---

## 1. Dataset Go / No-Go Evaluation

| Dataset Candidate | Proposed Role | Decision | Rationale & Governance Constraints |
| :--- | :--- | :---: | :--- |
| **WSPR-NCSU SMS Phishing** (IEEE S&P 2024) | Confirmed Smishing (Cohort A) | **GO** | **Cleared for immediate pilot.** Carrier gateway verified, 2022–2024 collection postdates training data, zero leakage. Must sample strictly 1 message per campaign and strip destination phone numbers. |
| **UCI SMS Spam Collection** (DocEng 2011) | Legitimate SMS Ham (Cohort B) | **CONDITIONAL GO** | **Cleared for acquisition ONLY for full screening.** Provenance review confirmed substantial verbatim overlap with Mishra & Soni (which is inside our training data). Must screen all 5,574 rows; accept ONLY non-colliding ham records. |
| **ExAIS_SMS Spam Dataset** (FUNAAB 2015) | General Spam (Cohort C) & Ham (Cohort B) | **GO** | **Cleared for acquisition.** Regional Nigerian African-English SMS dataset. Zero overlap with `combined_reduced.json`. Excellent source for commercial spam nuisance testing. User metadata must be stripped. |
| **Zenodo CEAS 2008 Sub-Corpus** (`CEAS_08.csv`) | Phishing & Legitimate Emails (Cohorts D & E) | **GO** | **Cleared for pilot.** Cleanly separated conference benchmark; unbundled from `ealvaradob` training sources. |
| **Mishra & Soni SMS Dataset** (Mendeley 2022) | Any Evaluation Cohort | **NO-GO** | **Disqualified.** 100% ingested into our training data via `combined_reduced.json`. |
| **DIFrauD Email Phishing** (`redasers/difraud`) | Email Phishing Evaluation | **NO-GO** | **Disqualified.** Upstream source audit confirms it is built from Enron and Nazario, matching our base training corpus. |
| **Zenodo Enron & Nazario Sub-Files** | Email Evaluation | **NO-GO** | **Disqualified.** Direct upstream sources of `combined_reduced.json`. |
| **IWSPA-AP V2.0** | Email Evaluation | **NO-GO (For Open Pilot)** | **Access blocked.** Requires formal institutional registration and signing an NDA. (V1.0 remains conditional). |

---

## 2. Smallest Sensible Pilot Acquisition Specification

Rather than attempting full multi-gigabyte corpus downloads, we specify the **smallest sensible pilot acquisition**:

```
+---------------------------------------------------------------------------------------------------+
| SMALLEST SENSIBLE PILOT: TEXT-EVAL-1 PILOT 100/100                                                |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  Total Pilot Target: Exactly 450 Verified, Independently Screened Text Messages                   |
|                                                                                                   |
|  1. SMS Modality (250 samples):                                                                   |
|     - Cohort A (Smishing): 100 samples from 100 distinct WSPR-NCSU campaigns                      |
|     - Cohort B (Legitimate SMS): 100 samples (50 UCI Ham post-screened + 50 ExAIS Ham)           |
|     - Cohort C (Commercial Spam): 50 samples (25 ExAIS Spam + 25 UCI Spam post-screened)          |
|                                                                                                   |
|  2. Email Modality (200 samples):                                                                 |
|     - Cohort D (Phishing Email): 100 samples from CEAS 2008 (label=1)                             |
|     - Cohort E (Legitimate Email): 100 samples from CEAS 2008 (label=0)                           |
|                                                                                                   |
|  3. Deduplication Preflight Gate:                                                                 |
|     Every one of the 450 candidate texts must pass:                                               |
|     * Zero exact normalized SHA-256 match against 77,677 project corpus.                         |
|     * SimHash Hamming distance > 3 OR character 5-gram Jaccard < 0.90 against corpus.            |
|     * Zero URL collisions against project training domain holdouts.                               |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### Execution Strategy:
- **Download Volume:** Small lightweight CSV slices ($< 15\text{ MB}$ total).
- **Runtime:** Screening 450 samples against the existing `corpus_simhash_index.npz` executes in $< 1\text{ second}$.
- **Zero Modification:** Preserves all frozen models, APIs, and existing evaluation reports.
