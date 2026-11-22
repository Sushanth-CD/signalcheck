# SMS Negative Control & Overlap Review: UCI SMS Spam Collection & ExAIS_SMS

**Milestone:** TEXT-EVAL-1 Readiness Review  
**Scope:** Screening Feasibility, Overlap Analysis, and Negative Control Viability  
**Status:** Read-Only Technical Review  
**Date:** November 2026  

---

## 1. Executive Summary: The UCI Overlap Warning

In earlier project planning, the **UCI SMS Spam Collection** (Almeida & Gómez Hidalgo, 2011/2012; 5,574 messages) was considered an ideal benign negative control baseline.

However, forensic review of the literature—specifically the **DIFrauD benchmark documentation** (Boumber & Verma, University of Houston, 2023)—explicitly reports that **the Mishra & Soni SMS dataset (2022/2023) contains extensive overlapping records and duplicates from the UCI SMS Spam Collection**.

Because our project's training corpus (`backend/data/raw/combined_reduced.json`, 77,677 records) directly ingested the Mishra & Soni SMS dataset from Hugging Face (`ealvaradob/phishing-dataset`), **a substantial portion of the UCI SMS Spam Collection is already present inside our training data.**

> [!CAUTION]
> **CRITICAL METHODOLOGICAL DIRECTIVE:**
> The UCI SMS Spam Collection **CANNOT be assumed to be independent** or used as an unvetted negative control. Labeling UCI Ham as "independent" without record-level deduplication is invalid.

---

## 2. Screening Feasibility of the UCI SMS Spam Collection

Can the complete UCI SMS Spam Collection (5,574 records) be screened efficiently using existing project tools? **YES.**

### 2.1 Screening Protocol:
1. **Corpus Size:** $N = 5,574$ records (4,827 ham, 747 spam).
2. **Execution Cost:** Screening 5,574 short texts against the 77,677-record SimHash index takes under 5 seconds using our existing `corpus_simhash_index.npz` and BKTree matcher.
3. **Screening Pipeline:**
   - **Stage 1 (Exact SHA-256):** Rejects all verbatim normalized text matches.
   - **Stage 2 (SimHash $H \le 3$ & Jaccard $\ge 0.90$):** Rejects all near-duplicate templates (e.g., student chat variants, minor typo differences).
4. **Expected Outcome:**
   - A sizable fraction of the 4,827 ham messages and 747 spam messages will be flagged as collisions against the Mishra & Soni subset of `combined_reduced.json`.
   - **Filtered Cohort Selection:** ONLY those ham messages that pass all 4 independence stages ($H > 3$ or $J < 0.90$) will be retained for the independent negative control baseline.
5. **Readiness Decision:** **CONDITIONAL GO.** Acquisition and screening of the 5,574 UCI records is permitted for the sole purpose of extracting the non-overlapping independent ham subset.

---

## 3. Review of Alternative Negative Control: ExAIS_SMS

- **Official Repository:** [https://github.com/AbayomiAlli/SMS-Spam-Dataset](https://github.com/AbayomiAlli/SMS-Spam-Dataset) (also hosted on Kaggle).
- **Authors & Origin:** Federal University of Agriculture, Abeokuta (FUNAAB), Nigeria (Onashoga et al., 2015; Alli et al.).
- **Dataset Composition & Scale:**
  - Total records: **5,240 SMS messages**.
  - **Ham (Non-Spam):** 2,890 messages ($55.2\%$).
  - **Spam:** 2,350 messages ($44.8\%$).
  - Collected from 20 human participants (academic staff, students, non-academic personnel) across multiple Nigerian mobile networks (MTN, Glo, Airtel, Etisalat).
- **Resolution of Discrepant Row Counts:**
  - The original raw release contains 5,240 rows.
  - Subsequent cleaned or deduplicated research subsets cite numbers between 4,800 and 5,100 rows due to removal of blank lines or exact repeated carrier broadcast notices. The definitive raw baseline is the **5,240-row release**.
- **Metadata & Privacy Audit:**
  - Includes user metadata: timestamps, dates, and masked sender/carrier tags.
  - **Sanitization Requirement:** When ingesting ExAIS_SMS, all user IDs, timestamps, and network header columns must be discarded, extracting strictly the `message_text` and `label`.
- **Classification & Modality Suitability:**
  - **Classification:** **General SMS Spam & Ham Dataset.**
  - **NOT a smishing dataset.** The spam messages consist of regional carrier promotions, caller ringtone advertisements, banking transactional notifications, and service marketing.
- **Independence & Feasibility:**
  - **Independence: EXCELLENT.** Never integrated into Western or Hugging Face phishing compilations. Zero known overlap with `combined_reduced.json`.
  - **Readiness Decision:** **GO (Secondary / Alternative Benign Baseline)**. Provides a valuable contemporary cultural and regional cross-validation corpus.
