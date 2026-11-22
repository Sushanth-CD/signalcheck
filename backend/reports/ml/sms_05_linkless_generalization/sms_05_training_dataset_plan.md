# SMS-05 Training Dataset Preparation Plan

**Milestone:** SMS-05 Planning — Linkless Smishing Generalization  
**Scope:** Dataset Sizing, Class Balance, Normalization Protocol, and Partitioning Strategy  
**Status:** Protocol Specification Complete  
**Date:** November 2026  

---

## 1. Executive Summary & Objective

The objective of the **SMS-05 Training Dataset** is to provide an unbiased, multi-source training foundation that trains the model to recognize **both URL-bearing and linkless smishing attacks** while preserving near-zero false alarms on benign personal ham and commercial marketing spam.

### Core Architecture Rules
1. **Model Receives Only Sanitized Message Text:** Feature extraction operates solely on `sanitized_message_text`.
2. **Metadata Strictly Quarantined:** Dataset origin (`source_dataset`), collection date, sender ID, telephone type, and campaign ID are preserved in external manifests for audit and subgroup analysis but **never** passed to feature extractors.
3. **Quarantine Protection:**
   - The **500-message Mishra & Soni benchmark** remains permanently quarantined (zero training or validation participation).
   - The **250-message TEXT-EVAL-1 pilot** remains permanently quarantined.

---

## 2. Proposed Cohort Composition & Sizing

The target dataset scales the development pool from $5,400$ to approximately **$6,800$ clean instances**, achieving balanced 50/50 binary representation with multi-source diversity across all classes:

```
+---------------------------------------------------------------------------------------------------+
| PROPOSED SMS-05 CANDIDATE POOL (TARGET N ~ 6,800)                                                 |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  POSITIVE CLASS: MALICIOUS SMISHING (N ~ 3,400) [50.0%]                                           |
|    - Modern URL-Bearing Smishing (WSPR-NCSU Campaigns)              | ~1,400 records (41.2%)      |
|    - Modern Linkless & Conversational Smishing (IMC 2025 Reports)   | ~1,200 records (35.3%)      |
|    - Classical Phone Callback Smishing (Mishra & Soni Remaining)    | ~326 records (9.6%)         |
|    - Pretexting & Conversational Threat Scams (Zenodo Corpus)       | ~474 records (13.9%)        |
|    * Link Distribution: ~50% URL-Bearing / ~50% Linkless                                          |
|                                                                                                   |
|  NEGATIVE CLASS: BENIGN HAM & COMMERCIAL SPAM (N ~ 3,400) [50.0%]                                 |
|    - Benign Personal Ham (ExAIS Ham & Chat)                         | ~1,200 records (35.3%)      |
|    - Benign Transactional & Personal (Mishra & Soni Remaining Ham)  | ~800 records (23.5%)        |
|    - Benign Benchmark Ham (UCI SMS Collection)                     | ~300 records (8.8%)         |
|    - Commercial Marketing Spam (ExAIS Commercial Advertisements)    | ~800 records (23.5%)        |
|    - Commercial Service & Shortcode Spam (Mishra & Soni Remaining)  | ~300 records (8.8%)         |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Strict Partitioning and Leakage-Safe Splitting

To guarantee valid model selection and unbiased test evaluation, the candidate pool will be split into three source-aware partitions:

- **Training Partition (70% — $\sim 4,760$ records):** Used to fit feature vectorizers and train candidate classifiers.
- **Validation Partition (15% — $\sim 1,020$ records):** Used exclusively for hyperparameter tuning and model selection.
- **Internal Test Partition (15% — $\sim 1,020$ records):** Used for a single evaluation of the selected frozen candidate.

### Partitioning Constraints:
1. **Campaign-Aware Grouping:** All WSPR-NCSU records sharing a common `campaign_id` must be assigned to the same partition.
2. **Template-Aware Grouping:** Records sharing a 64-bit SimHash with Hamming distance $\le 3$ and Jaccard $\ge 0.90$ will be assigned to connected components and kept within a single partition.
3. **Source Stratification:** Every partition will maintain equal representation from WSPR-NCSU, IMC 2025, Mishra & Soni Remaining, ExAIS, and UCI.

---

## 4. Normalization and Feature Preprocessing Protocol

Text normalization will pass through the established production-grade standard (`ml.text_normalization.normalize_for_model`):
1. **NFKC Unicode Normalization:** Resolves mathematical script characters, full-width glyphs, and obfuscated homoglyphs.
2. **Case Folding:** Converts all text to standard lowercase.
3. **Whitespace Collapsing:** Replaces multi-spaces, tabs, and newlines with a single space.
4. **URL & Telephony Invariance:**  
   - URLs will be retained in their inert normalized string representation (`http://...`).
   - Telephone numbers will be retained as lexical tokens (allowing sub-word character n-grams to capture premium prefixes like `090` and `087`).
   - Currency symbols (`£`, `$`, `€`) will be preserved to allow urgency and prize feature extraction.
