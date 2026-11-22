# Future Experiment Protocol: Dedicated SMS Classifier Training

**Protocol Title:** SMS-DEDICATED-TRAIN-1: Training and Validation Protocol for Mobile Text Phishing Detection  
**Target Directory:** `backend/reports/ml/experiments/sms_dedicated_v1/`  
**Status:** PROPOSED EXPERIMENT PROTOCOL (Awaiting Execution Approval)  
**Date:** 2026-11-02  

---

## 1. Core Principles & Safeguards

To prevent the methodological issues identified in the web-page models, this protocol enforces five non-negotiable constraints:

1. **Strict Partition Independence:** Development data must be strictly isolated from independent evaluation corpora.
2. **Pilot Preservation:** The 250-record SMS pilot (`backend/reports/ml/text_eval_1_acquisition/sms_pilot/sample_manifest.csv`) **MUST NOT** be used for model training or threshold tuning. It remains permanently reserved as an external diagnostic benchmark.
3. **Fresh Independent Final Test Set:** A fresh, never-seen test set from separate WSPR campaigns and distinct ExAIS users will be acquired for final holdout testing.
4. **Campaign and User Grouping:** Grouping must be strictly enforced so that no two messages from the same attack campaign or participant appear across train and test splits.
5. **Three-Way Class Separation:** Training labels must explicitly distinguish **Smishing** (`1`), **Commercial Spam** (`0_spam`), and **Benign Ham** (`0_ham`).

---

## 2. Eligible Development Dataset Assembly

The training corpus will be assembled from clean, verified open sources:

```
Proposed Development Dataset (Target ~6,000 Records):
├── Malicious Smishing Cohort (~2,000 records)
│   └── Sourced from WSPR-NCSU campaigns (distinct from the 100 pilot campaigns)
│       └── Sampled strictly at 1 message per campaign across 2,000 distinct campaigns!
├── Benign Ham Cohort (~2,500 records)
│   ├── Clean independent UCI Ham (passed exact & SimHash filter against baseline corpus) : 1,250 records
│   └── ExAIS Ham (from designated training user IDs, e.g., Users 1-14)                   : 1,250 records
└── Commercial Spam Control Cohort (~1,500 records)
    ├── Clean independent UCI Spam (passed exact & SimHash filter against baseline corpus):   750 records
    └── ExAIS Spam (from designated training user IDs, e.g., Users 1-14)                  :   750 records
```

### Partitioning Strategy (Group-K-Fold by Campaign and User ID):
- **Train Split (70%):** ~4,200 records.
- **Validation Split (15%):** ~900 records (used exclusively for hyperparameter and threshold tuning).
- **Development Test Split (15%):** ~900 records (held out, grouped by campaign/user).

---

## 3. Data Cleansing & Deduplication Invariants

Before model fitting, candidate records must pass automated integrity verification:
1. **PII Stripping:** Remove all recipient phone numbers, user carrier IDs, and telecom headers.
2. **Offline Text Sanitization:** Do not resolve, fetch, or ping any embedded URLs.
3. **Exact Deduplication:** Compute normalized SHA-256 text hashes. Reject identical texts within and across partitions.
4. **Near-Duplicate Grouping:** Compute 64-bit SimHash character 5-grams. Cluster pairs with Hamming distance $\le 3$ and Jaccard $\ge 0.90$ into unified graph components to prevent split leakage.

---

## 4. Modeling Pipeline Specification

### Architecture: `SMSDualNgramPipeline`
```python
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV

feature_union = FeatureUnion([
    ('word_ngram', TfidfVectorizer(
        analyzer='word',
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.98,
        max_features=25000,
        sublinear_tf=True
    )),
    ('char_ngram', TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(3, 5),
        min_df=3,
        max_df=0.98,
        max_features=50000,
        sublinear_tf=True
    ))
])

sms_pipeline = Pipeline([
    ('features', feature_union),
    ('classifier', LogisticRegression(
        C=1.0,
        class_weight='balanced',
        solver='liblinear',
        random_state=20261102,
        max_iter=1000
    ))
])
```

---

## 5. Evaluation & Acceptance Gates

The candidate model must pass the following acceptance gates on the validation split:
1. **Smishing Recall:** $\ge 90.0\%$ at the designated decision threshold.
2. **Benign Ham Specificity:** $\ge 95.0\%$ (no more than 5% false alarms on legitimate communication).
3. **Commercial Spam Specificity:** $\ge 80.0\%$ (commercial marketing must not trigger high-confidence phishing alarms).
4. **Brier Score / Calibration Error:** Demonstrated alignment between predicted probabilities and empirical risk.

Only after passing all gates will the model be presented for deployment and independent external testing.
