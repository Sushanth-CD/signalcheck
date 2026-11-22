# SMS-05 Multi-Source Linkless-Aware Phishing Classifier Experiment Report

**Date**: November 2, 2026  
**Project**: [`cyber-security-awareness-platform`](file:///C:/Projects/cyber-security-awareness-platform)  
**Dataset Version**: `dataset_v1` ($N = 8,735$)  
**Manifest**: [`sms05_split_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_split_manifest.csv)  
**Selected Frozen Model**: **SMS-05-C** ([`sms_05_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/sms_05_model.joblib))  
**SHA-256**: `6b7ae684cde6bf041deb4963e6e5b4adf7c31ba12ceed2b6b1f838ccd7b77587`  

---

## 1. Executive Summary

SMS-05 resolves the critical architectural vulnerability discovered in SMS-03 (where internal test recall was $96.67\%$ on URL-bearing WSPR-NCSU smishing, but crashed to $11.00\%$ overall recall and $0.64\%$ linkless recall when evaluated on Mishra & Soni).

Using the multi-source dataset comprising **8,735 unique records** sourced across WSPR-NCSU, Mishra & Soni (2022), IMC 2025 reportsmishing, UCI SMS, and ExAIS:
1. Four candidate architectures were trained and validated without modifying frozen artifacts or quarantined benchmarks.
2. **SMS-05-C** (Combined Word + Character FeatureUnion) was selected purely on validation partition evidence ($N = 1,305$), achieving **$90.59\%$ linkless recall**, **$96.08\%$ URL recall**, **$0.76\%$ ham FPR**, and **$95.53\%$ balanced accuracy**.
3. Following cryptographic serialization and freezing (`6b7ae684cde6...`), a single **Internal Test Evaluation** ($N = 1,307$) was executed.
4. On the internal test set, frozen **SMS-05-C** achieved **$93.92\%$ overall smishing recall** ($479/510$), **$92.55\%$ linkless recall** ($236/255$), and **$95.29\%$ URL recall** ($243/255$), while keeping ham false positives at **$0.76\%$** ($4/526$).
5. In a head-to-head comparison on the identical SMS-05 test partition, **frozen SMS-03 achieved only $25.10\%$ linkless recall** ($64/255$) and $57.45\%$ overall smishing recall, demonstrating that SMS-05 provides a **+67.45 percentage point improvement in linkless smishing detection** while preserving exceptional ham protection.

---

## 2. Reconciled IMC Accounting & Dataset Preflight Verification

Prior to model fitting, all accounting items and preflight constraints were verified with 100% compliance:

### IMC Accounting Reconciliation
- **1,384 `spam` Taxonomy Rows vs 1,173 Quarantined Unique Records**:
  - The raw English dataset tagged with `scam_type == 'spam'` contained $1,384$ rows in the genuine SMS cohort.
  - Applying exact text normalization (`normalize_for_model` + SHA-256) resolved these $1,384$ rows into **exactly 1,173 unique text hashes** ($211$ duplicate message copies).
  - All 1,173 unique hashes (representing every single one of the 1,384 rows) were quarantined and excluded from SMS-05.
- **Missing 3 English Records**:
  - The 3 records were exact near-duplicate matches to benchmark row 209 (*"Dear Customer your pyatm wallet..."*, Jaccard = 0.9018).
  - Removing these 3 gave $22,075$ clean English records prior to quality filtering (which subsequently excluded 85 short/placeholder rows, 4 warning headers, and 221 OCR stubs, yielding 21,765 genuine SMS records).

### Dataset Invariants
- Total Candidates: **8,735**
- Partitions:
  - **Train**: $6,123$ ($70.10\%$)
  - **Validation**: $1,305$ ($14.94\%$)
  - **Internal Test**: $1,307$ ($14.96\%$)
- Class Distribution:
  - **Smishing**: $3,400$ ($50.00\%$ Linkless: $1,700$, $50.00\%$ URL-bearing: $1,700$)
  - **Ham**: $3,500$
  - **Commercial Spam**: $1,835$
- Partition Leakage Check: **0 collisions** across all 8,145 connected components, zero hash overlaps, zero campaign overlaps, and permanent quarantine of the 250-message pilot and 500-message Mishra benchmark.

---

## 3. Candidate Model Architectures

All four models received exclusively sanitized message text. All features were extracted strictly from text content:
1. **SMS-05-A (Word TF-IDF + Logistic Regression)**:
   - Word n-grams: $1\text{--}2$, sublinear TF, max features: $25,000$, min DF: $2$.
   - Classifier: `LogisticRegression(C=1.0, penalty='l2', solver='liblinear', class_weight='balanced')`.
2. **SMS-05-B (Character TF-IDF + Logistic Regression)**:
   - Character boundary n-grams: $3\text{--}5$, sublinear TF, max features: $50,000$, min DF: $3$.
   - Classifier: `LogisticRegression(C=1.0, penalty='l2', solver='liblinear', class_weight='balanced')`.
3. **SMS-05-C (Combined Word + Character FeatureUnion + Logistic Regression)**:
   - FeatureUnion combining SMS-05-A and SMS-05-B feature spaces.
   - Classifier: `LogisticRegression(C=1.0, penalty='l2', solver='liblinear', class_weight='balanced')`.
4. **SMS-05-D (Structured Two-Channel Content + Structural Features)**:
   - Channel 1: FeatureUnion(Word $1\text{--}2$ + Char $3\text{--}5$).
   - Channel 2: 6 derived text-level structural features: `has_url`, `has_phone_number`, `is_premium_rate_prefix`, `has_currency_symbol`, `uppercase_ratio`, `punctuation_density`.
   - Classifier: `LogisticRegression(C=1.0, penalty='l2', solver='liblinear', class_weight='balanced')`.

---

## 4. Comprehensive Validation Performance Comparison (N = 1,305)

Operating Threshold: **$0.50$**

| Metric | SMS-05-A | SMS-05-B | SMS-05-C (Winner) | SMS-05-D |
| :--- | :---: | :---: | :---: | :---: |
| **F1 Score** | $0.9382$ | $0.9401$ | **$0.9482$** | $0.9400$ |
| **Balanced Accuracy** | $0.9473$ | $0.9486$ | **$0.9553$** | $0.9504$ |
| **Precision** | $0.9534$ | $0.9573$ | **$0.9636$** | $0.9428$ |
| **Smishing Overall Recall** | $92.35\%$ ($471/510$) | $92.35\%$ ($471/510$) | **$93.33\%$** ($476/510$) | **$93.73\%$** ($478/510$) |
| ↳ **Linkless Recall** | $89.41\%$ ($228/255$) | $89.02\%$ ($227/255$) | **$90.59\%$** ($231/255$) | $89.41\%$ ($228/255$) |
| ↳ **URL-Bearing Recall** | $95.29\%$ ($243/255$) | $95.69\%$ ($244/255$) | $96.08\%$ ($245/255$) | **$98.04\%$** ($250/255$) |
| **Ham FPR** | $1.53\%$ ($8/524$) | **$0.76\%$** ($4/524$) | **$0.76\%$** ($4/524$) | $1.72\%$ ($9/524$) |
| **Commercial Spam FPR** | $5.54\%$ ($15/271$) | $6.27\%$ ($17/271$) | **$5.17\%$** ($14/271$) | $7.38\%$ ($20/271$) |
| **Specificity** | $0.9711$ | $0.9736$ | **$0.9774$** | $0.9635$ |
| **ROC-AUC** | $0.9873$ | $0.9869$ | **$0.9904$** | $0.9875$ |
| **Avg Precision (PR-AUC)** | $0.9833$ | $0.9826$ | **$0.9872$** | $0.9827$ |
| **Training Time ($N=6,123$)** | $1.67\text{s}$ | $6.02\text{s}$ | $8.15\text{s}$ | $11.21\text{s}$ |

**Validation Findings**:
- **SMS-05-C** dominated on overall accuracy, F1 score, linkless recall ($90.59\%$), and spam rejection ($5.17\%$).
- While **SMS-05-D** marginally improved URL recall to $98.04\%$, its structural channel increased false alarms on both Ham ($1.72\%$) and Commercial Spam ($7.38\%$), and delivered lower linkless recall ($89.41\%$) than SMS-05-C.
- Consequently, **SMS-05-C was formally selected and cryptographically frozen**.

---

## 5. Frozen Candidate Cryptographic Manifest

- **Selected Candidate**: `sms_05_c_combined`
- **Serialized Artifact**: [`sms_05_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/sms_05_model.joblib)
- **SHA-256 Digest**: `6b7ae684cde6bf041deb4963e6e5b4adf7c31ba12ceed2b6b1f838ccd7b77587`
- **File Size**: $2,884,128\text{ bytes}$
- **Operating Threshold**: $0.50$ (Fixed)
- **Seed**: $20261102$

---

## 6. Single Internal Test Evaluation Results (N = 1,307)

The frozen model **SMS-05-C** was evaluated on the held-out Internal Test partition ($N = 1,307$):

### Overall Classification Metrics
| Metric | Value | Interpretation |
| :--- | :---: | :--- |
| **Total Test Samples ($N$)** | $1,307$ | $510$ Positive (Smishing), $797$ Negative ($526$ Ham, $271$ Spam) |
| **F1 Score** | **$0.9551$** | Outstanding balance of precision and recall |
| **Balanced Accuracy** | **$0.9608$** | Macro-average of recall ($93.92\%$) and specificity ($98.24\%$) |
| **Accuracy** | **$96.56\%$** | $1,262$ correct classifications out of $1,307$ |
| **Precision** | **$97.16\%$** | $479\text{ TP} / (479\text{ TP} + 14\text{ FP})$ |
| **Overall Smishing Recall** | **$93.92\%$** | $479$ detected out of $510$ smishing messages ($31\text{ FN}$) |
| **Specificity** | **$98.24\%$** | $783$ correct rejections out of $797$ negatives ($14\text{ FP}$) |
| **ROC-AUC** | **$0.9928$** | Near-perfect threshold discrimination |
| **Average Precision** | **$0.9909$** | Precision-Recall curve area |

### Modality & Category Disaggregation
| Category / Subgroup | Total Samples | Flagged as Phishing | Rate (%) | Interpretation |
| :--- | :---: | :---: | :---: | :--- |
| **Smishing (All)** | $510$ | $479$ | **$93.92\%$** | Overall Smishing Recall |
| ↳ **Linkless Smishing** | $255$ | $236$ | **$92.55\%$** | Linkless Recall |
| ↳ **URL-Bearing Smishing** | $255$ | $243$ | **$95.29\%$** | URL-Bearing Recall |
| **Legitimate Ham** | $526$ | $4$ | **$0.76\%$** | Ham False Positive Rate |
| **Commercial Spam** | $271$ | $10$ | **$3.69\%$** | Commercial Spam FPR |

### Disaggregated Source Performance on Internal Test
| Source Dataset | Ground Truth Category | Total Samples | Flagged as Phishing | Rate (%) | Metric Type |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **WSPR-NCSU** | Smishing | $210$ | $201$ | **$95.71\%$** | Recall |
| **IMC 2025 reportsmishing** | Smishing | $251$ | $234$ | **$93.23\%$** | Recall |
| **Mishra & Soni (2022)** | Smishing | $49$ | $44$ | **$89.80\%$** | Recall |
| **UCI SMS** | Ham | $188$ | $1$ | **$0.53\%$** | False Positive Rate |
| **UCI SMS** | Commercial Spam | $5$ | $2$ | **$40.00\%$** | False Positive Rate ($2/5$ sparse sample) |
| **ExAIS** | Ham | $188$ | $3$ | **$1.60\%$** | False Positive Rate |
| **ExAIS** | Commercial Spam | $215$ | $4$ | **$1.86\%$** | False Positive Rate |
| **Mishra & Soni (2022)** | Ham | $150$ | $0$ | **$0.00\%$** | False Positive Rate |
| **Mishra & Soni (2022)** | Commercial Spam | $51$ | $4$ | **$7.84\%$** | False Positive Rate |

---

## 7. Direct Comparative Benchmark: Frozen SMS-03 vs Frozen SMS-05-C

Both frozen models were evaluated head-to-head on the identical **SMS-05 Internal Test Partition** ($N = 1,307$):

| Evaluation Metric | Frozen SMS-03 Baseline | Frozen SMS-05-C Winner | Absolute Delta | Operational Significance |
| :--- | :---: | :---: | :---: | :--- |
| **Model Artifact SHA-256** | `8dd043a3b832...` | `6b7ae684cde6...` | — | Cryptographically verified |
| **F1 Score** | $0.7226$ | **$0.9551$** | **+0.2325** | Dramatic improvement |
| **Balanced Accuracy** | $0.7822$ | **$0.9608$** | **+0.1786** | Broad multi-source generalization |
| **Smishing Overall Recall** | $57.45\%$ ($293/510$) | **$93.92\%$** ($479/510$) | **+36.47%** | Massive recall recovery |
| ↳ **Linkless Smishing Recall** | **$25.10\%$** ($64/255$) | **$92.55\%$** ($236/255$) | **+67.45%** | **Linkless blind spot eliminated** |
| ↳ **URL-Bearing Smishing Recall** | $89.80\%$ ($229/255$) | **$95.29\%$** ($243/255$) | **+5.49%** | Retains high URL capability |
| **Ham False Positive Rate** | **$0.38\%$** ($2/526$) | **$0.76\%$** ($4/526$) | +0.38% | Negligible change (<1% target met) |
| **Commercial Spam FPR** | **$2.21\%$** ($6/271$) | **$3.69\%$** ($10/271$) | +1.48% | Spam successfully separated |
| **ROC-AUC** | $0.9509$ | **$0.9928$** | **+0.0419** | Stronger discrimination |
| **Average Precision** | $0.9404$ | **$0.9909$** | **+0.0505** | High confidence rankings |

---

## 8. Key Takeaways & Deployment Readiness

1. **Vulnerability Resolved**:
   - Frozen SMS-03 suffered catastrophic collapse when presented with linkless attacks, detecting only $25.10\%$ on the multi-source test set.
   - SMS-05-C elevates linkless recall to **$92.55\%$**, while simultaneously improving URL-bearing recall from $89.80\%$ to **$95.29\%$**.
2. **True Cross-Source Generalization**:
   - SMS-05-C achieves over $89\%$ recall across all three independent smishing sources (WSPR: $95.71\%$, IMC: $93.23\%$, Mishra: $89.80\%$).
   - Legitimate ham messages from ExAIS, UCI, and Mishra remain protected, with a combined Ham FPR of just $0.76\%$.
3. **Architecture Robustness**:
   - Combining subword character boundary n-grams with word tokens proved superior to hand-crafted structural rules, avoiding the false alarm penalties introduced by structural feature engineering.
   - The frozen model artifact [`sms_05_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/sms_05_model.joblib) is ready for production evaluation.
