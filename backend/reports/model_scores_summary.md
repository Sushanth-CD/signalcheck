# Model Evaluation Scores & Statistical Verification Summary

**Platform:** SignalCheck Cyber Security Awareness Platform  
**Target File:** `backend/reports/model_scores_summary.md`  
**Date:** November 16, 2026  
**Status:** FORENSICALLY VERIFIED & AUDITED  
**Git Branch:** `auto/sms05`  
**Scope:** Rigorous offline verification, execution against saved test splits, false-positive/negative rate calculation, 95% bootstrap confidence interval estimation (1,000 resamples), split methodology accounting, and cross-domain comparability analysis for production-deployed Web and SMS models.

---

## 1. Executive Summary & Production Artifact Integrity

All models loaded by the SignalCheck backend at startup undergo pre-deserialization SHA-256 integrity verification against `backend/models/model_integrity_manifest.json`.

| Model Domain | Model Identifier | Runtime Load Path | SHA-256 Digest | Size (Bytes) | Verified Against Saved Test Split |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Web Phishing** | `phishing-tfidf-logreg-domain-grouped-v1` | `backend/models/text/phishing_tfidf_logreg_domain_grouped.joblib` | `42ce5d9c5a87a904528ac0f2235d4fe50103b494d6f9aa7d560247ca9a6170ca` | 9,757,792 | **YES** ($\Delta \le 5.55 \times 10^{-17}$) |
| **SMS Smishing** | `sms-05-c-combined-v1` | `backend/models/sms/sms_05_model.joblib` | `6b7ae684cde6bf041deb4963e6e5b4adf7c31ba12ceed2b6b1f838ccd7b77587` | 2,884,128 | **YES** ($\Delta \le 5.00 \times 10^{-7}$) |

---

## 2. Deployed Web Model Forensic Provenance & Split Alignment

### 2.1 Backend Load Path & Digest Confirmation
- **Inference Loader:** `backend/app/ml_classifier.py` lines 16–22 statically defines `MODEL_PATH` pointing to `backend/models/text/phishing_tfidf_logreg_domain_grouped.joblib`.
- **Integrity Manifest:** Stored in `backend/models/model_integrity_manifest.json` under key `"phishing"`.
- **Computed Digest:** `42ce5d9c5a87a904528ac0f2235d4fe50103b494d6f9aa7d560247ca9a6170ca` (Exact Match).

### 2.2 Test Split & `metrics.json` Provenance
Forensic investigation across the repository, notebooks, and freeze manifests revealed two distinct but documented relationships:

1. **Primary Origin & Exact Execution Split:**
   - **Generation Source:** Authored in notebook `backend/notebooks/02_phishing_text_classifier.ipynb`.
   - **Artifact Configuration:** Cell 4 set `MODEL = "backend/models/text/phishing_tfidf_logreg_domain_grouped.joblib"` and output directory `OUT = "backend/reports/ml/text_phishing_domain_grouped"`.
   - **Saved Test Predictions:** In Cell 20, the model scored its held-out test split ($N = 11,445$) and saved individual sample predictions to `backend/reports/ml/text_phishing_domain_grouped/test_predictions.csv` (along with `test_errors.csv` and `quarantine_predictions.csv`).
   - **Exact Execution Check:** Loading the deployed joblib (`42ce5d9c...`) and predicting on the 11,445 text samples reproduces the saved probabilities in `test_predictions.csv` with a maximum absolute difference of $\mathbf{5.55 \times 10^{-17}}$ (numerical identity).
   - **Status of `metrics.json`:** A standalone `metrics.json` file is **not present on disk** in `backend/reports/ml/text_phishing_domain_grouped/`. Cell 24 of `02_phishing_text_classifier.ipynb` explicitly records `Metrics exists: False` and `Report exists: False`, confirming the notebook run was completed through prediction export but halted prior to rendering the separate JSON artifact. The exact metrics block was captured directly in Cell 20's standard output.

2. **Freeze Manifest & Holdout V2 Reference:**
   - In `backend/reports/ml/phishing_hybrid_independent_evaluation/model_freeze_manifest.json` and `model_implementation_freeze_manifest.json`, the referenced `v2_baseline` model points to `backend/reports/ml/phishing_domain_holdout_v2/model.joblib` (SHA-256: `97ca5d41ea4322965eec838968e80838113be130684f9703f77a51e663355921`, 168,757 features).
   - The corresponding metrics file is `backend/reports/ml/phishing_domain_holdout_v2/metrics.json` ($N = 1,997$).
   - As documented in `backend/reports/stage_a_1_verification.md`, the production runtime artifact (`42ce5d9c...`) was frozen from the primary domain-grouping experiment line (`text_phishing_domain_grouped`) where full 200,000-feature vocabulary was retained.

---

## 3. Web Phishing Model Verification & Statistical Confidence

### 3.1 Verification on Primary Saved Test Split ($N = 11,445$)
The deployed joblib (`phishing_tfidf_logreg_domain_grouped.joblib`) was loaded and evaluated on the exact 11,445 test samples from `backend/reports/ml/text_phishing_domain_grouped/test_predictions.csv` at threshold $0.50$.

| Metric | Saved Notebook Cell 20 Output | Re-computed from Deployed Joblib | Mismatch / Difference ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Total Test Samples ($N$)** | 11,445 | 11,445 | 0 (Exact Match) |
| **True Negatives (TN)** | 6,224 | 6,224 | 0 (Exact Match) |
| **False Positives (FP)** | 460 | 460 | 0 (Exact Match) |
| **False Negatives (FN)** | 534 | 534 | 0 (Exact Match) |
| **True Positives (TP)** | 4,227 | 4,227 | 0 (Exact Match) |
| **Accuracy** | 0.913150 (91.31%) | 0.913150 (91.31%) | $0.000000$ (Exact Match) |
| **Precision** | 0.901856 (90.19%) | 0.901856 (90.19%) | $0.000000$ (Exact Match) |
| **Recall** | 0.887839 (88.78%) | 0.887839 (88.78%) | $0.000000$ (Exact Match) |
| **F1 Score** | 0.894793 | 0.894793 | $0.000000$ (Exact Match) |
| **ROC-AUC** | 0.973311 | 0.973298 | $\Delta = 0.000013$ ($< 0.001\%$, trapezoid rounding) |
| **False Positive Rate (FPR)** | — | **0.068821** (6.88%) | — |
| **False Negative Rate (FNR)** | — | **0.112161** (11.22%) | — |
| **Specificity** | 0.931179 (93.12%) | 0.931179 (93.12%) | $0.000000$ (Exact Match) |
| **95% Bootstrap CI: Precision** | — | **[0.8939, 0.9105]** | 1,000 resamples |
| **95% Bootstrap CI: Recall** | — | **[0.8786, 0.8966]** | 1,000 resamples |

### 3.2 Supplementary Evaluation on Holdout V2 Partition ($N = 1,997$)
When evaluated on the smaller `phishing_domain_holdout_v2` test partition:
- **Confusion Matrix:** TN = 455, FP = 58, FN = 66, TP = 1,418.
- **Accuracy:** 0.9379 (93.79%) | **Precision:** 0.9607 | **Recall:** 0.9555 | **F1:** 0.9581 | **ROC-AUC:** 0.9721.
- **FPR:** 0.11306 (11.31%) | **FNR:** 0.04447 (4.45%).

---

## 4. SMS Smishing Model Verification & Statistical Confidence

### 4.1 Verification on Primary Saved Test Split ($N = 1,307$)
The deployed SMS model (`sms_05_model.joblib`, SHA-256 `6b7ae684...`) was loaded and evaluated on `backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/test_predictions.csv` at threshold $0.50$. Probabilities were also checked against raw text from `sms05_split_manifest.csv` ($\Delta \le 5.0 \times 10^{-7}$).

| Metric | Saved in `test_metrics.json` | Re-computed from Deployed Joblib | Mismatch / Difference ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Total Test Samples ($N$)** | 1,307 | 1,307 | 0 (Exact Match) |
| **Negative Class Count ($N_{neg}$)** | 797 (526 Ham, 271 Spam) | 797 | 0 (Exact Match) |
| **Positive Class Count ($N_{pos}$)** | 510 (Smishing) | 510 | 0 (Exact Match) |
| **True Negatives (TN)** | 783 | 783 | 0 (Exact Match) |
| **False Positives (FP)** | 14 (4 Ham, 10 Spam) | 14 | 0 (Exact Match) |
| **False Negatives (FN)** | 31 | 31 | 0 (Exact Match) |
| **True Positives (TP)** | 479 | 479 | 0 (Exact Match) |
| **Accuracy** | 0.9656 (96.56%) | 0.965570 (96.56%) | $0.000000$ (Exact Match) |
| **Precision** | 0.9716 (97.16%) | 0.971602 (97.16%) | $0.000000$ (Exact Match) |
| **Recall** | 0.9392 (93.92%) | 0.939216 (93.92%) | $0.000000$ (Exact Match) |
| **F1 Score** | 0.9551 | 0.955135 | $0.000000$ (Exact Match) |
| **ROC-AUC** | 0.9928 | 0.992782 | $0.000000$ (Exact Match) |
| **False Positive Rate (FPR)** | — | **0.017566** (1.76%) | Ham: 0.76%, Spam: 3.69% |
| **False Negative Rate (FNR)** | — | **0.060784** (6.08%) | — |
| **Specificity** | 0.9824 (98.24%) | 0.982434 (98.24%) | $0.000000$ (Exact Match) |
| **Balanced Accuracy** | 0.9608 (96.08%) | 0.960825 (96.08%) | $0.000000$ (Exact Match) |
| **95% Bootstrap CI: Precision** | — | **[0.9552, 0.9842]** | 1,000 resamples |
| **95% Bootstrap CI: Recall** | — | **[0.9157, 0.9591]** | 1,000 resamples |

---

## 5. SMS Holdout Grouping & Hyperparameter Selection Integrity

A forensic review of `backend/reports/ml/sms_05_linkless_generalization/` confirmed:

### 5.1 How the Holdout Was Grouped
1. **Partition Structure:** Documented in `dataset_v1/sms05_split_manifest.csv` and `dataset_v1/sms05_dataset_report.md`. The corpus was partitioned into Training (70%, $N = 6,123$), Validation (15%, $N = 1,305$), and Internal Test (15%, $N = 1,307$).
2. **Connected Component Grouping:** Messages were grouped by template structure and near-duplicate SimHash fingerprints across 8,145 connected components. Exactly **0** group or text collisions occurred across Train, Validation, and Test splits.
3. **Benchmark Quarantine:** Diagnostic benchmarks (the 250-message pilot and 500-message Mishra & Soni benchmark) were permanently quarantined to prevent pre-training contamination.
4. **User-Level Overlap Caveat:** While message templates and text hashes were strictly isolated with zero cross-leakage, 19 of the 20 benign user profiles from user-donated corpora appear across both Training and Validation, and all 20 appear in both Training and Test (`sms05_dataset_report.md` Section 5).

### 5.2 Test Set Independence & Hyperparameter Tuning
- **Zero Test Set Tuning:** Neither the decision threshold nor any pipeline hyperparameters were tuned or chosen on the test set.
- **Validation-Driven Selection:** As detailed in `experiments/final_model_selection.md` and `experiments/model_comparison.md`, model selection among candidate pipelines (SMS-05-A, B, C, D) and operating threshold verification were determined **strictly on the Validation partition ($N = 1,305$)**.
- **Fixed Operating Threshold:** The classification threshold was frozen at **0.50** a priori. The test set ($N = 1,307$) was scored only once as a final verification of out-of-sample generalization.

---

## 6. Critical Methodological Caveats & Non-Comparability

1. **Incomparable Input Modalities:**
   - The Web Phishing model processes long, multi-token documents (emails, full HTML pages, web URLs) with word n-grams (1, 2).
   - The SMS Smishing model processes short mobile texts ($< 200$ characters) using a `FeatureUnion` of word n-grams (1, 2) and character n-grams (3, 5).
2. **Negative Class Formulation Differences:**
   - In Web phishing, the negative class consists of benign web pages and normal emails.
   - In SMS, the negative class contains both legitimate personal communication (**Ham**, FPR = 0.76%) and aggressive **Commercial Marketing Spam** (FPR = 3.69%).
3. **Lexical Leakage vs. Out-of-Distribution Degradation:**
   - Random and near-duplicate splits (such as the early 91.59% web baseline) permit domain lexical leakage when different URLs share registered domains (`eTLD+1`).
   - Strict domain holdout protocols force models to generalize to unseen target domains, demonstrating true out-of-distribution performance.
4. **Uncalibrated Model Scores:**
   - Probabilities produced by `predict_proba()` from both models are uncalibrated logistic regression outputs and should not be interpreted as posterior probabilities of attack. Both the API and UI carry explicit disclaimers.
