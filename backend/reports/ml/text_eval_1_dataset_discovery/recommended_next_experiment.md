# Recommended Next Experiment: Milestone Text-Eval-1 Execution

**Milestone:** TEXT-EVAL-1 Execution Plan  
**Status:** Strategic Recommendation & Implementation Roadmap  
**Target Project:** `C:\Projects\cyber-security-awareness-platform`  
**Date:** November 2026  

---

## 1. Executive Summary & Selection Decisions

Based on rigorous provenance tracing, forensic analysis of training corpus contamination, and format suitability, we deliver the final dataset selections for executing **TEXT-EVAL-1**:

```
+---------------------------------------------------------------------------------------------------+
| FINAL DATASET SELECTIONS FOR TEXT-EVAL-1                                                          |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  1. BEST SMS PHISHING / SMISHING DATASET:                                                         |
|     --> WSPR-NCSU SMS Phishing Dataset (IEEE S&P 2024)                                            |
|     * Why: Live carrier gateway collection (2022-2024), verified by VirusTotal & APWG,           |
|            organized into campaigns, 100% independent from training data.                         |
|     * Supplement: IMC 2025 User-Reported Smishing dataset for consumer-reported validation.       |
|                                                                                                   |
|  2. BEST BENIGN HAM SMS BASELINE:                                                                 |
|     --> UCI SMS Spam Collection (Ham Subset, Almeida & Gómez Hidalgo)                             |
|     * Why: 4,827 natural human text messages from NUS SMS Corpus and Caroline Tagg thesis.        |
|            Provides the cleanest negative control for false positive testing on mobile text.      |
|                                                                                                   |
|  3. BEST EMAIL DATASET:                                                                           |
|     --> IWSPA-AP Anti-Phishing Benchmark (ACM CODASPY / ReDAS Lab)                                |
|     * Why: Purpose-built anti-phishing challenge, realistic 90/10 class imbalance, clean body     |
|            text, completely unbundled from our Hugging Face training corpus.                      |
|     * Supplement: Zenodo CEAS 2008 sub-corpus (Champa et al., 2024). Strictly quarantine          |
|                   Enron and Nazario sub-files.                                                    |
|                                                                                                   |
|  QUARANTINED / EXCLUDED DATASETS (PROVENANCE COLLISION):                                          |
|  - Mishra & Soni Mendeley SMS (2022): 100% source overlap with combined_reduced.json.             |
|  - Zenodo Enron & Nazario sub-corpora: Exact training sources for combined_reduced.json.         |
|  - Apache SpamAssassin: Over-utilized, generic spam, high leakage risk.                           |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Experimental Execution Phases for Text-Eval-1

```
+---------------------------------------------------------------------------------------------------+
| EXECUTION TIMELINE & GATING WORKFLOW                                                              |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  Phase 1: Controlled Acquisition & Directory Setup                                                |
|           Acquire targeted slices: WSPR-NCSU (smishing), UCI Ham (benign), IWSPA-AP (email)       |
|           Target volume: ~1,000 smishing, ~1,000 ham SMS, ~500 phishing email, ~1,000 ham email    |
|                                                                                                   |
|  Phase 2: Automated 4-Stage Independence Audit                                                    |
|           [Exact Hash] -> [SimHash H <= 3] -> [Jaccard >= 0.90] -> [Domain Overlap]               |
|           Discard any colliding samples; verify zero leakage against 77,677 project records       |
|                                                                                                   |
|  Phase 3: Deterministic Stratification & Preflight Audit                                          |
|           Partition into Cohort A (SMS), Cohort B (Email), Cohort C (URL vs. No-URL)              |
|           Verify sha256 checksums, manifest integrity, and length distribution                   |
|                                                                                                   |
|  Phase 4: Frozen Model Benchmark Execution                                                        |
|           Evaluate V2 Baseline, V3 Content-Only, V3 URL-Only (C1 only), and V3 Dual-Channel       |
|           Record TP, FP, TN, FN, Recall, Specificity, F1, PR-AUC under fixed tau = 0.50          |
|                                                                                                   |
|  Phase 5: Subgroup Analysis & Architecture Synthesis                                              |
|           Evaluate short vs. long messages, commercial spam confusion, URL-absent degradation     |
|           Deliver final evaluation report and determine production readiness                      |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### Phase 1: Controlled Pilot Acquisition
- Setup evaluation directory:
  `backend/reports/ml/text_eval_1_evaluation/`
- Download targeted raw data slices without fetching bulk extraneous archives:
  - From WSPR-NCSU: Acquire 1,000 representative smishing messages across distinct campaigns.
  - From UCI SMS: Acquire 1,000 legitimate ham messages and 300 commercial spam messages.
  - From IWSPA-AP / CEAS: Acquire 500 verified phishing email bodies and 1,000 legitimate email bodies.
- Store raw texts in isolated, immutable manifest files.

### Phase 2: Automated Independence Audit
- Run automated screening script using the validated SimHash index (`near_duplicate_audit/corpus_simhash_index.npz`).
- Any record matching:
  - Normalized SHA-256 hash in project corpus, OR
  - SimHash Hamming distance $\le 3$ AND character 5-gram Jaccard $\ge 0.90$, OR
  - URL pointing to a training holdout domain,
  is immediately quarantined and logged in `quarantine_audit.csv`.

### Phase 3: Benchmark Scoring on Frozen Models
- Load frozen models directly from disk:
  - V2 Baseline: `backend/models/text/phishing_tfidf_logreg_domain_grouped.joblib`
  - V3 Content-Only: `backend/reports/ml/phishing_v3_experiments/content_only_model.joblib`
  - V3 URL-Only: `backend/reports/ml/phishing_v3_experiments/url_only_model.joblib`
  - V3 Dual-Channel: `backend/reports/ml/phishing_v3_experiments/dual_channel_v3_model.joblib`
- Execute inference using their native pipeline preprocessors.
- Enforce the routing rule: evaluate V3 URL-Only **strictly on messages containing extractable URLs**.

### Phase 4: Deliverables & Reporting
Generate a comprehensive evaluation report in `backend/reports/ml/text_eval_1_evaluation/`:
- `text_eval_1_report.md`
- `cohort_performance_summary.csv`
- `subgroup_length_analysis.csv`
- `commercial_spam_false_positive_analysis.csv`
- `confusion_matrices.json`

---

## 3. Anticipated Research Findings & Risk Mitigation

1. **Short Message False Alarm Risk:**
   - *Anticipation:* Based on V3 validation data where Content-Only had 0% specificity on messages $\le 100$ characters, we anticipate that text models may trigger high false alarms on terse benign SMS (e.g., OTP notifications, delivery updates).
   - *Mitigation:* The benchmark explicitly isolates `short_messages_le_100` so that this vulnerability is accurately quantified rather than concealed within long email averages.
2. **URL-Absent Blind Spot:**
   - *Anticipation:* Phishing lures that request a phone callback or demand an instant message reply without a link will show 0% coverage for V3 URL-Only and attenuated recall for V3 Dual-Channel.
   - *Mitigation:* Cohort C2 explicitly isolates URL-absent lures to benchmark the necessity of specialized natural language features.
3. **Spam vs. Phishing Differentiation:**
   - *Anticipation:* Generic commercial spam (Cohort A3) may be misclassified as phishing by models trained on noisy web corpora.
   - *Mitigation:* Evaluating Cohort A3 separately ensures we measure whether the platform distinguishes nuisance marketing from malicious security threats.

---

## 4. Final Recommendation

**Proceed immediately to Phase 1 of Milestone TEXT-EVAL-1.**  
Acquire the WSPR-NCSU smishing corpus, the UCI SMS Ham baseline, and the IWSPA-AP / CEAS email bodies, execute the 4-stage independence screening, and establish the platform's first rigorous, independent plain-text phishing benchmark.
