# SMS Model Readiness Decision & Go/No-Go Recommendation

**Audit Milestone:** SMS Model Readiness Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Decision Authority:** Lead Security & Machine Learning Architecture Review  

---

## 1. Summary of Audit Findings

1. **Root Cause of Cross-Modality Failure:**  
   The frozen V2, V3 Dual, V3 Content, and V3 URL models failed on SMS because they were trained almost entirely on HTML source code and web URLs (only 13 SMS records out of 9,481 training instances). Short text inputs lack the extensive web token vocabulary, causing the model to collapse to its positive training intercept ($\beta_0$) and yield false positive rates $> 96\%$.
2. **Data Availability in Open Ecosystem:**  
   Sufficient high-quality, open-license development data exists to train a specialized SMS model:
   - WSPR-NCSU offers over 35,000 distinct smishing campaigns under an MIT License.
   - Clean, non-overlapping subsets of UCI SMS Ham (>3,400 independent records) and ExAIS SMS (>5,200 records) provide diverse, authentic negative controls.
3. **Feasibility of Purpose-Built Architecture:**  
   A dual word-and-character n-gram TF-IDF pipeline with regularized Logistic Regression solves the sparsity problem, provides robustness against typo/slang variations, and runs with sub-millisecond latency on standard CPU hardware.

---

## 2. Definitive Decision: GO FOR DEDICATED SMS CLASSIFIER

> [!IMPORTANT]
> **FORMAL DECISION: GO.**  
> Authorization is granted to develop a separate, dedicated SMS / Mobile Phishing Classifier under the proposed `SMS-DEDICATED-TRAIN-1` protocol.

---

## 3. Mandatory Implementation Constraints

1. **No Alteration of Existing HTML Models:**  
   The frozen V2, V3 Dual, V3 Content, and V3 URL models must remain strictly untouched. They serve as specialized web-page and URL classifiers.
2. **Modality Separation at the API Gateway:**  
   FastAPI endpoints must implement explicit modality detection:
   - Inputs detected as HTML or DOM structures route to the Dual-Channel / Hybrid router.
   - Inputs detected as short plain-text messages or mobile texts route exclusively to the new dedicated SMS classifier.
3. **Diagnostic Reservation of the 250 Pilot Samples:**  
   The 250-message pilot acquired under TEXT-EVAL-1 must remain permanently quarantined from training and hyperparameter tuning. It serves as a benchmark for measuring progress.
4. **Next Planned Action:**  
   Execute the data assembly, grouping, and initial training run according to `sms_training_experiment_protocol.md`.
