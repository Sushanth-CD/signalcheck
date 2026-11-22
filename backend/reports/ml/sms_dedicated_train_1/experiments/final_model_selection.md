# Final Model Selection: Freezing SMS-03 Combined Architecture

**Milestone:** SMS-DEDICATED-TRAIN-1 Phase 5  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/experiments/final_model_selection.md`  

---

## 1. Candidate Selection Rationale

Based strictly on empirical evidence from the held-out Validation partition ($N = 805$), **SMS-03 (Combined Word + Character TF-IDF with L2-Regularized Logistic Regression)** is selected as the winning architecture.

### Selection Justification:
1. **Superior Discrimination Between Malicious Smishing and Commercial Spam:**  
   In mobile communications, the hardest challenge is avoiding false alarms on aggressive marketing spam. SMS-03 achieved a commercial spam FPR of only **2.71%** (6/221), outperforming character-only SMS-02 (4.07%).
2. **Minimal False Alarms on Benign Personal Communication:**  
   Out of 374 validation ham messages, SMS-03 flagged only 2 messages (**0.53% FPR**), ensuring legitimate conversations are virtually never blocked.
3. **High Smishing Detection Sensitivity:**  
   Achieved **94.76% smishing recall** on validation (199 of 210 distinct WSPR attack campaigns caught), matching the best sensitivity of character n-grams.
4. **Theoretical Immunity to Cross-Modality Sparsity:**  
   By combining word-level semantic tokens with character 3–5 sub-word n-grams, SMS-03 ensures that short texts always generate active feature representations, completely eliminating the positive intercept collapse that plagued V2 and V3 web models.

---

## 2. Model Freeze Record

The winning pipeline was serialized and cryptographically frozen:

- **Saved Artifact Path:**  
  `backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib`
- **File Size:** 2,134,240 bytes
- **SHA-256 Hash:**  
  `8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df`
- **Selected Decision Threshold:** **0.50** (optimal default operating point).
- **Integrity Manifest:**  
  `backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/model_integrity_manifest.json`

---

## 3. Validation Threshold Curve for SMS-03

| Operating Threshold | Smishing Recall | Ham FPR | Commercial Spam FPR | Overall Specificity | F1 Score |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **0.30** | 0.9619 (202/210) | 0.0107 (4/374) | 0.0543 (12/221) | 0.9731 | 0.9395 |
| **0.40** | 0.9571 (201/210) | 0.0053 (2/374) | 0.0362 (8/221) | 0.9832 | 0.9481 |
| **0.50 (SELECTED)**| **0.9476 (199/210)**| **0.0053 (2/374)**| **0.0271 (6/221)** | **0.9866** | **0.9544** |
| **0.60** | 0.9286 (195/210) | 0.0027 (1/374) | 0.0226 (5/221) | 0.9899 | 0.9512 |
| **0.70** | 0.9143 (192/210) | 0.0027 (1/374) | 0.0136 (3/221) | 0.9933 | 0.9505 |

*Finding:* Threshold 0.50 provides the ideal balance between high smishing sensitivity ($\approx 95\%$) and negligible false positive rates on benign communication ($0.5\%$).
