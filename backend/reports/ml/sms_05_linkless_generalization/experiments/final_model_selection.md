# SMS-05 Final Model Selection and Freezing Report

**Date**: November 2, 2026  
**Selected Candidate**: **SMS-05-C** (`sms_05_c_combined`)  
**Pipeline**: Combined Word + Character FeatureUnion + Logistic Regression  
**Frozen Model Artifact**: [`sms_05_model.joblib`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/sms_05_model.joblib)  
**Integrity Manifest**: [`model_integrity_manifest.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/model_integrity_manifest.json)  

---

## 1. Selection Justification (Validation Partition Evidence Only)

The decision to freeze **SMS-05-C** as the operational SMS-05 production candidate was reached strictly based on validation partition performance ($N = 1,305$):

1. **Maximized Linkless Recall ($90.59\%$)**:
   - Outperformed SMS-05-A ($89.41\%$), SMS-05-B ($89.02\%$), and SMS-05-D ($89.41\%$).
   - Successfully solves the structural linkless deficiency identified in SMS-03 without requiring brittle heuristics.
2. **Superior Balanced Accuracy ($95.53\%$) and F1 Score ($0.9482$)**:
   - Led all four architectures across both metrics.
3. **Rigorous False Positive Suppression**:
   - Tied for the lowest Ham FPR ($0.76\%$, $4/524$).
   - Achieved the lowest Commercial Spam FPR ($5.17\%$, $14/271$).
   - Avoided the false positive inflation observed in SMS-05-D (where structural features inflated Ham FPR to $1.72\%$ and Commercial Spam FPR to $7.38\%$).

---

## 2. Cryptographic Integrity Details

| Property | Value |
| :--- | :--- |
| **Model ID** | `sms_05_c_combined` |
| **Model Display Name** | SMS-05-C: Combined Word + Character FeatureUnion + Logistic Regression |
| **Artifact Relative Path** | `backend/reports/ml/sms_05_linkless_generalization/experiments/sms_05_c_combined/sms_05_model.joblib` |
| **Artifact File Size** | $2,884,128\text{ bytes}$ ($2.75\text{ MB}$) |
| **SHA-256 Digest** | `6b7ae684cde6bf041deb4963e6e5b4adf7c31ba12ceed2b6b1f838ccd7b77587` |
| **Operating Threshold** | $0.50$ (Frozen) |
| **Random Seed** | $20261102$ |
| **Input Modality** | Sanitized mobile SMS message text (plain string) |

---

## 3. Pipeline Architecture Specification

```
Pipeline(
  steps=[
    ('features', FeatureUnion(
      transformer_list=[
        ('word_branch', TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 2),
            sublinear_tf=True,
            lowercase=True,
            max_features=25000,
            min_df=2
        )),
        ('char_branch', TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 5),
            sublinear_tf=True,
            lowercase=True,
            max_features=50000,
            min_df=3
        ))
      ]
    )),
    ('classifier', LogisticRegression(
        C=1.0,
        class_weight='balanced',
        penalty='l2',
        solver='liblinear',
        random_state=20261102,
        max_iter=1000
    ))
  ]
)
```
