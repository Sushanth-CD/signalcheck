# SMS-05 Candidate Models Comparison (Validation Partition)

**Experiment Date**: November 2, 2026  
**Dataset**: [`sms05_split_manifest.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/sms_05_linkless_generalization/dataset_v1/sms05_split_manifest.csv)  
**Partition Evaluated**: Validation ($N = 1,305$)  
**Operating Threshold**: Fixed at $0.50$  

---

## 1. Executive Summary

Four candidate SMS-specific phishing classifiers were trained on the multi-source, linkless-aware training partition ($N = 6,123$) and comprehensively evaluated on the validation partition ($N = 1,305$):
- **SMS-05-A**: Word TF-IDF ($1\text{--}2$ n-grams) + Logistic Regression ($C=1.0$, balanced).
- **SMS-05-B**: Character TF-IDF (`char_wb` $3\text{--}5$ n-grams) + Logistic Regression ($C=1.0$, balanced).
- **SMS-05-C**: Combined Word + Character FeatureUnion + Logistic Regression ($C=1.0$, balanced).
- **SMS-05-D**: Structured Two-Channel Model (Word + Char FeatureUnion + Text-derived Structural Features: `has_url`, `has_phone_number`, `is_premium_rate_prefix`, `has_currency_symbol`, `uppercase_ratio`, `punctuation_density`) + Logistic Regression ($C=1.0$, balanced).

**Winning Candidate**: **SMS-05-C** achieved the highest overall performance on the validation partition, delivering the top F1 score ($0.9482$), the highest Balanced Accuracy ($0.9553$), the highest ROC-AUC ($0.9904$), the highest Linkless Smishing Recall ($90.59\%$), while maintaining strict false-positive rate control on legitimate ham ($0.76\%$).

---

## 2. Validation Performance Table (N = 1,305)

| Metric | SMS-05-A (Word) | SMS-05-B (Char) | SMS-05-C (Combined) | SMS-05-D (Two-Channel) | Selection Advantage |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **F1 Score** | $0.9382$ | $0.9401$ | **$0.9482$** | $0.9400$ | **SMS-05-C (+0.81% over B)** |
| **Balanced Accuracy** | $0.9473$ | $0.9486$ | **$0.9553$** | $0.9504$ | **SMS-05-C (+0.67% over B)** |
| **Precision** | $0.9534$ | $0.9573$ | **$0.9636$** | $0.9428$ | **SMS-05-C (+0.63% over B)** |
| **Smishing Overall Recall** | $92.35\%$ ($471/510$) | $92.35\%$ ($471/510$) | **$93.33\%$** ($476/510$) | **$93.73\%$** ($478/510$) | SMS-05-D (+0.40% recall) |
| ↳ **Linkless Smishing Recall** | $89.41\%$ ($228/255$) | $89.02\%$ ($227/255$) | **$90.59\%$** ($231/255$) | $89.41\%$ ($228/255$) | **SMS-05-C (+1.18% over A/D)** |
| ↳ **URL-Bearing Smishing Recall** | $95.29\%$ ($243/255$) | $95.69\%$ ($244/255$) | $96.08\%$ ($245/255$) | **$98.04\%$** ($250/255$) | SMS-05-D (+1.96% over C) |
| **Ham False Positive Rate** | $1.53\%$ ($8/524$) | **$0.76\%$** ($4/524$) | **$0.76\%$** ($4/524$) | $1.72\%$ ($9/524$) | **SMS-05-B / C (Tied lowest)** |
| **Commercial Spam FPR** | $5.54\%$ ($15/271$) | $6.27\%$ ($17/271$) | **$5.17\%$** ($14/271$) | $7.38\%$ ($20/271$) | **SMS-05-C (Lowest)** |
| **Specificity** | $0.9711$ | $0.9736$ | **$0.9774$** | $0.9635$ | **SMS-05-C (Highest)** |
| **ROC-AUC** | $0.9873$ | $0.9869$ | **$0.9904$** | $0.9875$ | **SMS-05-C (Highest)** |
| **Average Precision (PR-AUC)** | $0.9833$ | $0.9826$ | **$0.9872$** | $0.9827$ | **SMS-05-C (Highest)** |
| **Fit Time (Train $N=6,123$)** | **$1.67\text{s}$** | $6.02\text{s}$ | $8.15\text{s}$ | $11.21\text{s}$ | SMS-05-A (Fastest) |

---

## 3. Comparative Observations

1. **Linkless Smishing Superiority of SMS-05-C**:
   - The primary objective of SMS-05 is resolving the linkless blind spot of SMS-03 (which had an internal linkless recall of near-zero and Mishra linkless recall of $0.64\%$).
   - On the validation set, **SMS-05-C reached $90.59\%$ linkless recall**, exceeding SMS-05-A ($89.41\%$), SMS-05-B ($89.02\%$), and SMS-05-D ($89.41\%$).
2. **False Positive Suppression**:
   - In SMS security, false positive alerts on legitimate interpersonal and transactional messages destroys user trust.
   - SMS-05-C tied with SMS-05-B for the lowest **Ham FPR ($0.76\%$, $4/524$)**, and achieved the strictly lowest **Commercial Spam FPR ($5.17\%$, $14/271$)**.
   - By contrast, SMS-05-D suffered higher false positives on both Ham ($1.72\%$) and Commercial Spam ($7.38\%$), because hand-crafted structural indicators like currency symbols, phone numbers, and uppercase ratios frequently trigger on legitimate bank notifications and marketing SMS.
3. **Lexical and Subword Synergy**:
   - The union of word unigrams/bigrams and character boundary $3\text{--}5$ n-grams allows the model to capture domain spoofing, obfuscated slang, financial urgency tokens, and brand typos simultaneously.
