# Phishing Classifier: Controlled Comparative Review (V2 vs. V3 Variants)

**Evaluation Date (UTC):** 2026-10-31 14:16:40  
**Evaluation Scope:** Strictly identical validation representatives ($n = 2,005$ total; $n = 2,004$ primary domain holdout cohort).  
**Protocol:** Read-only analysis. No models retrained. Zero test-set evaluation.

---

## 1. Population Audit (Resolution of the 2,004 vs. 2,005 Discrepancy)

* **Finding:** In the V2 experiment (`metrics.json`), two populations were reported:
  1. `all_model_eligible_unique_texts`: **2,005** unique text representatives.
  2. `primary_domain_evaluation`: **2,004** unique text representatives.
* **The Exactly Discrepant Record:**
  - **Source Record ID:** `combined_reduced.json:source_record_14145`
  - **Source Record Index:** `14145`
  - **Ground Truth Label:** `1` (Phishing)
  - **Text:** `chegalogo.com.br/verfied.par.visa/update/secure/672bfcaa73dbfe28bff5bc77604084fa/f38a762ac3ee6a66a497b43f5a9be87b/maj.html?id=`
  - **Root Cause:** In the split manifest, this record has `domain_evaluation_eligible = False` and `evaluation_scope = secondary_no_confident_destination` because it is an HTTP-like URL lacking an explicit scheme (`https://` or `http://`), leaving it classified as an ambiguous bare mention without an accepted primary destination key.
  - **Model Agreement:** **All 4 models correctly classify this record as phishing** (V2 score: 0.9345, Content-only: 0.7928, URL-only: 0.7850, Dual-channel: 0.8368).
* **Controlled Evaluation:** Both the full population ($n = 2,005$) and primary cohort ($n = 2,004$) are reported below; because this single record is a True Positive for all models, metrics between $n = 2,005$ and $n = 2,004$ differ by $< 0.0001$.

---

## 2. Recomputed Overall Comparative Metrics (Threshold = 0.50)

### On All Model-Eligible Validation Representatives ($n = 2,005$; 515 Benign, 1,490 Phishing)

| Model Architecture | Precision | Recall | F1-Score | Specificity | Accuracy | ROC-AUC | Avg Precision | Confusion Matrix (TN / FP / FN / TP) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **V2 Baseline (Single Bag-of-Words)** | 0.9133 | **0.8913** | **0.9022** | 0.7553 | **0.8564** | **0.9215** | 0.9698 | 389 / 126 / 162 / 1328 |
| **V3 Content-Only** | 0.8199 | 0.9383 | 0.8751 | 0.4039 | 0.8010 | 0.6852 | 0.8229 | 208 / 307 / 92 / 1398 |
| **V3 URL-Only** | 0.9092 | 0.8738 | 0.8912 | 0.7476 | 0.8414 | 0.9114 | 0.9689 | 385 / 130 / 188 / 1302 |
| **V3 Dual-Channel (Combined)** | **0.9161** | 0.8718 | 0.8934 | **0.7689** | 0.8454 | 0.9167 | **0.9709** | 396 / **119** / 191 / 1299 |

### On Primary Domain-Held-Out Validation Cohort ($n = 2,004$; 515 Benign, 1,489 Phishing)

| Model Architecture | Precision | Recall | F1-Score | Specificity | Accuracy | ROC-AUC | Avg Precision | Confusion Matrix (TN / FP / FN / TP) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **V2 Baseline** | 0.9133 | **0.8912** | **0.9021** | 0.7553 | **0.8563** | **0.9215** | 0.9698 | 389 / 126 / 162 / 1327 |
| **V3 Content-Only** | 0.8198 | 0.9382 | 0.8750 | 0.4039 | 0.8009 | 0.6852 | 0.8229 | 208 / 307 / 92 / 1397 |
| **V3 URL-Only** | 0.9092 | 0.8737 | 0.8911 | 0.7476 | 0.8413 | 0.9114 | 0.9689 | 385 / 130 / 188 / 1301 |
| **V3 Dual-Channel** | **0.9160** | 0.8717 | 0.8933 | **0.7689** | 0.8453 | 0.9167 | **0.9709** | 396 / **119** / 191 / 1298 |

---

## 3. Subgroup Comparative Analysis

Subgroup metrics recomputed on identical validation records ($n = 2,005$):

| Subgroup | Model | Sample Count | Precision | Recall | F1-Score | Specificity | FP | FN |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **HTML Messages** | **V2 Baseline** | 377 | 0.5362 | 0.2372 | 0.3289 | **0.9683** | **7** | 119 |
| | **V3 Content-Only** | 377 | 0.7200 | 0.5769 | 0.6406 | 0.8416 | 35 | 66 |
| | **V3 URL-Only** | 377 | 0.6691 | **0.5833** | 0.6233 | 0.7964 | 45 | **65** |
| | **V3 Dual-Channel** | 377 | **0.8421** | 0.5128 | **0.6375** | 0.9321 | 15 | 76 |
| **Short Messages ($\le 100$ chars)** | **V2 Baseline** | 1,432 | 0.9377 | **0.9752** | **0.9561** | 0.7148 | 75 | **29** |
| | **V3 Content-Only** | 1,432 | 0.8162 | 0.9991 | 0.8985 | 0.0000 | 263 | 1 |
| | **V3 URL-Only** | 1,432 | **0.9363** | 0.9307 | 0.9335 | **0.7186** | **74** | 81 |
| | **V3 Dual-Channel** | 1,432 | 0.9183 | 0.9427 | 0.9304 | 0.6274 | 98 | 67 |
| **Long Messages ($>1,000$ chars)** | **V2 Baseline** | 410 | 0.5405 | 0.2326 | 0.3252 | **0.9664** | **8** | 132 |
| | **V3 Content-Only** | 410 | 0.7120 | 0.5174 | 0.5993 | 0.8487 | 36 | 83 |
| | **V3 URL-Only** | 410 | 0.6667 | **0.6047** | 0.6341 | 0.7815 | 52 | **68** |
| | **V3 Dual-Channel** | 410 | **0.8544** | 0.5116 | **0.6400** | 0.9370 | 15 | 84 |
| **URL-Containing Messages** | **V2 Baseline** | 2,004 | 0.9133 | **0.8912** | **0.9021** | 0.7553 | 126 | **162** |
| | **V3 Content-Only** | 2,004 | 0.8198 | 0.9382 | 0.8750 | 0.4039 | 307 | 92 |
| | **V3 URL-Only** | 2,004 | 0.9092 | 0.8737 | 0.8911 | 0.7476 | 130 | 188 |
| | **V3 Dual-Channel** | 2,004 | **0.9160** | 0.8717 | 0.8933 | **0.7689** | **119** | 191 |
| **Messages Without URLs** | All Models | 1 | 1.0000 | 1.0000 | 1.0000 | N/A | 0 | 0 |

---

## 4. Key Subgroup Findings

1. **HTML & Long Message Breakthrough:**
   * In V2, HTML messages suffered catastrophic false negative collapse (Recall = 23.72%, F1 = 0.3289, 119 phishing messages missed).
   * **V3 Dual-Channel nearly doubles the F1-score to 0.6375** and boosts Precision to **84.21%** while cutting false negatives from 119 to 76.
   * This confirms that stripping scripts, styles, and HTML markup prevents boilerplate from drowning out phishing tokens.
2. **False Alarm Reduction (Specificity):**
   * On the full validation set, **V3 Dual-Channel achieves the highest Specificity (76.89%) and lowest False Positives (119 vs. 126)**, and highest Average Precision (0.9709).
3. **Trade-Off on Short Messages:**
   * On short messages ($\le 100$ characters, consisting mostly of bare URLs), V2 retained an edge in Recall (97.52% vs. 94.27% for V3 Dual, and 93.07% for V3 URL-only). V2's unigram/bigram model over raw URL strings captured raw text punctuation artifacts that were slightly more sensitive in this cohort, though prone to the `https` false-positive bias observed in the V2 error analysis.

---

## 5. Threshold Operating Points Comparison (Validation Only)

| Model | Operating Point | Threshold ($	au$) | Precision | Recall | F1-Score | Specificity |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **V2 Baseline** | Reference | 0.50 | 0.9133 | 0.8913 | 0.9022 | 0.7553 |
| | Max F1 | 0.26 | 0.8535 | 0.9778 | 0.9114 | 0.5146 |
| | High Specificity ($\ge 90\%$) | 0.68 | 0.9589 | 0.7831 | 0.8621 | 0.9010 |
| **V3 Content-Only** | Reference | 0.50 | 0.8199 | 0.9383 | 0.8751 | 0.4039 |
| | Max F1 | 0.65 | 0.8596 | 0.8980 | 0.8783 | 0.5592 |
| | High Specificity ($\ge 90\%$) | 0.90 | 0.9392 | 0.6289 | 0.7533 | 0.9068 |
| **V3 URL-Only** | Reference | 0.50 | 0.9092 | 0.8738 | 0.8912 | 0.7476 |
| | Max F1 | 0.34 | 0.8732 | 0.9188 | 0.8954 | 0.6136 |
| | High Specificity ($\ge 90\%$) | 0.70 | 0.9577 | 0.7960 | 0.8694 | 0.9010 |
| **V3 Dual-Channel** | Reference | 0.50 | **0.9161** | 0.8718 | 0.8934 | **0.7689** |
| | Max F1 | 0.35 | 0.8766 | 0.9201 | 0.8978 | 0.6252 |
| | High Specificity ($\ge 90\%$) | 0.70 | **0.9612** | 0.7973 | **0.8716** | **0.9068** |

At the high-specificity operating point ($	au = 0.70$), **V3 Dual-Channel achieves the highest precision (96.12%) and highest F1 (0.8716) of any model**, cutting false positives from 119 down to 48.

---

## 6. Architectural Decision & Recommendation

### Recommendation: **CONDITIONAL GO**

#### Rationale:
1. **Definite Structural Advancement for HTML & Web Content:**
   V3 Dual-Channel successfully fixes the primary structural weakness identified in V2's error analysis: HTML messages jumped from an F1 of **0.3289 to 0.6375**, and precision on HTML jumped from **53.62% to 84.21%**, eliminating over 40 false negatives caused by HTML markup dilution.
2. **False Positive & Specificity Improvement:**
   V3 Dual-Channel achieves the best overall validation specificity (**76.89%** vs. 75.53%) and precision (**91.61%** vs. 91.33%), directly addressing user alert-fatigue.
3. **Condition for Final Production Deployment:**
   - Overall F1 on the full validation partition is marginally lower (0.8934 vs. 0.9022) due to lower recall on short bare-URL strings.
   - **Condition:** Do not replace V2 in production immediately. Proceed with V3 under an ensemble or routing policy (e.g., routing HTML/body inputs to V3 Dual-Channel, while maintaining V2/URL-focused weighting on pure bare URLs), and evaluate V3 against V2 on a **fresh, independent, unseen test cohort** that has not been inspected during development.
