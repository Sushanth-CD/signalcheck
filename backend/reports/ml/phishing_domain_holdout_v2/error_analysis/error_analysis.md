# Phishing Classifier V2 — Error Analysis Report

**Experiment:** `phishing_domain_holdout_v2`  
**Model:** TF-IDF (168,757 unigram/bigram features, sublinear TF) + Logistic Regression ($C=1.0$, `liblinear`)  
**Scope:** Primary Unseen-Destination Evaluation Cohort ($n = 1,993$ unique text groups)  
**Reference Threshold:** 0.50 (fixed; evaluated on validation partition)

---

## 1. Executive Summary & Test Results

On the primary unseen-destination test partition, the model achieves:
* **F1-Score:** 0.8950
* **Precision:** 0.9093
* **Recall:** 0.8811
* **Specificity:** 0.7466 (False Positive Rate = 25.34%)
* **ROC-AUC:** 0.9113
* **Average Precision:** 0.9651

### Test Confusion Matrix Breakdown ($n = 1,993$)
* **True Negatives (TN):** 383
* **False Positives (FP):** 130
* **False Negatives (FN):** 176
* **True Positives (TP):** 1,304

While phishing detection sensitivity is solid (88.11% recall), the **25.34% false positive rate (130 benign samples misclassified as phishing)** represents a substantial alert-fatigue vulnerability. Concurrently, **176 phishing attacks were completely missed (FN)**.

---

## 2. Analysis of False Positives ($n = 130$)

Benign records classified as phishing have a mean predicted phishing score of **0.6763** (median: **0.6447**).

### Key Patterns & Root Causes

1. **Short Bare URL Bias:**
   * 93.8% (122 / 130) of FP records are ultra-short strings ($\le 100$ characters, median normalized length is only **45 characters**).
   * In the combined dataset, many benign examples are full webpage HTML dumps or long text, whereas phishing examples are heavily concentrated in bare URL strings. Consequently, the model learned a strong structural correlation between "bare URL structure" and "phishing".
2. **Aggressive Token Weights on Web Infrastructure:**
   * Words like `https` ($\beta = +5.5526$) and `http` ($\beta = +3.6880$) are among the most positive phishing weights in the entire model. Because short benign URLs lack offsetting benign prose, the presence of `https://` alone pushes the logit strongly positive:
     * `https` alone contributed phishing evidence in **65 of the 130 FP records** (mean contribution: $+1.0311$).
     * `http` appeared in **38 FP records** (mean contribution: $+0.7145$).
3. **Generic Web & E-Commerce Tokens:**
   * Tokens that legitimately exist in benign website URLs trigger phishing penalties:
     * `login` ($\beta = +3.2254$): e.g., legitimate user portals or article links.
     * `php` ($\beta = +3.2430$): standard web backend file extensions on legacy or WordPress blogs.
     * `top` ($\beta = +3.6497$), `vip`, `shop`, `wp`: common top-level domains or directory paths.
     * Brand names like `amazon` ($\beta = +1.6826$) occurring in benign discussion or review URLs.

---

## 3. Analysis of False Negatives ($n = 176$)

Phishing attacks classified as benign have a mean predicted phishing score of **0.3280** (median: **0.3250**).

### Key Patterns & Root Causes

1. **HTML & Document Payload Dumps (Length Mismatch):**
   * **73.3% (129 / 176)** of false negatives contain full HTML document structures (median normalized text length is **8,758 characters**, with 117 records having $>5,000$ characters).
   * Phishing kits that clone full HTML landing pages introduce hundreds of standard boilerplate HTML tags, standard web prose, and footer content.
2. **Benign Token Drowning:**
   * The presence of legitimate HTML and English stop words overwhelms the phishing tokens. Negative coefficients associated with standard web layout terms suppress the score:
     * `www` ($\beta = -3.8457$): appeared in **119 of the 176 FN records**.
     * `html` / `htm` ($\beta = -3.2887$ / $-2.2809$): heavily pull score down.
     * `com` ($\beta = -0.3199$): present in 34 FN records.
     * Prose tokens like `the`, `and`, `about`, `products`, `reviews`, `software`.
3. **Impersonation & Financial Context Masked by Boilerplate:**
   * 53.4% of false negatives contain brand impersonation targets (e.g. Chase, PayPal, Microsoft, Apple, FedEx) and 51.7% contain financial terminology, but the model has no structural understanding of login forms or brand-domain mismatches; it merely averages TF-IDF weights across thousands of boilerplate terms.

---

## 4. Logistic Regression Feature Contribution Analysis

### Global Top-15 Feature Coefficients

| Rank | Phishing Driver Token | Coefficient | Benign Driver Token | Coefficient |
|:---:|:---|:---:|:---|:---:|
| 1 | `cn` | $+5.6017$ | `pdf` | $-5.1994$ |
| 2 | `https` | $+5.5526$ | `www` | $-3.8457$ |
| 3 | `http` | $+3.6880$ | `html` | $-3.2887$ |
| 4 | `top` | $+3.6497$ | `en` | $-2.8079$ |
| 5 | `jp` | $+3.4389$ | `software` | $-2.5189$ |
| 6 | `php` | $+3.2430$ | `htm` | $-2.2809$ |
| 7 | `login` | $+3.2254$ | `shtml` | $-2.2688$ |
| 8 | `wp` | $+2.9684$ | `org` | $-2.2621$ |
| 9 | `duckdns org` | $+2.8404$ | `edu` | $-2.1855$ |
| 10 | `duckdns` | $+2.8404$ | `products` | $-2.0302$ |
| 11 | `xyz` | $+2.4591$ | `the` | $-2.0121$ |
| 12 | `shop` | $+2.4154$ | `asp` | $-1.9693$ |
| 13 | `icu` | $+2.3644$ | `and` | $-1.9473$ |
| 14 | `com br` | $+2.3081$ | `aspx` | $-1.7961$ |
| 15 | `paypal` | $+2.2225$ | `com products` | $-1.7447$ |

### Misleading & High-Risk Token Dependencies
* **Protocol Indicators (`https`, `http`):** Assigning $+5.55$ to `https` reflects dataset distribution bias (benign text often had protocols stripped or was raw HTML prose, whereas phishing samples were raw URLs). In the modern web where $>95\%$ of benign sites use HTTPS, this token creates massive false positive vulnerability.
* **Structural Web Extensions (`www`, `html`):** Strongly negative weights ($-3.85$ and $-3.29$) allow full HTML phishing pages to bypass the classifier simply by including doctype declarations and `www` links.

---

## 5. Subgroup & Category Performance

Performance variations across structural patterns (analyzed on the test primary cohort):

| Category / Cohort | Record Count ($n$) | F1-Score | Specificity | FP | FN |
|:---|:---:|:---:|:---:|:---:|:---:|
| **All Test Primary** | 1,993 | 0.8950 | 0.7466 | 130 | 176 |
| **HTML Present** | 368 | 0.3483 | **0.9902** | 2 | **129** |
| **HTML Absent** | 1,625 | 0.9355 | **0.5858** | **128** | 47 |
| **Length 0–100 chars** | 1,368 | 0.9351 | **0.5704** | **122** | 25 |
| **Length 101–300 chars** | 184 | 0.9581 | 0.6250 | 6 | 8 |
| **Length 301–1,000 chars** | 48 | 0.9286 | 1.0000 | 0 | 6 |
| **Length 1,001–5,000 chars** | 91 | 0.6957 | 0.9787 | 1 | 20 |
| **Length 5,000+ chars** | 302 | 0.2716 | 0.9939 | 1 | **117** |
| **Brand Impersonation Mentioned** | 302 | 0.5740 | 0.9931 | 1 | 94 |
| **Financial Terms Present** | 207 | 0.4172 | 0.9512 | 4 | 91 |

*Notice the stark bifurcation:*
* **Short inputs ($\le 100$ chars):** Specificity drops to **57.04%** (responsible for **122 of the 130 FPs**).
* **Long HTML inputs ($>5,000$ chars):** Recall collapses, causing an F1 of **0.2716** (responsible for **117 of the 176 FNs**).

---

## 6. Threshold Analysis (Validation Partition Only)

Evaluated strictly on the primary validation domain cohort ($n = 2,004$; 515 benign, 1,489 phishing):
* **ROC-AUC:** 0.9215 | **Average Precision:** 0.9698

| Operating Threshold ($\tau$) | Validation F1 | Validation Precision | Validation Recall | Validation Specificity | Notes |
|:---:|:---:|:---:|:---:|:---:|:---|
| **0.26** | **0.9114** | 0.8535 | **0.9778** | 0.5146 | **Optimal F1 on Validation** (High recall, poor specificity) |
| **0.50** | 0.9021 | 0.9133 | 0.8912 | 0.7553 | **Current Reference Threshold** |
| **0.60** | 0.8879 | 0.9388 | 0.8422 | 0.8427 | Balanced reduction in false alarms |
| **0.68** | 0.8621 | **0.9589** | 0.7831 | **0.9010** | **Best F1 meeting Specificity $\ge 90\%$** |
| **0.75** | 0.8282 | 0.9723 | 0.7206 | 0.9417 | Strict alert environment (minimal FP) |

### Score Distribution by Quadrant (Validation Cohort)
* **True Positives ($n = 1,327$):** Mean = 0.8813, Median = 0.9370 ($p_{10} = 0.6558$)
* **False Positives ($n = 126$):** Mean = 0.6703, Median = 0.6301 ($p_{10} = 0.5283, p_{90} = 0.8820$)
* **True Negatives ($n = 389$):** Mean = 0.2063, Median = 0.1742 ($p_{90} = 0.4135$)
* **False Negatives ($n = 162$):** Mean = 0.3224, Median = 0.3256 ($p_{10} = 0.1794, p_{90} = 0.4638$)

A threshold shift from $0.50 \to 0.68$ on validation achieves $\ge 90\%$ specificity, cutting false positives by more than half, at the cost of lowering phishing recall from 89.1% to 78.3%.

---

## 7. Artifacts Summary

All detailed diagnostic datasets have been saved to:
`backend/reports/ml/phishing_domain_holdout_v2/error_analysis/`

* `error_analysis.md`: This comprehensive diagnostic report.
* `false_positive_analysis.csv`: All 130 test FPs with normalized snippet, lengths, and diagnostic flags.
* `false_negative_analysis.csv`: All 176 test FNs with diagnostic metadata.
* `feature_contribution_analysis.csv`: 3,608 rows detailing global and per-instance feature contributions.
* `threshold_analysis.json`: Full threshold sweep (0.05 to 0.95), quadrant score percentiles, and trade-off curves.
* `error_category_summary.json`: Granular confusion matrices across length buckets and linguistic categories.

---

## 8. Prioritized Recommendations for Model Improvement

### Recommendation 1: Input Modality Normalization & HTML Stripping
* **Evidence:** 73.3% of false negatives are full HTML documents ($>5,000$ chars) where benign web tags drown out phishing tokens, while 93.8% of false positives are bare URLs ($<100$ chars).
* **Action:** Preprocess inputs by stripping HTML markup, scripts, and CSS to extract plain text and isolated URLs before tokenization. Evaluate URLs and message body text via dedicated feature representations or dual-input channels rather than a single bag-of-words.

### Recommendation 2: Protocol & Infrastructure Token Filtering
* **Evidence:** `https` ($\beta = +5.5526$) and `http` ($\beta = +3.6880$) are the 2nd and 3rd strongest positive weights, directly driving over 50% of false positives on benign URLs. Conversely, `www` ($\beta = -3.8457$) and `html` ($\beta = -3.2887$) drive false negatives.
* **Action:** Remove generic web protocol schemes (`http`, `https`), common generic prefixes (`www`), and standard file extensions (`html`, `php`) from the bag-of-words vocabulary using an explicit domain-aware stopword list or specialized URL tokenization.

### Recommendation 3: Threshold Calibration & Tiered Alerting (Based on Validation)
* **Evidence:** At the current 0.50 threshold, specificity is only 74.66% (25.3% false alarm rate). The validation sweep demonstrates that elevating threshold $\tau$ to 0.68 achieves 90.1% specificity with 95.9% precision, while maintaining 78.3% recall.
* **Action:** In production awareness training, adopt a dual-threshold confidence policy (e.g., $\tau \ge 0.68$ for confirmed Phishing warnings, $0.35 \le \tau < 0.68$ for Suspicious/Review prompts, and $< 0.35$ for Benign) to mitigate user fatigue from high false alarm rates without completely discarding low-confidence phishing indicators.
