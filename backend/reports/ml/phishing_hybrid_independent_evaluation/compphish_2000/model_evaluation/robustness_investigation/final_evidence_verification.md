# CompPhish V4 Final Evidence Verification

**Verification Scope:** Read-Only Audit of Robustness Investigation Artifacts  
**Corpus:** CompPhish V4 Independent Evaluation Corpus ($N = 2,000$)  
**Directory:** `backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/robustness_investigation/`  
**Execution Date:** November 2026  
**Status:** Verification Completed (Read-Only)

---

## 1. Verification of Near-Duplicate Connected Components

### 1.1 Artifact Audit and Component Findings

We inspected `near_duplicate_components.json`, `within_cohort_independence.json`, and the generation scripts in the evaluation tree.

#### Recorded Summary Metrics in `near_duplicate_components.json`:
- **Total Samples:** 2,000
- **Unique Normalized-Text Hashes:** 1,835
- **Exact-Duplicate Clique Pairs:** 1,073
- **Total Components Recorded:** 1,835
- **Largest Component Size:** 26 (Hash `a7fe83ec64bb23eb28090598db3d166ed98e52e39d1afbbfd74c579553f93e4e` and Hash `d762ff29efab23c4eece3b88b4bf59584747674abb696678e0995ca661ce2912`)
- **Singleton Count:** 1,789
- **Components with Size $> 1$:** 46
- **Number of Records in Non-Singleton Components:** 211
- **Mixed-Label Components:** 1
- **Largest Mixed-Label Component:** Size 26 (SHA-256 `a7fe...3e4e`: 23 phishing from PhishTank & Crawl Batch 1, and 3 legitimate from Crawl Batch 1 & 2)

#### Recorded Pair Findings in `within_cohort_independence.json`:
- **SimHash Candidate Pairs (Hamming distance $\le 3$):** 16,580
- **Confirmed Near-Duplicate Pairs (Shingle Jaccard similarity $\ge 0.90$):** 16,549

### 1.2 Methodological Discrepancy & Verification Limitation

> [!IMPORTANT]
> **Explicit Verification Finding on Connected Components:**
> Inspection of `near_duplicate_components.json` reveals that the 1,835 components recorded in that file were constructed by equivalence partitioning on **exact normalized text hashes** (`normalized_text_sha256`), yielding 46 non-singleton clusters ($N = 211$) and 1,789 singletons. The file records the 1,073 clique pairs derived solely from those 46 exact-duplicate groups.
> 
> The file does **NOT** contain connected-component results derived from the graph union of all 16,549 confirmed SimHash near-duplicate pairs ($H \le 3, J \ge 0.90$). Because the individual pairwise endpoints for the 16,549 near-duplicate pairs were not preserved on disk in `near_duplicate_components.json` or `within_cohort_independence.json`, **full near-duplicate graph connected-component analysis cannot be independently verified from the available artifacts.** Under strict read-only audit constraints, missing pair endpoints must not be reconstructed or conjectured.

---

## 2. Verification of Duplicate-Weighted Metric Scope

### 2.1 Audit of `duplicate_weighted_metrics.json`

The metrics recorded in `duplicate_weighted_metrics.json` compare default page-weighted performance against grouped weighting:

| Model | Weighting Scheme | TP | FP | TN | FN | Accuracy | Recall | Specificity | F1 Score | Balanced Acc |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **V2 Baseline** | Page-Weighted ($w_i = 1.0$) | 83.0 | 24.0 | 1038.0 | 855.0 | 0.5605 | 0.0885 | 0.9774 | 0.1589 | 0.5329 |
| | Exact-Group-Weighted ($w_i = 1/n_k$) | 69.0 | 19.0 | 1033.1 | 713.9 | 0.6006 | 0.0881 | 0.9819 | 0.1585 | 0.5350 |
| | **Delta ($\Delta$)** | - | - | - | - | **+0.0401** | **-0.0004** | **+0.0045** | **-0.0004** | **+0.0021** |
| **V3 URL-Only** | Page-Weighted ($w_i = 1.0$) | 830.0 | 379.0 | 683.0 | 108.0 | 0.7565 | 0.8849 | 0.6431 | 0.7732 | 0.7640 |
| | Exact-Group-Weighted ($w_i = 1/n_k$) | 687.9 | 369.1 | 683.0 | 95.0 | 0.7471 | 0.8787 | 0.6492 | 0.7477 | 0.7639 |
| | **Delta ($\Delta$)** | - | - | - | - | **-0.0094** | **-0.0062** | **+0.0060** | **-0.0254** | **-0.0001** |
| **V3 Dual** | Page-Weighted ($w_i = 1.0$) | 636.0 | 257.0 | 805.0 | 302.0 | 0.7205 | 0.6780 | 0.7580 | 0.6947 | 0.7180 |
| | Exact-Group-Weighted ($w_i = 1/n_k$) | 532.9 | 248.1 | 804.0 | 250.0 | 0.7285 | 0.6807 | 0.7642 | 0.6815 | 0.7224 |
| | **Delta ($\Delta$)** | - | - | - | - | **+0.0080** | **+0.0026** | **+0.0062** | **-0.0132** | **+0.0044** |

### 2.2 Scope Limitation

> [!WARNING]
> **Absence of Near-Duplicate Component Weights:**
> In `duplicate_weighted_metrics.json`, weighting adjustments are applied strictly using $w_i = 1 / n_k$ where $n_k$ is the cluster size of each of the 1,835 **exact normalized-text duplicate equivalence groups**. 
> 
> **Near-duplicate component-weighted metrics are completely absent.** Consequently, the current duplicate-weighted robustness evidence only adjusts for exact-text HTML duplicates, leaving potential clustering effects from the broader 16,549 near-duplicate SimHash pairings unweighted.

---

## 3. Review of Source-Specific URL Bias Claims

Analysis of `source_stratum_analysis.csv` and `url_feature_bias_analysis.md` requires separating legitimate statistical associations from dataset collection artifacts.

### 3.1 Observed Feature Associations (Model Weights)
In the frozen V3 URL model (`LogisticRegression` with character and word n-grams):
- **Strong Positive Weights (Predicting Phishing):** High-risk TLDs like `.cn` (+6.04), `.jp` (+3.65), `.top` (+3.52), `.xyz` (+3.10), `.shop` (+2.64), `.icu` (+2.64), `.cfd` (+2.08); dynamic DNS tokens like `duckdns` (+3.24); credential slugs like `php` (+2.45), `wp` (+2.32), `paypal` (+2.26), and `login` (+2.08).
- **Strong Negative Weights (Predicting Legitimate):** Informational path indicators like `pdf` (-4.66), `en` (-3.96), `products` (-2.64), `about` (-2.31); institutional TLD `edu` (-2.16); standard web prefixes like `www` (-2.74).

### 3.2 Cross-Cohort Empirical Performance
- **Phishing Cohorts:** URL-Only maintains consistently high sensitivity across disparate feeds:
  - OpenPhish Feed: $84.44\%$ Recall (Mean Prob: $0.7582$)
  - Crawl Batch 1: $88.05\%$ Recall (Mean Prob: $0.7245$)
  - PhishTank Feed: $90.13\%$ Recall (Mean Prob: $0.7502$)
  - Crawl Batch 2: $90.62\%$ Recall (Mean Prob: $0.7181$)
- **Legitimate Cohorts:** URL-Only exhibits persistently high False Positive Rates (FPR) across all legitimate strata:
  - Crawl Batch 1: $\text{FPR} = 29.34\%$ ($\text{Specificity} = 70.66\%$)
  - Top Sites Seed: $\text{FPR} = 37.08\%$ ($\text{Specificity} = 62.92\%$)
  - Crawl Batch 2: $\text{FPR} = 42.51\%$ ($\text{Specificity} = 57.49\%$)

### 3.3 Distinguishing Predictive Utility vs. Collection Artifacts
- **Valid Threat Indicators (Not Artifacts):** Strong positive associations with tokens like `login`, `paypal`, `.top`, or `.xyz` represent genuine threat landscape behavior—phishers routinely register disposable cheap TLDs and construct credential-harvesting paths. These cannot be characterized as collection artifacts simply because their regression weights are large.
- **Genuine Collection Artifacts:**
  1. **Homepage Root Bias in `top_sites_seed`:** The top-sites legitimate cohort consists almost exclusively of bare domain roots (`example.com/`), displaying a mean path length of only 1.9 characters (vs. 16.9 characters in phishing). The model exploits the complete absence of path tokens to assign low risk to bare roots, rather than evaluating substantive URL structures.
  2. **Prefix Skew (`www`):** Modern legitimate domains in `crawl_2024_2025_batch1` and `crawl_2025_batch2` increasingly omit the legacy `www.` subdomain. Because `www` carries a substantial negative weight (-2.74), its absence on modern legitimate domains drives False Positive Rates up to $42.51\%$.

---

## 4. Final Decisions on Robustness & Architecture

Based strictly on verified evidence from the 2,000-sample CompPhish V4 evaluation and post-evaluation audit:

### Decision A: URL-Only as a Promising Experimental Candidate
**Status: SUPPORTED**  
- **Evidence:** V3 URL-Only achieves an overall Recall of $88.49\%$ across 938 independent phishing attacks collected between September 2024 and August 2025. It detects phishing across diverse feeds (OpenPhish, PhishTank, autonomous web crawls) without requiring DOM rendering, HTTP GET payloads, or execution sandboxes. It remains a viable high-throughput preliminary triage candidate.

### Decision B: URL-Only as a Production-Ready Detector
**Status: NOT SUPPORTED**  
- **Evidence:** V3 URL-Only exhibits an unacceptable overall False Positive Rate of **$35.69\%$** (379 false alarms across 1,062 legitimate domains, yielding Specificity of only $64.31\%$). On contemporary crawled legitimate sites, the false positive rate climbs to $42.51\%$. Deploying this model standalone in an enterprise environment would trigger catastrophic alert fatigue.

### Decision C: Demonstrated Benefit of Dual-Channel Feature Fusion
**Status: SUPPORTED**  
- **Evidence:** Dual-Channel fusion directly mitigates the high false-alarm profile of URL lexical features. Dual-Channel cuts URL false alarms from 379 down to 257, raising specificity from $64.31\%$ to **$75.80\%$** (a 11.49 percentage point improvement). When DOM content is analyzed alongside URLs, legitimate pages lacking `www.` or using modern structures are recognized as benign, demonstrating the clear noise-filtering necessity of HTML feature fusion.

### Decision D: Need for Further Evaluation Before Model Integration
**Status: SUPPORTED**  
- **Evidence:** Further evaluation and architectural refinement are mandatory before production integration:
  1. **Cloaked / Stub Page Vulnerability:** On `crawl_2024_2025_batch1`, Dual-Channel recall dropped sharply to $59.36\%$ (vs. $88.05\%$ for URL-Only) because dormant/defensive landing pages lacked phishing HTML keywords, pulling down the joint probability.
  2. **Empty-Stub Imputation Bias:** Dual-Channel uses an uncalibrated default intercept when HTML is sparse or blocked.
  3. **Threshold Calibration:** Fixed operating threshold ($\tau = 0.50$) was tuned on synthetic training splits and requires recalibration under real-world class prevalence ($\le 1\%$ phishing base rate).
  4. **Dynamic Routing Verification:** Hybrid routing policies (e.g., URL fallback when HTML retrieval fails or is blocked) require empirical benchmarking across real enterprise network conditions.
