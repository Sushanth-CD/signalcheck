# Post-Evaluation Audit Report: CompPhish V4 2,000-Sample Independent Evaluation

**Audit Date:** 2026-11-01 21:30:00 UTC  
**Target Evaluation Directory:** `backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/`  
**Audit Status:** Complete — Read-Only Verification  

---

## Executive Summary of Audit Findings

1. **Within-Cohort Independence:**
   - All 2,000 accepted samples originate from **2,000 unique, strictly disjoint domain grouping keys** (0 domain collisions).
   - Among the 2,000 samples, there are **1,835 unique normalized text SHA-256 hashes**.
   - Exactly **46 duplicate text groups** (encompassing **211 total records**, or **165 redundant duplicate instances**) exist within the cohort across distinct domains.
   - All within-cohort text duplicate instances correspond to universal web boilerplate (empty 39-byte HTML shells, generic web server error templates, or standard parking notices).
   - Exactly **one group** (hash `a7fe83ec64bb`, $N=26$) spans both classes (23 phishing landing pages and 3 legitimate crawl targets hosting the identical minimal container `<html><head></head><body></body></html>`).
   - Pairwise SimHash shingling ($H \le 3$, $J \ge 0.90$) identified **16,580 candidate pairs** and **16,549 confirmed near-duplicate pairs**, primarily driven by shared minimal markup across distinct domains.
   - In accordance with audit instructions, **zero samples were removed**, preserving the empirical baseline of the independent evaluation.

2. **Metric Reproduction:**
   - **100% exact reproduction across all models, operating thresholds, and metrics.**
   - All confusion matrix counts ($\text{TN}$, $\text{FP}$, $\text{FN}$, $\text{TP}$), accuracy, precision, recall, specificity, F1 score, balanced accuracy, ROC-AUC, and Average Precision / PR-AUC matched `metrics.json` and `predictions.csv` with zero discrepancies.
   - Primary decision threshold 0.50 and sensitivity thresholds ($0.26 / 0.68$ for V2; $0.35 / 0.70$ for V3 Dual) reproduced identically.

3. **Subgroup Metric Interpretation Corrections:**
   - The initial subgroup summary (`subgroup_metrics.csv`) reported standard positive-class precision and F1 inside single-class strata, causing legitimate strata to display trivial `0.0` precision/F1 and phishing strata to display inflated `1.0` precision.
   - A corrected analysis file, [`subgroup_metrics_corrected.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/subgroup_metrics_corrected.csv), has been generated with class-appropriate metrics (correct legitimate samples, false positives, specificity, and false positive rate for legitimate strata; detected phishing samples, missed phishing samples, recall, and false negative rate for phishing strata).

4. **Hybrid Routing Verification:**
   - 100% ($2,000 / 2,000$) of samples were detected as valid HTML documents by the established regex.
   - Both **Policy 3** and **Policy 4** routed **2,000 samples to V3 Dual** and **0 samples to V2 Baseline**.
   - Route agreement between Policy 3 and Policy 4 is **100.0%**.
   - Crucially, this evaluation provides **zero empirical validation** of routing behavior on non-HTML inputs (SMS, plain text emails, or files) where Policy 3 and Policy 4 diverge.

5. **Evidence-Based Model Assessment (URL-Only vs. Dual-Channel):**
   - Combining URL and content features does **not** monotonically improve every metric; rather, it introduces a pronounced operational trade-off.
   - `V3 URL-Only` maximizes threat capture ($\text{Recall}=0.8849$, $\text{F1}=0.7732$), missing only 108 phishing pages.
   - `V3 Dual-Channel` enforces content confirmation, sharply reducing false alarms from 379 down to 257 (filtering 145 URL false positives and boosting specificity from $0.6431$ to $0.7580$), but inadvertently suppresses 197 true phishing detections where landing pages served minimal or evasive content ($\text{Recall}$ drops to $0.6780$).
   - `V2 Baseline` text-only TF-IDF suffers probability compression ($90\%$ of probabilities fall below $0.4616$), collapsing at threshold 0.50 ($\text{Recall}=0.0885$), but recovering to $\text{Recall}=0.8006$ at threshold 0.26.

---

## 1. Within-Cohort Independence Audit

### Methodology & Definitions
- **Normalization:** NFKC Unicode normalization, case-folding, and whitespace collapsing (`unicodedata.normalize("NFKC", text).casefold()`).
- **Exact Hash:** SHA-256 computed on normalized text strings.
- **Character 5-gram SimHash:** 64-bit integer fingerprints calculated from character 5-grams.
- **Near-Duplicate Screening:** Hamming distance $H \le 3$ with exact character 5-gram Jaccard similarity $J \ge 0.90$.

### Audit Results

| Metric Category | Count / Finding | Technical Description |
| :--- | :---: | :--- |
| **Total Samples Evaluated** | 2,000 | 1,062 legitimate, 938 phishing |
| **Unique Domain Grouping Keys** | 2,000 | 100.0% unique; exactly 1 sample per registrable domain or distinct host key |
| **Unique Normalized Text Hashes** | 1,835 | 165 redundant duplicate instances ($2,000 - 1,835 = 165$) |
| **Distinct Duplicate Text Groups** | 46 | Groups containing $\ge 2$ samples with identical normalized text |
| **Total Records in Duplicate Groups** | 211 | Samples sharing text hashes across distinct domains |
| **Cross-Class Duplicate Groups** | 1 | Group sharing identical text between legitimate and phishing samples |
| **Cross-Class Duplicate Records** | 26 | 23 phishing, 3 legitimate (Hash `a7fe83ec64bb...`) |
| **SimHash Candidate Pairs ($H \le 3$)** | 16,580 | Pairwise candidate pairs within Hamming radius 3 |
| **Confirmed Near-Duplicate Pairs ($J \ge 0.90$)** | 16,549 | Pairwise pairs with confirmed shingle overlap $\ge 90\%$ |

### Top Within-Cohort Exact Duplicate Groups

| Normalized Text SHA-256 (Prefix) | Count ($N$) | Ground Truth Labels | Sample Serial Numbers (First 4) | Example Registrable Domains | Root Nature of Duplicate |
| :--- | :---: | :--- | :--- | :--- | :--- |
| `a7fe83ec64bb` | 26 | Phishing (23), Legit (3) | `9157096`, `202420256114`, `202420255956`, `202420261595` | `multifixedchain.web.app`, `exhentai.org`, `mbtrx.com`, `gestaoescolar.org.br` | Empty 39-byte HTML container (`<html><head></head><body></body></html>`) |
| `d762ff29efab` | 26 | Phishing (26) | `9160700`, `9162472`, `9162479`, `9162532` | `pl-oferta124565.sbs`, `pl-oferta926481634.cfd`, `pl-293474.icu`, `pl-6532595.icu` | Phishing campaign boilerplate / redirect shell |
| `653d6bbe21f8` | 17 | Phishing (17) | `202420255630`, `202420255703`, `202420255211`, `202420254915` | `legalbuzzzone.vercel.app`, `warningadgen.vercel.app`, `moderationtoolbrandhype.vercel.app`, etc. | Vercel SaaS-hosted phishing template boilerplate |
| `b3b0da6ab101` | 12 | Phishing (12) | `202420250813`, `202420251067`, `202420251078`, `202420250805` | `r2.dev` multi-tenant endpoints | Cloudflare R2 worker hosting identical phishing script wrappers |
| `db4275899558` | 11 | Phishing (11) | `83500`, `83000`, `91100`, `80900` | Distinct second-level attack domains | PhishTank feed attack campaign sharing identical landing page |
| `cb46232557f9` | 5 | Legitimate (5) | `202420256040`, `202420256121`, `202420256106`, `202420256160` | Regional crawl targets | Standard 404 / 500 error page or domain parking notice |

### Cross-Class Text Collision Details
The sole cross-class text collision group (`a7fe83ec64bb`, $N=26$) represents a raw 39-byte stub (`<html><head></head><body></body></html>`):
- **Phishing Samples (23):** Evasive phishing campaigns where the crawler was served an empty wrapper, JavaScript payload container, or blocked crawler stub (e.g. `multifixedchain.web.app`, `service-relaycolis.info`, `oferta-591274.icu`).
- **Legitimate Samples (3):** Dormant, parked, or placeholder domains (e.g. `exhentai.org`, `mbtrx.com`, `gestaoescolar.org.br`) serving blank containers during collection.

**Conclusion:** Within-cohort duplicates reflect standard real-world web phenomena (shared hosting templates, SaaS scaffolds, and blank containers across distinct registrable domains). Zero samples require removal.

---

## 2. Independent Recomputation of Aggregate Evaluation Metrics

All metrics were recomputed directly from `predictions.csv` using frozen ground truth labels ($1=\text{phishing}$, $0=\text{legitimate}$) and positive-class decision rule $\hat{y} = \mathbb{I}(p \ge \tau)$.

### Recomputed Metric Verification Table

| Model / Policy Name | Operating Point ($\tau$) | TN | FP | FN | TP | Accuracy | Precision | Recall | Specificity | F1 Score | Bal. Acc | ROC-AUC | PR-AUC | Audit Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **V2_Baseline** | **0.50** | 1038 | 24 | 855 | 83 | 0.5605 | 0.775701 | 0.088486 | 0.977401 | 0.158852 | 0.532944 | 0.812464 | 0.754692 | **MATCH** |
| **V2_Baseline** | **0.26** | 700 | 362 | 187 | 751 | 0.7255 | 0.674753 | 0.800640 | 0.659134 | 0.732326 | 0.729887 | 0.812464 | 0.754692 | **MATCH** |
| **V2_Baseline** | **0.68** | 1062 | 0 | 938 | 0 | 0.5310 | 0.000000 | 0.000000 | 1.000000 | 0.000000 | 0.500000 | 0.812464 | 0.754692 | **MATCH** |
| **V3_Content_Only** | **0.50** | 698 | 364 | 647 | 291 | 0.4945 | 0.444275 | 0.310235 | 0.657250 | 0.365348 | 0.483742 | 0.599480 | 0.537618 | **MATCH** |
| **V3_URL_Only** | **0.50** | 683 | 379 | 108 | 830 | 0.7565 | 0.686518 | 0.884861 | 0.643126 | 0.773215 | 0.763994 | 0.832946 | 0.793132 | **MATCH** |
| **V3_Dual_Channel** | **0.50** | 805 | 257 | 302 | 636 | 0.7205 | 0.712206 | 0.678038 | 0.758004 | 0.694702 | 0.718021 | 0.786221 | 0.726584 | **MATCH** |
| **V3_Dual_Channel** | **0.35** | 626 | 436 | 143 | 795 | 0.7105 | 0.645816 | 0.847548 | 0.589454 | 0.733057 | 0.718501 | 0.786221 | 0.726584 | **MATCH** |
| **V3_Dual_Channel** | **0.70** | 942 | 120 | 550 | 388 | 0.6650 | 0.763780 | 0.413646 | 0.887006 | 0.536653 | 0.650326 | 0.786221 | 0.726584 | **MATCH** |
| **Hybrid_Policy_3** | **0.50** | 805 | 257 | 302 | 636 | 0.7205 | 0.712206 | 0.678038 | 0.758004 | 0.694702 | 0.718021 | 0.786221 | 0.726584 | **MATCH** |
| **Hybrid_Policy_4** | **0.50** | 805 | 257 | 302 | 636 | 0.7205 | 0.712206 | 0.678038 | 0.758004 | 0.694702 | 0.718021 | 0.786221 | 0.726584 | **MATCH** |

**Discrepancies:** Zero. All values in `metrics.json` reproduced with 100% precision.

---

## 3. Subgroup Metric Interpretation & Correction

In single-class evaluation cohorts, reporting standard positive-class precision and F1 is mathematically degenerative:
- On **legitimate-only strata** ($y=0$ for all samples), $\text{TP}=0$ and $\text{FN}=0$. Thus, $\text{Precision} = \frac{0}{0 + \text{FP}} = 0.0$ and $\text{F1} = 0.0$ regardless of how accurately the model classifies benign sites.
- On **phishing-only strata** ($y=1$ for all samples), $\text{TN}=0$ and $\text{FP}=0$. Thus, $\text{Precision} = \frac{\text{TP}}{\text{TP} + 0} = 1.0$ regardless of how many phishing samples are missed.

### Corrected Stratum Breakdown (Threshold 0.50)

#### A. Legitimate Strata ($N=1,062$)

| Model Name | Stratum Name | Sample Count ($N$) | Correct Legitimate ($\text{TN}$) | False Positives ($\text{FP}$) | Specificity ($\frac{\text{TN}}{N}$) | False Positive Rate ($\frac{\text{FP}}{N}$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **V2_Baseline** | `crawl_2024_2025_batch1` | 392 | 381 | 11 | 0.971939 | 0.028061 |
| **V2_Baseline** | `top_sites_seed` | 383 | 377 | 6 | 0.984334 | 0.015666 |
| **V2_Baseline** | `crawl_2025_batch2` | 287 | 280 | 7 | 0.975610 | 0.024390 |
| **V3_Content_Only** | `crawl_2024_2025_batch1` | 392 | 294 | 98 | 0.750000 | 0.250000 |
| **V3_Content_Only** | `top_sites_seed` | 383 | 221 | 162 | 0.577023 | 0.422977 |
| **V3_Content_Only** | `crawl_2025_batch2` | 287 | 183 | 104 | 0.637631 | 0.362369 |
| **V3_URL_Only** | `crawl_2024_2025_batch1` | 392 | 277 | 115 | 0.706633 | 0.293367 |
| **V3_URL_Only** | `top_sites_seed` | 383 | 241 | 142 | 0.629243 | 0.370757 |
| **V3_URL_Only** | `crawl_2025_batch2` | 287 | 165 | 122 | 0.574913 | 0.425087 |
| **V3_Dual_Channel** | `crawl_2024_2025_batch1` | 392 | 302 | 90 | **0.770408** | **0.229592** |
| **V3_Dual_Channel** | `top_sites_seed` | 383 | 291 | 92 | **0.759791** | **0.240209** |
| **V3_Dual_Channel** | `crawl_2025_batch2` | 287 | 212 | 75 | **0.738676** | **0.261324** |
| **Hybrid_Policy_3/4** | *(Identical to V3 Dual across all 3 legitimate strata)* | | | | | |

#### B. Phishing Strata ($N=938$)

| Model Name | Stratum Name | Sample Count ($N$) | Detected Phishing ($\text{TP}$) | Missed Phishing ($\text{FN}$) | Recall ($\frac{\text{TP}}{N}$) | False Negative Rate ($\frac{\text{FN}}{N}$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **V2_Baseline** | `crawl_2024_2025_batch1` | 502 | 67 | 435 | 0.133466 | 0.866534 |
| **V2_Baseline** | `phishtank_feed` | 314 | 8 | 306 | 0.025478 | 0.974522 |
| **V2_Baseline** | `openphish_feed` | 90 | 1 | 89 | 0.011111 | 0.988889 |
| **V2_Baseline** | `crawl_2025_batch2` | 32 | 7 | 25 | 0.218750 | 0.781250 |
| **V3_Content_Only** | `crawl_2024_2025_batch1` | 502 | 199 | 303 | 0.396414 | 0.603586 |
| **V3_Content_Only** | `phishtank_feed` | 314 | 57 | 257 | 0.181529 | 0.818471 |
| **V3_Content_Only** | `openphish_feed` | 90 | 19 | 71 | 0.211111 | 0.788889 |
| **V3_Content_Only** | `crawl_2025_batch2` | 32 | 16 | 16 | 0.500000 | 0.500000 |
| **V3_URL_Only** | `crawl_2024_2025_batch1` | 502 | 442 | 60 | **0.880478** | **0.119522** |
| **V3_URL_Only** | `phishtank_feed` | 314 | 283 | 31 | **0.901274** | **0.098726** |
| **V3_URL_Only** | `openphish_feed` | 90 | 76 | 14 | **0.844444** | **0.155556** |
| **V3_URL_Only** | `crawl_2025_batch2` | 32 | 29 | 3 | **0.906250** | **0.093750** |
| **V3_Dual_Channel** | `crawl_2024_2025_batch1` | 502 | 298 | 204 | 0.593625 | 0.406375 |
| **V3_Dual_Channel** | `phishtank_feed` | 314 | 255 | 59 | 0.812102 | 0.187898 |
| **V3_Dual_Channel** | `openphish_feed` | 90 | 62 | 28 | 0.688889 | 0.311111 |
| **V3_Dual_Channel** | `crawl_2025_batch2` | 32 | 21 | 11 | 0.656250 | 0.343750 |
| **Hybrid_Policy_3/4** | *(Identical to V3 Dual across all 4 phishing strata)* | | | | | |

---

## 4. Hybrid Routing Verification

| Verification Dimension | Finding / Value | Audit Decision |
| :--- | :---: | :--- |
| **Total Samples Evaluated** | 2,000 | Confirmed |
| **HTML Detected Samples** | 2,000 (100.0%) | Confirmed via `is_html_detected` flag |
| **Policy 3 Branch Distribution** | `V3_Dual`: 2,000 (100.0%), `V2_Baseline`: 0 | Confirmed |
| **Policy 4 Branch Distribution** | `V3_Dual`: 2,000 (100.0%), `V2_Baseline`: 0 | Confirmed |
| **Route Agreement Count** | 2,000 / 2,000 (100.0%) | Confirmed |
| **Prediction Agreement at 0.50** | 2,000 / 2,000 (100.0%) | Confirmed |
| **Probability Agreement** | 2,000 / 2,000 (100.0%) | Confirmed |

> [!WARNING]
> **Essential Evaluation Boundary:**  
> Because **100%** of the CompPhish V4 evaluation corpus consists of valid HTML landing pages, **both Policy 3 and Policy 4 executed identically on every record**. This evaluation **does NOT** test or validate routing on non-HTML inputs (e.g. plain text emails, SMS lures, binary files, or missing content), where Policy 3 routes to V2 and Policy 4 routes to V3 URL-Only. Any claim of generalized router validation across modalities is unsupported by this corpus.

---

## 5. Technical Reassessment: URL-Only versus Dual-Channel

The empirical data on CompPhish V4 reveals critical architectural trade-offs:

```
               [URL-Only Predictions]
                      /    \
            FP=379            TP=830
           /      \          /      \
Dual filters    Dual misses Dual retains Dual suppresses
 145 to TN       234 as FP   633 as TP     197 to FN
    │                          │
    ▼                          ▼
Higher Specificity         Lower Recall
 (+12.2% over URL)          (-20.7% under URL)
```

1. **Why URL-Only Achieves Higher Recall ($0.8849$) and F1 ($0.7732$):**
   - Phishing attacks systematically rely on structural URL manipulation (suspicious tokens, high character entropy, multi-subdomains, free-tier hosting patterns such as `*.web.app`, `*.r2.dev`, `*.sbs`).
   - The lexical and character n-gram URL pipeline aggressively flags these indicators without being misled by what is (or is not) rendered inside the HTML DOM.
   - Consequently, URL-Only detects 830 of 938 phishing attacks (missing only 108).

2. **Why Dual-Channel Achieves Higher Specificity ($0.7580$) and Precision ($0.7122$):**
   - Complex legitimate URLs (e.g., deep regional portals, e-commerce affiliate redirects, tracking parameters) frequently trigger false alarms in URL-Only ($379$ false positives).
   - In 145 instances, benign DOM body text (dense legitimate vocabulary, standard corporate legal copy, normal language structure) successfully counteracts the suspicious URL score, converting an initial false alarm into a correct true negative ($\text{TN}$).
   - This suppresses false alarms by $32.2\%$ ($379 \to 257$), raising specificity from $0.6431$ to $0.7580$.

3. **Does Dual-Channel Provide an Advantage Over URL-Only on This Corpus?**
   - **Nuanced Trade-off, Not Unilateral Dominance:**
     - Content rescued missed phishing URLs in only **3 samples** ($\text{URL FN} \to \text{Dual TP}$).
     - In contrast, evasive or blank HTML landing pages (e.g., parking pages, blank DOM shells, JavaScript obfuscation) caused the content channel to dilute strong URL threat signals, converting **197 true phishing detections into false negatives** ($\text{URL TP} \to \text{Dual FN}$).
     - Thus, Dual-Channel functions primarily as a **false-alarm suppression filter** rather than an attack-discovery engine. It provides an advantage if minimizing false positives is prioritized over raw threat capture.

4. **Why V2 Baseline Varies Wildly With Threshold:**
   - **Extreme Probability Compression:**
     - Pure word TF-IDF on raw HTML encounters severe out-of-vocabulary and noise issues. $90\%$ of all V2 probabilities fall below $0.4616$, and even for phishing records, the median probability is only $0.3829$.
     - At $\tau = 0.50$, the decision boundary sits in the upper tail of the model's output distribution, yielding an abysmal recall of $0.0885$ ($\text{FN}=855$).
     - Lowering $\tau$ to $0.26$ aligns with the true compressed distribution, dramatically recovering recall to $0.8006$ ($\text{TP}=751$), while increasing false positives to $362$.
     - Raising $\tau$ to $0.68$ exceeds the maximum probability assigned to any phishing sample, causing recall to collapse to exactly $0.0000$.

5. **Why Evaluation Metrics Cannot Be Directly Interpreted as Production Precision:**
   - **Prevalence Distortion (Base-Rate Fallacy):**
     - This test corpus has a phishing prevalence of $46.90\%$ ($938 / 2,000$).
     - In enterprise web browsing and gateway filtering, phishing prevalence is typically $<0.1\%$ (less than 1 in 1,000 requests).
     - Under Bayes' Theorem, a model with specificity $0.7580$ (false positive rate $\approx 24.2\%$) deployed in a $0.1\%$ prevalence stream would generate roughly **242 false alarms for every 1 true phishing attack caught** ($\text{Precision} \approx 0.004$, or $0.4\%$).
     - Therefore, evaluation precision ($71.2\%$) is an artifact of the artificial $1:1$ test ratio and must not be cited as expected operational precision without deployment re-weighting.

---

## 6. Audit Deliverables Inventory

The following 5 audit artifacts have been generated in `backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/`:

1. [`post_evaluation_audit.md`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/post_evaluation_audit.md) — Comprehensive technical audit report (this document).
2. [`within_cohort_independence.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/within_cohort_independence.json) — Full breakdown of within-cohort exact duplicate text groups, cross-class collisions, and SimHash near-duplicate counts.
3. [`independently_recomputed_metrics.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/independently_recomputed_metrics.json) — Complete machine-readable audit confirming 100% exact reproduction of confusion matrices, thresholds, and performance metrics.
4. [`subgroup_metrics_corrected.csv`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/subgroup_metrics_corrected.csv) — 42-row table with class-appropriate metrics (correct legitimate, FP, specificity, FPR for legitimate strata; detected phish, missed phish, recall, FNR for phishing strata).
5. [`hybrid_routing_audit.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/post_evaluation_audit/hybrid_routing_audit.json) — Audit confirming 100% HTML detection, 100% agreement between Policies 3 and 4, and formal documentation of modal scope boundaries.
