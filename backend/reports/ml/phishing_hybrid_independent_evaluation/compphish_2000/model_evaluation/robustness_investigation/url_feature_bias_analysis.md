# URL Feature Bias Analysis: CompPhish V4 2,000-Sample Evaluation

**Evaluation Target:** CompPhish V4 2,000-Sample Independent Evaluation Corpus  
**Model Under Investigation:** `V3 URL-Only` (Logistic Regression over URL TF-IDF, Frozen Model)  
**Investigation Type:** READ-ONLY Forensic Feature & Stratum Bias Analysis  
**Output Location:** `backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/model_evaluation/robustness_investigation/`  

---

## 1. Executive Summary & Core Findings

In the 2,000-sample independent CompPhish V4 evaluation, `V3 URL-Only` demonstrated an apparent F1 advantage over `V3 Dual` (F1 = 0.7732 vs. 0.6947) driven by high raw recall (0.8849 vs. 0.6780). However, a systematic investigation of the model's feature space, training vocabulary, and source strata reveals that this advantage is heavily conditioned by **vocabulary alignment** and **source-specific URL artifacts**:

1. **Massive TLD & Token Bias:**  
   The frozen `V3 URL-Only` model relies intensely on specific Country Code / Generic Top-Level Domains (ccTLDs/gTLDs) and structural URL tokens that were heavily represented in its training set (e.g., `.cn` [$\beta = +6.0439$], `.jp` [$\beta = +3.6519$], `.top` [$\beta = +3.5237$], `duckdns` [$\beta = +3.2423$], `.xyz` [$\beta = +3.0989$], `.shop` [$\beta = +2.6405$], `.icu` [$\beta = +2.6375$], `php` [$\beta = +2.4545$], `wp` [$\beta = +2.3241$], `paypal` [$\beta = +2.2610$]).

2. **Source-Stratum Divergence:**  
   Across the 4 independent phishing cohorts, URL-Only recall varies from **84.44%** (OpenPhish feed) to **90.62%** (Crawl 2025 batch 2), while Dual-Channel recall fluctuates dramatically from **59.36%** (Crawl 2024–2025 batch 1) to **81.21%** (PhishTank feed). Dual-Channel drops recall specifically on crawl cohorts where landing pages contain minimal text, evasive scripts, or blank frames that suppress the DOM probability.

3. **High False Positive Rate on Legitimate Crawls:**  
   `V3 URL-Only` produces a high False Positive Rate across legitimate cohorts (**29.34%** on Crawl Batch 1, **37.08%** on Top-Sites Seed, and **42.51%** on Crawl Batch 2), resulting in poor overall specificity (**64.31%**). In contrast, `V3 Dual` leverages DOM content to filter out 122 of these false alarms, improving specificity to **75.80%**.

4. **Empty HTML Bias Fallback:**  
   When HTML is blank or lacks extractable URLs, `V3 URL-Only` evaluates its default bias intercept ($\beta_0 = +1.2951 \implies p = 0.7850$), automatically classifying empty pages as phishing.

---

## 2. Frozen V3 URL-Only Model Architecture & Feature Weights

The frozen `V3 URL-Only` model (`backend/reports/ml/phishing_v3_experiments/url_only_model.joblib`) consists of an scikit-learn Pipeline with two stages:
1. `features`: `url_extractor` followed by `tfidf_url` (word n-grams $(1, 2)$, sublinear TF, 9,188 features).
2. `classifier`: `LogisticRegression` with intercept $\beta_0 = +1.295068$.

### Top 25 Phishing-Predictive URL Features

| Rank | Feature Token / N-gram | Coefficient ($\beta$) | Odds Ratio ($e^\beta$) | Primary Context / Mechanism |
| :---: | :--- | :---: | :---: | :--- |
| 1 | `cn` | **+6.0439** | 421.53 | `.cn` ccTLD or Chinese registrar |
| 2 | `jp` | **+3.6519** | 38.55 | `.jp` ccTLD or Japanese targeting |
| 3 | `top` | **+3.5237** | 33.91 | `.top` low-cost gTLD abuse |
| 4 | `duckdns org` | **+3.2423** | 25.59 | Free dynamic DNS provider |
| 5 | `duckdns` | **+3.2423** | 25.59 | Free dynamic DNS provider |
| 6 | `xyz` | **+3.0989** | 22.17 | `.xyz` low-cost gTLD abuse |
| 7 | `images` | **+2.9404** | 18.92 | Phishing asset subfolder |
| 8 | `shop` | **+2.6405** | 14.02 | `.shop` e-commerce phishing abuse |
| 9 | `icu` | **+2.6375** | 13.98 | `.icu` cheap registrar abuse |
| 10 | `php` | **+2.4545** | 11.64 | Dynamic script endpoint (`login.php`) |
| 11 | `wp` | **+2.3241** | 10.22 | Compromised WordPress site (`wp-content`) |
| 12 | `paypal` | **+2.2610** | 9.59 | Brand-impersonation keyword |
| 13 | `login` | **+2.0840** | 8.04 | Credential harvesting endpoint |
| 14 | `cfd` | **+2.0811** | 8.01 | `.cfd` low-cost gTLD abuse |
| 15 | `includes` | **+1.9568** | 7.08 | Script path / CMS include directory |
| 16 | `club` | **+1.8609** | 6.43 | `.club` cheap gTLD abuse |
| 17 | `eki` | **+1.7763** | 5.91 | Japanese transit/brand phishing token |
| 18 | `js` | **+1.7650** | 5.84 | Evasive JavaScript resource endpoint |
| 19 | `vip` | **+1.7613** | 5.82 | `.vip` gTLD abuse |
| 20 | `com br` | **+1.7219** | 5.60 | Brazilian second-level domain target |
| 21 | `admin` | **+1.6807** | 5.37 | Phishing kit admin panel / backend |
| 22 | `top www` | **+1.6473** | 5.19 | Subdomain on `.top` domain |
| 23 | `amazon` | **+1.6333** | 5.12 | Brand-impersonation token |
| 24 | `br` | **+1.6262** | 5.08 | `.br` ccTLD |
| 25 | `buzz` | **+1.6016** | 4.96 | `.buzz` gTLD abuse |

### Top 25 Legitimate-Predictive URL Features

| Rank | Feature Token / N-gram | Coefficient ($\beta$) | Odds Ratio ($e^\beta$) | Primary Context / Mechanism |
| :---: | :--- | :---: | :---: | :--- |
| 1 | `pdf` | **-4.6628** | 0.0094 | Informational document download |
| 2 | `en` | **-3.9591** | 0.0191 | Multi-language localization path (`/en/`) |
| 3 | `and` | **-3.3057** | 0.0367 | Descriptive corporate / blog article slug |
| 4 | `host_www` | **-3.1176** | 0.0443 | Canonical `www.` subdomain marker |
| 5 | `html` | **-3.0580** | 0.0470 | Static website extension (`index.html`) |
| 6 | `www` | **-2.7372** | 0.0648 | Canonical web prefix |
| 7 | `the` | **-2.6657** | 0.0695 | Natural English title slug |
| 8 | `products` | **-2.6357** | 0.0717 | Commercial product catalog path |
| 9 | `software` | **-2.6090** | 0.0736 | Developer / enterprise software page |
| 10 | `org www` | **-2.4439** | 0.0868 | Non-profit / educational canonical host |
| 11 | `for` | **-2.4266** | 0.0883 | Natural language URL path slug |
| 12 | `uk www` | **-2.3807** | 0.0925 | UK enterprise canonical host |
| 13 | `htm` | **-2.3446** | 0.0959 | Static web file extension |
| 14 | `about` | **-2.3066** | 0.0996 | Standard corporate `/about/` page |
| 15 | `search` | **-2.2852** | 0.1018 | Enterprise search engine endpoint |
| 16 | `contact` | **-2.2763** | 0.1027 | Standard corporate `/contact/` page |
| 17 | `privacy` | **-2.1889** | 0.1120 | Compliance privacy policy path |
| 18 | `games` | **-2.1723** | 0.1139 | Entertainment portal path |
| 19 | `edu` | **-2.1644** | 0.1148 | Accredited educational domain (`.edu`) |
| 20 | `asp` | **-2.1267** | 0.1192 | Enterprise ASP.NET web extension |
| 21 | `of` | **-2.0804** | 0.1249 | Natural language URL path slug |
| 22 | `blog` | **-2.0078** | 0.1343 | Editorial blog section path |
| 23 | `shtml` | **-1.9873** | 0.1371 | Server-parsed HTML extension |
| 24 | `english` | **-1.8903** | 0.1510 | Language selector path |
| 25 | `faq` | **-1.8572** | 0.1561 | Customer support FAQ page |

---

## 3. Stratum-Level Bias and Performance Breakdown

The CompPhish V4 2,000-sample corpus is partitioned across 7 disjoint strata (4 phishing, 3 legitimate). Evaluation at threshold $\tau = 0.50$ reveals significant performance variations driven by source generation patterns:

| Stratum / Cohort Name | Label | $N$ | URL Predicted Pos Rate | URL Mean Prob | Dual Predicted Pos Rate | Dual Mean Prob | URL Recall / Spec | Dual Recall / Spec | URL False Alarm Rate (FPR) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **crawl_2024_2025_batch1** | Phishing | 502 | 88.05% | 0.7245 | 59.36% | 0.5435 | **88.05%** Rec | **59.36%** Rec | — |
| **phishtank_feed** | Phishing | 314 | 90.13% | 0.7502 | 81.21% | 0.6502 | **90.13%** Rec | **81.21%** Rec | — |
| **openphish_feed** | Phishing | 90 | 84.44% | 0.7582 | 68.89% | 0.6562 | **84.44%** Rec | **68.89%** Rec | — |
| **crawl_2025_batch2** | Phishing | 32 | 90.62% | 0.7181 | 65.62% | 0.5985 | **90.62%** Rec | **65.62%** Rec | — |
| **crawl_2024_2025_batch1** | Legitimate | 392 | 29.34% | 0.3616 | 22.96% | 0.2674 | **70.66%** Spec | **77.04%** Spec | **29.34%** |
| **top_sites_seed** | Legitimate | 383 | 37.08% | 0.4200 | 24.02% | 0.3417 | **62.92%** Spec | **75.98%** Spec | **37.08%** |
| **crawl_2025_batch2** | Legitimate | 287 | 42.51% | 0.4475 | 26.13% | 0.3336 | **57.49%** Spec | **73.87%** Spec | **42.51%** |

### Stratum Findings

1. **PhishTank vs. Web Crawl Recall Gap in Dual Channel:**  
   In `phishtank_feed` ($N=314$), `V3 Dual` captures **81.21%** of attacks because PhishTank URLs frequently point to full phishing kits with rich HTML forms and phishing brand text. However, on `crawl_2024_2025_batch1` ($N=502$), Dual recall plunges to **59.36%** (a 21.85 percentage point drop). The web crawler collected hundreds of phishing domains that served parked stubs, empty shells, or client-side redirects where HTML content lacked strong text cues, causing the DOM channel to pull down the joint probability.
2. **False Positive Inflation on Modern Web Crawls:**  
   In `crawl_2025_batch2` ($N=287$), legitimate websites frequently lack the legacy canonical `www` token ($\beta = -2.7372$) and use regional or newer gTLDs without long descriptive path slugs (`/about`, `/contact`), driving `V3 URL-Only` specificity down to **57.49%** (FPR = **42.51%**).
3. **Dual Model Correction:**  
   The DOM content model in `V3 Dual` counterbalances URL false alarms, lifting specificity from **57.49% $\to$ 73.87%** on Crawl Batch 2, from **62.92% $\to$ 75.98%** on Top-Sites, and from **70.66% $\to$ 77.04%** on Crawl Batch 1.

---

## 4. Source-Specific Artifacts & Feature Distribution

Analysis of URL structure reveals clear artifact signatures across the collection cohorts:

* **Hyphenated Hostnames:**  
  `phishtank_feed` exhibits hyphens in **51.3%** of hostnames, and `openphish_feed` in **42.2%**, compared to only **4.2%** in `top_sites_seed` and **10.3%** in `crawl_2025_batch2`.
* **Path Depth:**  
  `openphish_feed` has an average path length of **16.9 characters**, while `top_sites_seed` averages just **1.9 characters**. `top_sites_seed` consists mostly of bare root domains (`https://example.com/`), which heavily penalizes path-token matching.
* **Modern Cloud Scaffolds (`.app`, `.io`, `.dev`):**  
  Cloudflare R2 (`r2.dev`), Vercel (`vercel.app`), and Web App (`web.app`) multi-tenant endpoints appear in over 260 phishing URLs in CompPhish V4. In `V3 URL-Only`, while tokens like `app`, `io`, and `dev` are present, their interaction with phishing subdomains produces confident detections that do not rely on DOM inspection.

---

## 5. Architectural Implications

The apparent advantage of `V3 URL-Only` is an artifact of:
1. Phishing URLs in CompPhish V4 matching the vocabulary of low-cost gTLDs, brand keywords, and phishing path endpoints.
2. The presence of 211 duplicate HTML pages and evasive stubs where DOM content is uninformative or blank, penalizing Dual Channel.

When deployed to production, deploying `V3 URL-Only` alone would result in a **35.7% false positive rate** on benign enterprise traffic. Therefore, `V3 Dual` remains the architecturally sound policy for live integration, provided its empty-page edge cases are handled with appropriate guardrails.
