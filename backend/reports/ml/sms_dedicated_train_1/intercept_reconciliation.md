# Technical Reconciliation: Model Intercepts & SMS Participation

**Audit Date:** 2026-11-02  
**Target Milestone:** SMS-DEDICATED-TRAIN-1 Phase 0  
**Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Referenced Artifact:** `backend/reports/ml/phishing_hybrid_independent_evaluation/model_implementation_freeze_manifest.json`  

---

## 1. Discrepancy A: SMS Source Participation in Training Split

### Audit Finding:
The previous split audit identified 202 "plain-text" records in the training partition of `domain_holdout_v2` and flagged that 13 matched the UCI SMS Spam Collection / Mishra & Soni subcorpus.

### Concrete Record Audit:
We performed record-level tracking of all 9,481 training instances in `backend/reports/ml/phishing_domain_extraction_v2/domain_holdout_split_v2/split_manifest.csv` against `combined_reduced.json` and the official UCI / Mishra & Soni dataset.

- **Total Plain-Text Records in Raw Corpus:** 18,929.
- **Excluded by Domain Key Filter:** 15,504 plain-text records possessed zero extractable HTTP/HTTPS registrable domain destinations and were systematically routed to `no_destination_cohort` (excluded from model training).
- **Quarantined Plain-Text Records:** 2,876 plain-text records were quarantined due to promotional review flags.
- **Records Entering Training Split:** Exactly **202 plain-text records** entered the training split.
- **UCI SMS Matches in Training Split:** Exactly **13 records** from the UCI SMS spam subcorpus entered the fitted training matrix.
  - *Representative Samples:* Index 15570 (*"Knock Knock Txt whose there to 80082..."*), Index 22573 (*"Cashbin.co.uk (Get lots of cash this weekend!) www.cashbin.c"*), Index 35240 (*"Save money on wedding lingerie at www.bridal.petticoatdreams"*).
  - *Why they entered:* Each of these 13 records happened to contain a clean, high-confidence domain string (e.g., `cashbin.co.uk`, `petticoatdreams.co.uk`, `areyouunique.co.uk`) that satisfied the domain-grouping requirements.

> [!NOTE]
> **Definitive Conclusion on Participation:**  
> It is **NOT** true that zero SMS records were used. Exactly **13 SMS-source records** (all URL-bearing commercial spam from UCI) were included in the 9,481 training rows. However, 95.6% of the raw SMS subcorpus was excluded, leaving the frozen models virtually unexposed to mobile conversational text.

---

## 2. Discrepancy B: Zero-Feature Intercept Reconciliation

### The Apparent Conflict:
- Earlier pilot evaluation report cited baseline probabilities of:
  - V2: `0.613`, V3 Content: `0.639`, V3 Dual: `0.741`.
- Later readiness audit reported:
  - V2: `0.7455`, V3 Content: `0.8036`, V3 Dual: `0.8123`, V3 URL: `0.7850`.

### Mathematical & Algorithmic Reconciliation:
Using the exact frozen model artifacts (`model.joblib`, `dual_channel_v3_model.joblib`, `content_only_model.joblib`, `url_only_model.joblib`), we evaluated the logistic regression decision functions and intercepts:

$$\text{Logit: } z = \beta_0 + \mathbf{w}^T \mathbf{x}, \quad P(y=1) = \sigma(z) = \frac{1}{1 + e^{-z}}$$

1. **Theoretical Intercept ($\mathbf{x} = \mathbf{0}$, All Features Zero):**
   When an input vector $\mathbf{x}$ contains strictly zero active features ($nnz = 0$), $z = \beta_0$:
   - **V2 Baseline:** $\beta_0 = +1.074635 \implies \sigma(\beta_0) = \mathbf{0.745477}$
   - **V3 Content-Only:** $\beta_0 = +1.409128 \implies \sigma(\beta_0) = \mathbf{0.803628}$
   - **V3 Dual-Channel:** $\beta_0 = +1.465068 \implies \sigma(\beta_0) = \mathbf{0.812307}$
   - **V3 URL-Only:** $\beta_0 = +1.295068 \implies \sigma(\beta_0) = \mathbf{0.785004}$
   - *Verification:* Feeding an explicit `csr_matrix((1, n_features))` or an empty string `""` into each classifier yields **exactly** `0.745477`, `0.803628`, `0.812307`, and `0.785004`.

2. **Source of the Earlier `0.613` / `0.639` / `0.741` Values:**
   The earlier report evaluated the synthetic sentence:
   `"This is a test message without url."`
   - In that sentence, words like `"this"`, `"is"`, `"a"`, `"message"` matched benign stopword n-grams in the web-page training vocabulary, creating negative weights ($\mathbf{w}^T \mathbf{x} < 0$) that pulled the logit downward from $\beta_0$:
     - For V2: $z = 1.0746 - 0.6146 = 0.4600 \implies \sigma(z) = \mathbf{0.6130}$
     - For V3 Content: $z = 1.4091 - 0.8373 = 0.5718 \implies \sigma(z) = \mathbf{0.6392}$
     - For V3 Dual: $z = 1.4651 - 0.4158 = 1.0493 \implies \sigma(z) = \mathbf{0.7406}$

> [!IMPORTANT]
> **Resolution:**  
> There is no contradiction. 
> - $\mathbf{0.7455 / 0.8036 / 0.8123 / 0.7850}$ are the **exact mathematical intercept-only probabilities** (when $nnz = 0$, such as for empty strings or completely out-of-vocabulary inputs like `"Kpele"` or `"2"`).
> - $\mathbf{0.6130 / 0.6392 / 0.7406}$ were the probabilities for the specific test string `"This is a test message without url."`. Both sets of values are mathematically accurate under their respective input conditions.
