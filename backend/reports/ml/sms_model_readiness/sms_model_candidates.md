# Dedicated SMS Model Candidates & Feasibility Analysis

**Report Milestone:** SMS Model Readiness Audit  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Status:** Architecture Design & Feasibility Review (READ-ONLY)  

---

## 1. Feasibility Assessment: Can We Train a Dedicated SMS Classifier?

**Verdict: YES, WITH A PURPOSE-BUILT ARCHITECTURE.**

The failure of our frozen V2/V3 models on SMS was **not** an inherent flaw of machine learning, but an extreme **modality mismatch**:
1. The frozen models were trained on 8,239 web URLs and 1,028 HTML pages, with only 13 SMS messages.
2. Web HTML vocabularies (e.g., `div`, `class`, `href`, `script`, `font-size`) are completely absent in SMS messages.
3. Mobile SMS text has unique linguistic properties: character limits (160 chars), heavy slang, phonetic abbreviations (`u`, `ur`, `txt`, `2day`), creative leetspeak/obfuscation (`v-i-s-i-t`, zero-width spaces), bare shortened URLs, and regional colloquialisms.

A classifier trained directly on mobile text messages with balanced negative controls can achieve high discrimination.

---

## 2. Evaluation of Model Candidate Architectures

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| CANDIDATE MODEL ARCHITECTURES FOR DEDICATED SMS CLASSIFICATION                                    |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                   |
|  Candidate 1: Word-Level TF-IDF + Regularized Logistic Regression                                 |
|  - Tokenization: Word n-grams (1-2) with sublinear TF scaling                                     |
|  - Pros: High interpretability; fast CPU training and inference (<1 ms); low memory footprint.    |
|  - Cons: Highly vulnerable to spelling variations, deliberate leetspeak, and out-of-vocab typos. |
|                                                                                                   |
|  Candidate 2: Character-Level TF-IDF + Logistic Regression                                         |
|  - Tokenization: Character n-grams (3-5) spanning word boundaries                                 |
|  - Pros: Extremely robust to obfuscation, slang, emoji patterns, and short URL fragments.         |
|  - Cons: Larger vocabulary space; higher dimension (requires L2 regularization).                  |
|                                                                                                   |
|  Candidate 3: Combined Word + Character FeatureUnion + Logistic Regression (RECOMMENDED)          |
|  - Tokenization: Word n-grams (1-2, 20k features) + Character n-grams (3-5, 50k features)         |
|  - Intercept & Calibration: Balanced class weighting + Platt scaling / isotonic calibration.     |
|  - Pros: Captures semantic intent while remaining immune to spelling mutations and bare URLs.     |
|                                                                                                   |
|  Candidate 4: Linear Support Vector Machine (LinearSVC) with CalibratedClassifierCV               |
|  - Optimization: Margin maximization with hinge loss, calibrated via 5-fold Platt scaling.        |
|  - Pros: Excellent separation in high-dimensional sparse text representations.                    |
|  - Cons: Requires two-stage training for calibrated probability estimates; slower inference.      |
|                                                                                                   |
|  Candidate 5: Rule-Enhanced LightGBM / GBDT Baseline                                              |
|  - Input: TF-IDF dense embeddings + explicit hand-crafted features (URL count, phone count, etc.)|
|  - Pros: Captures nonlinear feature interactions (e.g., URL present AND urgency words present).   |
|  - Cons: Slower CPU inference; prone to overfitting on small vocabulary subsets.                   |
|                                                                                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 3. In-Depth Linguistic & Threat Considerations

### 3.1 Vocabulary Sparsity & Intercept Mitigation
In the frozen models, the positive intercept ($\beta_0$) dominated because benign SMS activated zero or few benign web features.
- **Solution:** In an SMS-specific training split, benign messages will activate hundreds of frequent benign conversational tokens (`thanks`, `see`, `tomorrow`, `home`, `call`, `okay`, `love`).
- **Feature Union Design:** A hybrid pipeline combining word n-grams (1–2) and character n-grams (3–5) ensures that even unseen slang generates active character n-gram matches, completely preventing intercept collapse.

### 3.2 URL Obfuscation & Slashed Links
Attackers routinely obscure links in SMS:
- Bare domains: `ucezef.com/GJuWoYQ` (lacking `http://`).
- Slashed punctuation: `01161191684/visit: urlzs.com/g1ux5`.
- URL shorteners: `bit.ly`, `tinyurl.com`, `t.co`, `ow.ly`.
- **Mitigation:** The pipeline must integrate the offline candidate extractor (`notebooks.phishing_url_extraction_v2.extract_candidates`) to normalize and isolate URL tokens into dedicated lexical features.

### 3.3 Class Separation: Phishing vs. Commercial Spam vs. Ham
The most critical design requirement is separating **Smishing** from **Commercial Advertising Spam**:
- Commercial spam is pushy and annoying (*"Free sexy singles in your area"*, *"Claim your £1000 prize"*), but it does not steal credentials or deploy malware.
- If commercial spam is naively labeled as phishing, legitimate retail notifications (Amazon shipping notices, airline updates, telecom promos) will be blocked.
- **Strategy:** Treat SMS classification as a **3-class problem** or a **hierarchical 2-stage detector**:
  - *Stage 1:* Spam vs. Non-Spam filter.
  - *Stage 2:* Phishing / Credential-Theft filter applied to flagged messages.

---

## 4. Summary Recommendation

The recommended primary candidate is a **Dual Word + Character TF-IDF Pipeline with L2-Regularized Logistic Regression**:
- Word n-grams: `(1, 2)`, max features 25,000, sublinear TF.
- Character n-grams: `(3, 5)`, max features 50,000, sublinear TF.
- Classifier: Logistic Regression with `class_weight='balanced'`, solver `lbfgs` / `liblinear`, $C = 1.0$.
- Calibration: Probability calibration verified via Brier score and reliability diagrams.
