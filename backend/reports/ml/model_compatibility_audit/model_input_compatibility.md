# Model Input Compatibility Audit

**Audit Scope:** Read-Only Technical Architecture & Model Specification Audit  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Date:** November 2026  
**Auditor:** Automated Read-Only Architecture Review  

---

## 1. Executive Summary

This document performs an exhaustive, code-level audit of the four candidate phishing detection models available in the repository:
1. **V2 TF-IDF + Logistic Regression Baseline** (`phishing_tfidf_logreg_domain_grouped.joblib` / `phishing_tfidf_logreg.joblib`)
2. **V3 Content-Only Model** (`content_only_model.joblib`)
3. **V3 URL-Only Model** (`url_only_model.joblib`)
4. **V3 Dual-Channel Combined Model** (`dual_channel_v3_model.joblib`)

The goal is to determine the exact technical specifications of each model, verify what input formats they were trained on, analyze their internal preprocessing pipelines and feature representations, and objectively evaluate their compatibility with the three operational input modalities required by the application:
- **Plain Text / Messages (SMS, email bodies, chat notifications)**
- **Standalone URLs (submitted links, browser address bars)**
- **Raw Webpage Content (HTML source, DOM snapshots)**

---

## 2. Model-by-Model Deep Dive

```
+---------------------------------------------------------------------------------------------------+
| MODEL ARCHITECTURE & PREPROCESSING PIPELINE OVERVIEW                                              |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  1. V2 Baseline:                                                                                  |
|     Input Text ----> [normalize_for_model] ----> [TfidfVectorizer (word 1-2)] ----> [LogisticReg]   |
|                      (NFKC, lower, spaces)       (200k max_features)                               |
|                                                                                                   |
|  2. V3 Content-Only:                                                                              |
|     Input Text ----> [ContentHTMLParser / URL-strip] ----> [TfidfVectorizer] ----> [LogisticReg]  |
|                      (extracts body/title/anchor)          (150k max_features)                    |
|                                                                                                   |
|  3. V3 URL-Only:                                                                                  |
|     Input Text ----> [extract_candidates (V2 parser)] -> [TfidfVectorizer] ----> [LogisticReg]    |
|                      (host, labels, path, params)          (50k max_features)                     |
|                                                                                                   |
|  4. V3 Dual-Channel:                                                                              |
|     Input Text --+-> [Content Branch] ---> [Tfidf (150k)] --+                                     |
|                  |                                          +-> [FeatureUnion] -> [LogisticReg]   |
|                  +-> [URL Branch] -------> [Tfidf (50k)] ---+   (200k joint)                      |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

### 2.1 Model 1: V2 TF-IDF + Logistic Regression Baseline

- **Model Artifact Path:**
  - Persisted in production path: `backend/models/text/phishing_tfidf_logreg_domain_grouped.joblib`
  - Baseline variant: `backend/models/text/phishing_tfidf_logreg.joblib`
- **Original Training Input Format:**
  - Trained on `phishing_text_candidates.jsonl` / `combined_reduced.json` (77,677 total records, 9,481 training representatives after exact/near-duplicate and domain grouping).
  - Training records were heterogeneous text records containing simulated email messages, synthetic SMS, scraped phishing HTML fragments, and short phishing links mixed with prose.
- **Exact Preprocessing Pipeline:**
  - Uses `backend.ml.text_normalization.normalize_for_model`:
    ```python
    def normalize_for_model(text: str) -> str:
        value = unicodedata.normalize("NFKC", str(text)).lower()
        return re.sub(r"\s+", " ", value).strip()
    ```
  - Followed by `sklearn.feature_extraction.text.TfidfVectorizer`:
    - `lowercase=False` (preprocessor handles lowercasing)
    - `ngram_range=(1, 2)` (unigrams and bigrams)
    - `min_df=2`, `max_df=0.995`
    - `sublinear_tf=True`
    - `max_features=200_000`
- **Features Used During Inference:**
  - Word unigrams and bigrams extracted via standard scikit-learn regex token pattern (`(?u)\b\w\w+\b`).
  - Punctuation, URL structural separators (`/`, `:`, `?`, `=`, `&`, `.`), and special characters are stripped by the token pattern unless part of a word boundary.
- **Expected Input Type:**
  - A sequence of strings (`Sequence[str]`).
- **Model Output & Probability Semantics:**
  - `classifier.predict_proba([text])[:, 1]` outputs the predicted probability $P(Y=1 \mid X)$ of class 1 ("phishing").
  - Decision rule: $\hat{Y} = 1$ if $P \ge 0.50$ else $0$ ("benign").
  - Uncalibrated Platt/logistic score; not a calibrated Bayesian posterior under realistic prior class probabilities.
- **Known Limitations:**
  - Completely blind to URL structure: URLs inside text or submitted as bare strings are tokenized arbitrarily (e.g., `https://evil.com/login` becomes `https`, `evil`, `com`, `login`).
  - Severe vulnerability to HTML markup noise: tags like `<div>`, `<script>`, `<style>`, CSS classes, and HTML entities contaminate the vocabulary.
  - Catastrophic collapse on independent HTML: On CompPhish V4 ($N = 2,000$), V2 achieved Recall = **0.0885** (F1 = 0.1589), failing to detect over 91% of real phishing HTML.
- **Existing Evaluation Evidence:**
  - In-domain validation: F1 = 0.9021, Precision = 0.9133, Recall = 0.8912, Specificity = 0.7553.
  - Independent CompPhish V4 (2,000 samples): Recall = 0.0885, Specificity = 0.9774, F1 = 0.1589.
- **Modality Suitability:**
  - **SMS / Plain Text Messages:** Moderate suitability (trained on natural text, captures keyword cues).
  - **Standalone URLs:** Poor suitability (destroys URL structural hierarchy).
  - **Raw HTML:** Completely unsuitable (empirically confirmed failure).

---

### 2.2 Model 2: V3 Content-Only Model

- **Model Artifact Path:**
  - `backend/reports/ml/phishing_v3_experiments/content_only_model.joblib`
- **Original Training Input Format:**
  - Trained on the 9,481 V2 domain-holdout training representatives from `combined_reduced.json`.
- **Exact Preprocessing Pipeline:**
  - Implemented in `backend.ml.dual_channel.ContentChannelExtractor`:
    - Checks if input matches `HTML_TAG_PATTERN` (`(?is)<\s*(?:!doctype\s+html|html|head|body|meta|link|a|form|div|p|span|table|h[1-6])\b`).
    - If HTML: parses with `ContentHTMLParser` (Python `html.parser.HTMLParser`), silently discarding `<script>`, `<style>`, `<noscript>`, and extracting text only from `<title>`, `<a>` (anchor text), and body text elements.
    - If plain text: invokes `extract_candidates("content_extract", raw_text)` and **strips all high-confidence URL spans** from the text.
    - Applies `normalize_text_convention` (Unicode NFKC, lowercase, whitespace collapsing).
  - Followed by `TfidfVectorizer`:
    - `analyzer="word"`, `ngram_range=(1, 2)`
    - `max_features=150_000`, `sublinear_tf=True`
- **Features Used During Inference:**
  - Word unigrams and bigrams from visible human-readable webpage text or URL-stripped message text.
- **Expected Input Type:**
  - A sequence of raw strings (`Sequence[str]`).
- **Model Output & Probability Semantics:**
  - Logistic regression probability $P(Y=1 \mid X_{\text{content}})$. Threshold $\tau = 0.50$.
- **Known Limitations:**
  - **Complete blindness to links:** Because URLs are stripped from plain text and href targets are ignored in HTML, any phishing message or webpage that relies on a clean, deceptive narrative with a malicious destination link cannot be recognized via its URL indicators.
  - Extreme false alarm rate on short messages: On the validation subgroup `short_messages_le_100` ($N = 1,432$), Content-Only produced **263 false positives** and achieved **0.0000 Specificity** (it classified every single short message as phishing!).
  - Severely impaired on minimal/empty landing pages: If an HTML document contains little text or uses canvas/script rendering, Content-Only generates a zero vector, defaulting to the baseline logistic intercept.
- **Existing Evaluation Evidence:**
  - V3 Validation partition: F1 = 0.8751, Precision = 0.8199, Recall = 0.9383, Specificity = 0.4039.
  - HTML validation subset ($N = 377$): Recall = 0.5769, F1 = 0.6406.
- **Modality Suitability:**
  - **SMS / Plain Text Messages:** Unusable standalone (0% specificity on short text).
  - **Standalone URLs:** Completely unusable (URL string is stripped or yields an empty token vector).
  - **Raw HTML:** Poor to fair (strips scripts and styles cleanly, but blind to anchor destinations and deceptive domains).

---

### 2.3 Model 3: V3 URL-Only Model

- **Model Artifact Path:**
  - `backend/reports/ml/phishing_v3_experiments/url_only_model.joblib`
- **Original Training Input Format:**
  - Trained on the 9,481 V2 domain-holdout training representatives from `combined_reduced.json`.
- **Exact Preprocessing Pipeline:**
  - Implemented in `backend.ml.dual_channel.URLChannelExtractor`:
    - Executes `extract_candidates("url_extract", raw_text)` using the deterministic V2 candidate extractor (`notebooks.phishing_url_extraction_v2.py`).
    - Filters for `confidence == "high"` and `parser_status in {"normalized_hostname", "ip_literal"}`.
    - If valid URL candidates are found:
      - Extracts and normalizes hostname, emitting prefix `host_<hostname>`.
      - Splits host labels by `.`, `-`, `_`.
      - Unquotes and splits URL path by `/`, `.`, `-`, `_`.
      - Parses query string parameters, emitting prefix `param_<param_name>` (query parameter values are excluded to prevent overfitting).
    - If no valid URL candidates exist, returns an empty string `""`.
  - Followed by `TfidfVectorizer`:
    - `analyzer="word"`, `ngram_range=(1, 2)`
    - `max_features=50_000`, `sublinear_tf=True`
- **Features Used During Inference:**
  - Structural URL tokens: host markers (`host_login.microsoftonline.com`), label tokens (`login`, `microsoftonline`), path tokens (`oauth2`, `authorize`), query parameter keys (`param_client_id`, `param_redirect_uri`).
- **Expected Input Type:**
  - A sequence of raw strings (`Sequence[str]`), either standalone URLs or text containing extractable URLs.
- **Model Output & Probability Semantics:**
  - Logistic regression probability $P(Y=1 \mid X_{\text{url}})$. Threshold $\tau = 0.50$.
- **Known Limitations:**
  - **High False Positive Rate on Modern Benign Domains:** Suffers from a 35.69% FPR on CompPhish V4 (Specificity = 64.31%), peaking at 42.51% FPR on recent 2025 web crawls.
  - Absence of `www.` Penalty: Strong negative coefficient on `www` (-2.74) causes modern benign URLs lacking `www.` to be penalized and misclassified as phishing.
  - Path Length Bias: Highly sensitive to path tokens; legitimate URLs with deep paths (e.g., e-commerce, documentation) trigger false alarms.
  - **Zero Coverage for Messages Without URLs:** If a text input contains no URL, the transformer produces an empty string, yielding a score driven solely by the intercept ($P = 0.1741$), meaning it cannot classify social engineering or credential solicitations that lack URLs.
- **Existing Evaluation Evidence:**
  - V3 Validation partition: F1 = 0.8912, Precision = 0.9092, Recall = 0.8738, Specificity = 0.7476.
  - CompPhish V4 Independent Evaluation ($N = 2,000$): Recall = 0.8849, Specificity = 0.6431, F1 = 0.7732.
- **Modality Suitability:**
  - **SMS / Plain Text Messages:** Partially suitable if and only if the message contains an embedded URL; completely blind if no URL is present.
  - **Standalone URLs:** High sensitivity (Recall 88.5%), but high false alarm rate (FPR 35.7%).
  - **Raw HTML:** Highly dependent on URL presence; ignores page content, rendering it blind to content cloaking.

---

### 2.4 Model 4: V3 Dual-Channel Combined Model

- **Model Artifact Path:**
  - `backend/reports/ml/phishing_v3_experiments/dual_channel_v3_model.joblib`
- **Original Training Input Format:**
  - Trained on the 9,481 V2 domain-holdout training representatives from `combined_reduced.json`.
- **Exact Preprocessing Pipeline:**
  - Combines `ContentChannelExtractor` and `URLChannelExtractor` in parallel using `sklearn.pipeline.FeatureUnion`:
    ```python
    FeatureUnion([
        ("content_branch", build_content_only_feature_pipeline()),
        ("url_branch", build_url_only_feature_pipeline()),
    ])
    ```
  - Followed by `LogisticRegression(C=1.0, solver="liblinear", max_iter=2000, random_state=20261026)`.
- **Features Used During Inference:**
  - Up to 150,000 content word unigrams/bigrams PLUS up to 50,000 structural URL tokens, concatenated into a 200,000-dimensional sparse feature space.
- **Expected Input Type:**
  - A sequence of raw strings (`Sequence[str]`).
- **Model Output & Probability Semantics:**
  - Logistic regression probability $P(Y=1 \mid [X_{\text{content}}, X_{\text{url}}])$. Threshold $\tau = 0.50$.
- **Known Limitations:**
  - **Vulnerability to Empty / Cloaked Webpages:** When evaluated on independent crawled phishing pages that serve empty stubs, parking notices, or bot-blockers (e.g., CompPhish Crawl Batch 1), the content channel generates zero phishing tokens, dragging the joint probability down and causing Recall to drop to 59.36%.
  - **Dependency on Input Format:** If passed a standalone URL, the content channel is empty, causing the model to evaluate the URL with an attenuated logistic intercept originally calibrated for joint text+URL inputs.
- **Existing Evaluation Evidence:**
  - V3 Validation partition: F1 = 0.8934, Precision = 0.9161, Recall = 0.8718, Specificity = 0.7689.
  - CompPhish V4 Independent Evaluation ($N = 2,000$): Recall = 0.6780, Specificity = 0.7580, F1 = 0.6947.
  - Exact-Duplicate Weighted Metrics: Recall = 0.6807, Specificity = 0.7642, F1 = 0.6815.
- **Modality Suitability:**
  - **SMS / Plain Text Messages:** Moderate suitability; effectively handles messages with both narrative text and links.
  - **Standalone URLs:** Sub-optimal without dedicated routing (content channel is missing).
  - **Raw HTML:** Best overall architecture for full HTML documents with both body text and links, though vulnerable to cloaked/empty pages.

---

## 3. Comprehensive Model Comparison Matrix

| Property | V2 Baseline | V3 Content-Only | V3 URL-Only | V3 Dual-Channel |
| :--- | :--- | :--- | :--- | :--- |
| **Pipeline Step 1** | Text Normalization | Content/HTML Parser | V2 URL Extractor | Content + URL FeatureUnion |
| **Pipeline Step 2** | TF-IDF (200k max) | TF-IDF (150k max) | TF-IDF (50k max) | Dual TF-IDF (200k total) |
| **Classifier** | Logistic Regression | Logistic Regression | Logistic Regression | Logistic Regression |
| **Input Format** | Single text string | Single text/HTML string | Single text/URL string | Single text/HTML string |
| **URL Hierarchy Awareness** | None (regex tokenized) | None (URLs stripped) | Full (host, path, param) | Full in URL branch |
| **HTML Tag Awareness** | None (treats tags as text)| Full (strips script/style) | Extracts candidate URLs | Full in content branch |
| **CompPhish Recall (HTML)** | 8.85% (catastrophic) | ~57.7% (validation) | 88.49% | 67.80% |
| **CompPhish Specificity** | 97.74% | 40.39% (validation) | 64.31% (high FPR) | 75.80% |
| **SMS/Text Feasibility** | Baseline capability | Unusable (0% spec) | Only if URL present | Viable |
| **Standalone URL Feasibility**| Broken tokenization | Completely Unusable | Viable (needs calib) | Viable (needs routing) |
| **Raw HTML Feasibility** | Unusable | Moderate | High recall / high FP | Most balanced |
