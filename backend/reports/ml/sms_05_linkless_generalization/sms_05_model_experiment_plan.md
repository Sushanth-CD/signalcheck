# SMS-05 Model Experiment Plan: Multi-Modality Architectures

**Milestone:** SMS-05 Planning — Linkless Smishing Generalization  
**Scope:** Architectural Exploration, Two-Channel Structural Modeling, and Evaluation Protocols  
**Status:** Protocol Specification Complete  
**Date:** November 2026  

---

## 1. Executive Summary & Problem Formulation

The SMS-03 evaluation demonstrated that relying solely on word and character n-grams from URL-bearing training data forces the classifier into a binary failure mode:
- If a message contains a URL $\rightarrow$ features push positive $\rightarrow$ classified as smishing.
- If a message has no URL $\rightarrow$ features fail to overcome the $-1.3329$ intercept $\rightarrow$ classified as negative (ham/spam).

To overcome this, **SMS-05 will evaluate four distinct architectural candidates** designed to capture both structural link features and conversational social engineering patterns.

---

## 2. Candidate Model Architectures

```
+---------------------------------------------------------------------------------------------------+
| SMS-05 CANDIDATE ARCHITECTURAL MATRIX                                                             |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  SMS-05-A: Word TF-IDF + Logistic Regression                                                      |
|    - Pipeline: TfidfVectorizer(ngram_range=(1,2), max_features=10,000, sublinear_tf=True)        |
|    - Classifier: LogisticRegression(C=1.0, max_iter=1000)                                         |
|    - Hypothesis: Tests whether word n-grams alone can capture conversational urgency phrases.      |
|                                                                                                   |
|  SMS-05-B: Character TF-IDF + Logistic Regression                                                 |
|    - Pipeline: TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=25,000)        |
|    - Classifier: LogisticRegression(C=1.0, max_iter=1000)                                         |
|    - Hypothesis: Tests whether sub-word character chunks capture telephone prefixes & obfuscation.|
|                                                                                                   |
|  SMS-05-C: Combined Word + Character FeatureUnion + Logistic Regression (SMS-03 Successor)        |
|    - Pipeline: FeatureUnion([('word', WordTFIDF), ('char', CharTFIDF)])                           |
|    - Classifier: LogisticRegression(C=1.0, max_iter=1000)                                         |
|    - Hypothesis: Serves as the direct baseline trained on the new balanced multi-source pool.     |
|                                                                                                   |
|  SMS-05-D: Structured Two-Channel Model (Content Channel + Structural Meta-Channel)               |
|    - Channel 1 (Content): Word + Char FeatureUnion on raw text excluding explicit URL strings.   |
|    - Channel 2 (Structural Meta): Explicit binary and numeric features:                           |
|        * has_url (0/1)                                                                            |
|        * has_phone_number (0/1)                                                                   |
|        * is_premium_rate_prefix (0/1)                                                             |
|        * has_currency_symbol (0/1)                                                                |
|        * uppercase_ratio (float)                                                                  |
|        * punctuation_density (float)                                                              |
|    - Classifier: LogisticRegression(C=1.0) with separate channel regularization scaling.          |
|    - Hypothesis: Prevents URL presence from masking text content by explicitly modeling both.     |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Deep Dive: The Structured Two-Channel Model (SMS-05-D)

The key limitation of SMS-03 was that URL tokens (`https`, `http`, `.com`) had weights an order of magnitude higher than text tokens. 

In **SMS-05-D**, the model decouples URL structure from message semantics:
1. **Content Branch:** Evaluates the social engineering, urgency, and lure principles within the message body.
2. **Structural Branch:** Evaluates metadata attributes directly:
   - Does the message instruct the user to call a UK premium rate (`090`, `087`) or US toll-free number?
   - Does the message contain an actionable link?
   - Does the message contain financial prize triggers (`£500`, `$1000`)?
3. **Combination:** Logistic regression learns independent coefficients for structural indicators without allowing a single URL token to drown out conversational threat indicators.

---

## 4. Benchmark Comparison Protocol

All candidate architectures will be trained on the identical SMS-05 Training partition ($\sim 4,760$ records) and compared on the **Validation partition** ($\sim 1,020$ records) at the frozen threshold of **0.50**:

| Selection Criterion | Target Benchmark Metric | Minimum Passing Threshold |
| :--- | :--- | :---: |
| **1. Primary Objective** | Validation F1 Score | $\ge 0.9200$ |
| **2. Linkless Generalization** | Linkless Smishing Recall | $\ge 0.8500$ |
| **3. URL-Bearing Generalization**| URL-Bearing Smishing Recall | $\ge 0.9000$ |
| **4. Benign Ham Control** | Benign Ham False Positive Rate | $\le 1.00\%$ |
| **5. Commercial Spam Control** | Commercial Marketing Spam FPR | $\le 5.00\%$ |
| **6. Overall Discrimination** | ROC-AUC | $\ge 0.9800$ |

The candidate achieving the highest Balanced Accuracy while satisfying both Ham FPR $\le 1.0\%$ and Linkless Smishing Recall $\ge 85.0\%$ will be selected and cryptographically frozen.
