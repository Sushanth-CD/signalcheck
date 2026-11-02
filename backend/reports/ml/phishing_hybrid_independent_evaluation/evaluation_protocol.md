# Independent Evaluation Protocol for Phishing Classifier Architectures

**Document Version:** 1.0.0  
**Target Candidates:**  
1. **Model 1:** V2 Baseline (`backend/reports/ml/phishing_domain_holdout_v2/model.joblib`)
2. **Model 2:** V3 Dual-Channel (`backend/reports/ml/phishing_v3_experiments/dual_channel_v3_model.joblib`)
3. **Model 3:** Hybrid Policy 3 (`HTML -> V3 Dual, else V2`)
4. **Model 4:** Hybrid Policy 4 (`HTML or Length > 1000 -> V3 Dual, else V2`)

---

## 1. Evaluation Integrity & Blindness Guarantees

* **Fixed Weights & Freezes:** All models and preprocessors must be loaded strictly from their frozen hashes recorded in [`model_freeze_manifest.json`](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/ml/phishing_hybrid_independent_evaluation/model_freeze_manifest.json). Zero hyperparameter tuning, vocabulary re-fitting, or weight adaptation is permitted.
* **Double-Blind Test Set Protection:** The V2 test set from `combined_reduced.json` ($n = 1,993$ primary records) has already been inspected during V2 verification and error analysis. It is **categorically disqualified** from serving as independent validation evidence.
* **Offline Execution:** All URL feature extractions, HTML parsers, and inference pipelines must operate strictly offline without performing HTTP requests, socket connections, or DNS resolutions.

---

## 2. Deterministic Routing Implementations

For every record $r$ in the independent test partition with raw text $T_r$:

### Step 2.1: Input Normalization & Routing Feature Extraction
1. Calculate character length: $L_r = \text{len}(T_r)$.
2. Calculate HTML indicator using the frozen deterministic regex:
   $$\text{is\_html}_r = \text{bool}(\text{re.search}(\text{r"(?is)<\s*(?:!doctype\s+html|html|head|body|meta|link|a|form|div|p)\b"}, T_r))$$

### Step 2.2: Compute Candidate Probabilities
* $S_{\text{v2}}(T_r) = P(\text{phishing} \mid T_r, \text{V2})$
* $S_{\text{v3\_dual}}(T_r) = P(\text{phishing} \mid T_r, \text{V3 Dual})$

### Step 2.3: Routing Policies

* **Policy 1 (V2 All):**
  $$S_{\text{P1}}(T_r) = S_{\text{v2}}(T_r)$$
* **Policy 2 (V3 Dual All):**
  $$S_{\text{P2}}(T_r) = S_{\text{v3\_dual}}(T_r)$$
* **Policy 3 (Hybrid: HTML $\to$ V3 Dual, else V2):**
  $$S_{\text{P3}}(T_r) = \begin{cases} S_{\text{v3\_dual}}(T_r) & \text{if } \text{is\_html}_r = \text{True} \\ S_{\text{v2}}(T_r) & \text{otherwise} \end{cases}$$
* **Policy 4 (Hybrid: HTML or Long $\to$ V3 Dual, else V2):**
  $$S_{\text{P4}}(T_r) = \begin{cases} S_{\text{v3\_dual}}(T_r) & \text{if } \text{is\_html}_r = \text{True} \text{ or } L_r > 1,000 \\ S_{\text{v2}}(T_r) & \text{otherwise} \end{cases}$$

---

## 3. Evaluation Metrics & Statistical Standards

All metrics must be evaluated at the standard reference decision threshold:
$$\hat{Y}_{\tau}(T_r) = \mathbb{I}(S(T_r) \ge 0.50)$$

### Primary Metrics:
1. **Confusion Matrix:** True Negatives ($TN$), False Positives ($FP$), False Negatives ($FN$), True Positives ($TP$).
2. **Precision (Positive Predictive Value):** $\frac{TP}{TP + FP}$
3. **Recall (Sensitivity / Phishing Detection Rate):** $\frac{TP}{TP + FN}$
4. **Specificity (True Negative Rate):** $\frac{TN}{TN + FP}$
5. **F1-Score:** $\frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
6. **Overall Accuracy:** $\frac{TP + TN}{TP + TN + FP + FN}$
7. **ROC-AUC:** Area under the Receiver Operating Characteristic curve.
8. **Average Precision (PR-AUC):** Area under the Precision-Recall curve.

### Secondary Operating Thresholds (Reporting Only):
* $\tau = 0.68$: High-specificity operating point (targeting $FP \le 10\%$).
* $\tau = 0.35$: High-recall operating point (targeting $FN \le 5\%$).

---

## 4. Mandatory Subgroup Segmentation

The independent evaluation corpus must be reported across four mandatory orthogonal slices to verify that routing achieves its intended structural specialization:

1. **HTML Subgroup:**
   - Criteria: $\text{is\_html} == \text{True}$.
   - Hypothesis: V3 Dual and Hybrid Policies 3 & 4 should outperform standalone V2 by preventing HTML boilerplate suppression.
2. **Short URL Subgroup:**
   - Criteria: $L_r \le 100$ characters AND $\text{is\_html} == \text{False}$ AND $\text{has\_url} == \text{True}$.
   - Hypothesis: V2 and Hybrid Policies 3 & 4 should outperform standalone V3 Dual by leveraging character n-gram URL sensitivity.
3. **Long Message Subgroup:**
   - Criteria: $L_r > 1,000$ characters.
   - Hypothesis: Policy 4 should provide the highest recall on long text bodies.
4. **Ordinary Plain Text Subgroup:**
   - Criteria: Non-HTML plain-text messages without long attachments ($100 < L_r \le 1,000$).
   - Hypothesis: V2 and Hybrid Policies should demonstrate identical and stable baseline accuracy.

---

## 5. Decision Gates & Acceptance Criteria

To declare the Hybrid Architecture ready for deployment consideration, the independent evaluation must meet three strict acceptance gates:

| Acceptance Gate | Condition | Rationale |
|---|---|---|
| **Gate 1: Superior Overall F1** | $\text{F1}_{\text{P3}} > \text{F1}_{\text{V2}}$ AND $\text{F1}_{\text{P3}} > \text{F1}_{\text{V3}}$ | Confirms that combining models generates net positive synergy rather than intermediate degradation. |
| **Gate 2: Resolved HTML False Negatives** | $\text{F1}_{\text{P3}}(\text{HTML}) \ge 0.60$ (vs. $\text{V2} \le 0.35$) | Proves that the HTML detection and tag-stripping pipeline generalizes to real-world out-of-sample HTML attacks. |
| **Gate 3: Controlled False Positive Rate** | $\text{Specificity}_{\text{P3}} \ge 0.75$ at $\tau = 0.50$ (or $\ge 0.90$ at $\tau = 0.68$) | Prevents severe alert fatigue in user awareness training workflows. |
