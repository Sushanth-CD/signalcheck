# TEXT-EVAL-1 SMS Pilot: Error Analysis & Modality Mismatch Investigation

**Date:** 2026-11-02  
**Evaluation Target:** 250 Independent SMS Messages (100 Smishing, 100 Ham, 50 Commercial Spam)  
**Location:** `backend/reports/ml/text_eval_1_acquisition/sms_pilot/model_evaluation/`  

---

## 1. Executive Failure Summary: Extreme Specificity Collapse

Evaluating our frozen models on independent SMS messages revealed an immediate, catastrophic architectural vulnerability:

> [!CAUTION]
> **Complete Specificity Collapse Across All Models:**  
> When presented with plain SMS text at the default 0.50 decision threshold:
> - **V2 Baseline Specificity:** **0.0400** (4% benign messages recognized; 96 false alarms out of 100).
> - **V3 Dual-Channel Specificity:** **0.0200** (2% benign messages recognized; 98 false alarms out of 100).
> - **V3 Content-Only Specificity:** **0.1600** (16% benign messages recognized; 84 false alarms out of 100).
> - **V3 URL-Only Specificity (on URL subset):** **0.0909** (1 benign message recognized out of 11).

While recall on Cohort A smishing appeared extraordinarily high (98% - 99%), this is a **pathological artifact of positive bias**, not smishing acumen. The models output elevated phishing probabilities ($\ge 0.50$) for virtually **all** short text inputs regardless of content.

---

## 2. Root Cause Analysis: TF-IDF Sparsity & Intercept Bias

### 2.1 The Bias Term Artifact
All four frozen models are Logistic Regression classifiers fitted on TF-IDF vectors derived from full webpage HTML or long email texts:
- **Logistic Regression Decision Function:** $z = \beta_0 + \sum_{i} \beta_i x_i$.
- When an input string is an SMS of 50–150 characters, almost all of the 168,757 training vocabulary features evaluate to $x_i = 0$.
- Consequently, $z \approx \beta_0$ (the model's unpenalized intercept).
- In our training data (which contained a heavy baseline representation of phishing features), the intercept combined with common benign stopwords pushes the default score above 0.50:
  - Typical plain text baseline probability: **0.613** for V2, **0.741** for V3 Dual, and **0.639** for V3 Content-Only.
  - As a result, a harmless message like `"Thanks a lot for your wishes on my birthday"` receives an estimated phishing probability of **0.733** on V2, triggering a false alarm.

### 2.2 Short vs. Long Text Disparity
Examining length subgroups confirms this sparsity pathology:
- **Short Texts (<129 characters):** Specificity is **0.0323** on V2 and **0.0161** on V3 Dual.
- **Longer Texts ($\ge 129$ characters):** Specificity improves slightly to **0.0526** on V2 and **0.0263** on V3 Dual.
- Because SMS messages are inherently concise, TF-IDF n-grams from web pages are essentially nonexistent, leaving the model stranded near its positive intercept.

---

## 3. False-Positive Analysis

### 3.1 Benign Personal Communication (Cohort B False Positives)
96 of 100 legitimate SMS messages were erroneously flagged as phishing by V2 (98 by V3 Dual):

1. **Serial 101 (`UCI_Ham`):**
   - **Text:** `Dai  <#>  naal eruku.`
   - **Probabilities:** V2 = 0.6983, V3 Dual = 0.8012, V3 Content = 0.7818.
   - **Failure Mechanism:** Extremely short colloquial text; lack of recognized HTML/body tokens causes logistic score to collapse to the positive default.
2. **Serial 105 (`UCI_Ham`):**
   - **Text:** `Id onluy matters when getting on from offcampus`
   - **Probabilities:** V2 = 0.6736, V3 Dual = 0.7613, V3 Content = 0.6948.
   - **Failure Mechanism:** Minor typos and short length produce zero positive match with benign HTML tokens, falling back to base bias.
3. **Serial 110 (`UCI_Ham`):**
   - **Text:** `Thanks a lot for your wishes on my birthday. Thanks you for making my birthday truly memorable.`
   - **Probabilities:** V2 = 0.7334, V3 Dual = 0.7185, V3 Content = 0.6418.
   - **Failure Mechanism:** Entirely benign social message; token weights in the web model fail to down-weight phishing probability.

### 3.2 Commercial Spam Nuisance (Cohort C False Positives)
49 of 50 commercial spam messages were misclassified as phishing by V2 (48 by V3 Dual, 45 by V3 Content):

1. **Serial 201 (`UCI_Spam`):**
   - **Text:** `Sexy Singles are waiting for you! Text your AGE followed by your GENDER as wither M or F E.G.23F. Fo`
   - **Probabilities:** V2 = 0.6225, V3 Dual = 0.7328, V3 Content = 0.6270.
   - **Failure Mechanism:** Adult dating marketing. The model lacks a dedicated "commercial spam" label and conflates aggressive marketing with phishing credential harvesting.
2. **Serial 210 (`UCI_Spam`):**
   - **Text:** `Not heard from U4 a while. Call 4 rude chat private line 01223585334 to cum. Wan 2C pics of me getti`
   - **Probabilities:** V2 = 0.6319, V3 Dual = 0.7555, V3 Content = 0.6158.
3. **Serial 225 (`UCI_Spam`):**
   - **Text:** `I am hot n horny and willing I live local to you - text a reply to hear strt back from me 150p per m`
   - **Probabilities:** V2 = 0.6985, V3 Dual = 0.8200, V3 Content = 0.6729.

---

## 4. False-Negative Analysis (Missed Smishing in Cohort A)

Despite the overwhelming positive bias, a handful of smishing messages were missed:

1. **Serial 32 (`WSPR-NCSU`):**
   - **Text:** `ucezef.com/GJuWoYQ`
   - **Probabilities:** V2 = **0.4012** (Missed!), V3 Dual = 0.8038, V3 Content = 0.6500, V3 URL = 0.7850.
   - **Failure Mechanism:** The message consists *only* of a short bare URL with zero accompanying conversational text. V2's word-level TF-IDF cannot extract semantic signal from the isolated token `ucezef`, causing it to drop below 0.50. However, V3 URL-Only and V3 Dual correctly flagged it based on character n-grams.
2. **Serial 15 (`WSPR-NCSU`):**
   - **Text:** `Postal reminder: Please handle the wrong address for your package and we will arrange for delivery as soon as possible.`
   - **Probabilities:** V2 = 0.5628, V3 Dual = **0.4766** (Missed!), V3 Content = 0.5288, V3 URL = 0.5357.
   - **Failure Mechanism:** V3 Dual's URL channel received zero URL tokens (the URL was severed in the message body), depressing the joint probability below 0.50.
3. **Serial 44 & 45 (`WSPR-NCSU`):**
   - **Serial 44:** `MOJO: Your order has been delivered! If not, give a missed call: 01161191684/visit: urlzs.com/g1ux5`
   - **Probabilities:** V3 Content = **0.4556** (Missed!).
   - **Serial 45:** `PayPal: Your account has been flagged due to an unauthorised sign-in attempt...`
   - **Probabilities:** V3 Content = **0.4359** (Missed!).
   - **Failure Mechanism:** V3 Content-Only strips URLs, leaving tokens that failed to meet the content threshold alone.

---

## 5. Architectural Recommendations

1. **Do NOT Deploy Frozen Models on SMS Modality:**  
   The frozen V2, V3 Dual, V3 Content, and V3 URL models are fundamentally unsuited for standalone SMS text classification. Deploying them on SMS will cause nearly 100% false alarms for legitimate users.
2. **Explicit Modality Gating in the API:**  
   FastAPI endpoints must reject or route plain-text SMS inputs away from the web-page HTML models.
3. **Dedicated Plain-Text / Smishing Model Required:**  
   A dedicated text model trained on short messages, with explicit negative examples of colloquial SMS and commercial spam, is strictly necessary before plain-text analysis can be offered.
