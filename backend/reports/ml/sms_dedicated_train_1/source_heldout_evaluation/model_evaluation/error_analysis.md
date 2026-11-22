# Error Analysis: Mishra & Soni Source-Held-Out Evaluation

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation  
**Target Model:** Frozen SMS-03 Combined Classifier (`sms_model.joblib`)  
**Threshold:** 0.50 (Frozen)  
**Total Benchmark Size:** 500 records (200 Smishing, 200 Ham, 100 Commercial Spam)  
**Total Errors Observed:** 181 / 500 (178 False Negatives, 3 False Positives)  
**Date:** November 2026  

---

## 1. Executive Summary & Core Diagnostic Finding

The evaluation revealed an asymmetric error profile:
- **Zero Ham False Positives (0/200):** Benign personal communications were preserved with **100.0% specificity**.
- **Minimal Commercial Spam False Positives (3/100):** Commercial marketing spam had a **3.0% FPR** (97.0% specificity).
- **Severe Smishing False Negatives (178/200):** Only **22 of 200 smishing messages** were detected (Overall Recall $= 11.0\%$).

### Root-Cause Diagnostic: The URL-Dependency Trap
Disaggregating the 200 smishing messages reveals that **recall collapses entirely on linkless lures**:
- **URL-bearing Smishing Recall:** **47.73%** (21 / 44 detected).
- **Linkless Smishing Recall:** **0.64%** (**1 / 156 detected**; 155 false negatives).

Feature coefficient inspection of the frozen model reveals why:
1. **URL Tokens Dominate the Positive Weights:** The top 20 positive features pushing the log-odds towards smishing are exclusively URL structural tokens: `word__https` ($+4.98$), `word__com` ($+4.49$), `char__http` ($+2.08$), `char__://` ($+2.08$), `char__.co` ($+2.05$).
2. **Negative Intercept Requires URL Boost:** The model intercept is **$-1.3329$** (base probability $\approx 20.8\%$). Without positive feature weights to counter this intercept, messages naturally default to negative ($< 0.50$).
3. **Telecommunication Tokens Push Negative:** Because negative training data (UCI spam and ExAIS commercial marketing) contained frequent phone calls and SMS keywords, words like `word__call` ($-1.06$), `word__dial` ($-0.80$), `word__text` ($-0.78$), `word__send` ($-0.82$), and `word__ur` ($-0.80$) received **negative weights**. Consequently, when a smishing attack asks the victim to *"call 0905809458"* or *"text CLAIM"*, the model actively drives the prediction further down into the negative class!

---

## 2. Exhaustive False Positive Analysis ($N = 3$)

Zero false positives occurred on benign Ham ($0/200$). Exactly **3 false positives** occurred on Commercial Spam ($3/100$):

| Benchmark ID | Source ID | Prob. Score | URL? | Length | Sanitized Text Excerpt (PII Masked) | Primary Lure Pattern |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| `BENCH_183` | 1341 | **0.6971** | No | 38 chars | `PRIVATE! Your 2003 Account Statement for 078` | Banking/account statement urgency keyword (`PRIVATE!`, `Account Statement`) with negative intercept overcome by uppercase capitalization. |
| `BENCH_199` | 3824 | **0.5588** | Yes | 108 chars | `Text82228>> Get more ringtones, logos and games from www.txt82228.com. Questions: info@txt82228.co.uk` | URL-bearing commercial download service (`www.txt82228.com`) triggered heavy positive URL weights (`word__com`, `char__.com`). |
| `BENCH_274` | 3110 | **0.5051** | Yes | 171 chars | `Minimal documentation, Quick approval, Low rates. Home Loan @9.25%... Call on 011-43065228 visit www.mymoneymantra.com...` | Financial loan advertisement containing both high-weight URL tokens (`www.`, `.com`) and financial tokens. |

---

## 3. False Negative Categorization ($N = 178$)

Every missed smishing lure ($N = 178$) was inspected and categorized by attack mechanism:

| Attack Category / Lure Pattern | Missed Count | % of All Missed | URL Present | URL Absent | Representative Linguistic Patterns |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Telephone Callback / Premium SMS** | 150 | 84.3% | 15 | 135 | Prompts to call premium rate numbers (`0906...`, `0871...`) or text keywords (`CLAIM`, `STORE`). |
| **Prize / Lottery / Award Scams** | 92 | 51.7% | 14 | 78 | Fake lottery notifications: *"UR awarded a £200 shopping spree"*, *"You have won a £150 prize"*. |
| **Generic Social Engineering / Urgency** | 100 | 56.2% | 18 | 82 | Urgent upgrade and voucher offers: *"T-Mobile customer claim camera phone upgrade"*. |
| **Fictitious Social / Dating Lures** | 51 | 28.7% | 3 | 48 | Impersonation lures: *"You have a secret admirer looking 2 make contact"*, *"Rodds1 is 21/m Aberdeen"*. |
| **Banking / Account Fraud** | 16 | 9.0% | 4 | 12 | Spoofed banking security alerts: *"Barclays alert"*, *"Account overdrawn"*. |
| **Delivery / Courier Scams** | 6 | 3.4% | 2 | 4 | Fake missed parcel and delivery fee notices: *"Your parcel is pending collection"*. |

*(Note: Categories overlap as messages frequently combine multiple mechanisms, e.g., a prize lure requiring a telephone callback).*

---

## 4. Analysis of Detected Smishing Messages ($N = 22$)

Understanding what SMS-03 *did* catch confirms the model's behavioral boundaries:

1. **The 21 URL-Bearing Detections:**
   - Messages containing explicit, high-entropy web domains:
     - `http://bit.do/cgjK-and` (Bank of America alert, score: **0.9579**)
     - `http://www.wtlp.co.uk/text` (Voucher claim, score: **0.7876**)
     - `http://wap.xxxmobilemovieclub.com` (score: **0.9991**)
   - In these cases, the combined weights of `word__http`, `word__https`, `word__com`, and character n-grams easily overcame the negative intercept.
2. **The Single Linkless Detection:**
   - Message: *"Records indicate you were involved in an accident in the last 2.5 years. As such you are entitled to claim compensation, Reply CLAIM for info or STOP to opt out"* (Score: **0.5710**).
   - This message succeeded because of legal/insurance claim terminology (`accident`, `compensation`, `entitled`) that happened to have sparse representation in negative training sets, allowing sub-word tokens to accumulate positive log-odds without URL assistance.

---

## 5. Synthesis: Implications for Architecture and Routing

1. **SMS-03 is an "SMS URL-Phishing Classifier", Not an "Omni-Smishing Classifier":**
   Because SMS-03 was trained on WSPR-NCSU (where every sample contained an extracted URL), the model learned that smishing is fundamentally synonymous with embedding a malicious web link.
2. **Sub-word Features Alone Cannot Counter Negative Intercepts on Short Plain Text:**
   Character n-grams captured sub-word variations of URLs, but did not develop positive weights for social engineering phone scams because telephone numbers and callback words were heavily present in the negative training sets (UCI and ExAIS marketing spam).
3. **Application Gating Implication:**
   SMS-03 cannot be deployed as an unassisted classifier for linkless smishing. To detect phone/callback scams, a model must either be trained on balanced linkless smishing or coupled with specialized intent/entity extraction (e.g., detecting premium-rate telephone regexes).
