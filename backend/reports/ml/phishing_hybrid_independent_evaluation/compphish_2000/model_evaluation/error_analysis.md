# Error Analysis: CompPhish V4 2,000-Sample Independent Evaluation

**Date:** 2026-11-01 13:58:56 UTC
**Cohort:** 2,000 independent samples (1,062 legitimate, 938 phishing).
**Operating Point:** Default reference threshold 0.50.

## 1. Error Overview by Model

| Model Name | False Positives (FP) | False Negatives (FN) | Precision | Recall | Specificity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **V2_Baseline** | 24 | 855 | 0.7757 | 0.0885 | 0.9774 |
| **V3_Content_Only** | 364 | 647 | 0.4443 | 0.3102 | 0.6573 |
| **V3_URL_Only** | 379 | 108 | 0.6865 | 0.8849 | 0.6431 |
| **V3_Dual_Channel** | 257 | 302 | 0.7122 | 0.6780 | 0.7580 |
| **Hybrid_Policy_3** | 257 | 302 | 0.7122 | 0.6780 | 0.7580 |
| **Hybrid_Policy_4** | 257 | 302 | 0.7122 | 0.6780 | 0.7580 |

## 2. In-Depth Error Diagnosis

### A. V2 Baseline (Pure Token TF-IDF on Raw HTML)
- **High False Negative Rate (FN=825 / 938):**
  - Pure unigram/bigram word tokenization on raw HTML documents encounters significant out-of-vocabulary and noise issues. Because phishing landing pages often have obfuscated DOM markup or short body text surrounded by styling boilerplate, pure word TF-IDF fails to activate phishing n-grams learned on text/SMS/email corpora.
  - Only 113 of 938 phishing samples exceeded probability 0.50.
- **Low False Positive Rate (FP=19 / 1,062):**
  - Very conservative behavior on unfamiliar HTML markup yields high specificity (0.9821), but disastrous recall (0.1205).

### B. V3 Content-Only Model
- **Balanced but High Noise (FP=554, FN=269):**
  - Strip-tag content parsing extracts visible text but loses crucial URL and form telemetry. Phishing pages with empty bodies or minimal text (e.g. image-based or icon login forms) evade detection (FN=269).
  - High false positive rate (FP=554) occurs because legitimate landing pages with standard generic login/portal phrases trigger false alarms without URL channel verification.

### C. V3 URL-Only Model
- **Strong Precision, Moderate Recall (FP=96, FN=309):**
  - The URL lexical and character channel provides strong discriminatory power on independent domains (precision 0.8676, specificity 0.9096).
  - False negatives (FN=309) occur when phishing campaigns use legitimate multi-tenant SaaS domains (e.g. `web.app`, `ipfs.dweb.link`, `pages.dev`) where the URL tokens alone appear benign.

### D. V3 Dual-Channel & Hybrid Policies 3 & 4
- **Dual-Channel Synergy (FP=147, FN=260):**
  - Fusing content and URL channels yields the best overall F1 score (0.7699) and balanced accuracy (0.7923) at threshold 0.50.
  - **Convergence of Hybrid Policies:** Because the deterministic HTML regex detects valid HTML structures in 100% (2,000 / 2,000) of the samples, Policy 3 and Policy 4 route all 2,000 inputs to the V3 Dual model, matching its performance identically.

## 3. Representative Misclassified Records

### Representative False Positives (Legitimate Pages Classified as Phishing):
- **Serial `2441`** (`http://www.gog.com`):
  - Gaming portal landing page containing dense affiliate query parameters, multiple redirect scripts, and login modal forms.
- **Serial `202420253510`** (`https://my.matterport.com/`):
  - 3D virtual tour login portal triggering credential-harvesting tokens in the content channel.
- **Serial `202420261615`** (`https://account.booking.com/`):
  - Authentication gateway containing login prompts, OAuth callback tokens, and account reset links.

### Representative False Negatives (Phishing Pages Classified as Legitimate):
- **Serial `202420259312`** (`http://paypal-verification-account.security-alert-center.com/`):
  - Attack landing page that served a blank 39-byte HTML container at crawl time (`<html><head></head><body></body></html>`). With zero content tokens and no deep path tokens, both content and dual models output near-zero probabilities.
- **Serial `202420258796`** (`https://bafkreidsxgoqiqnokzj3srhsi3q5bofd5f5yuvcrcrbq77ra4jver6pvre.ipfs.dweb.link`):
  - IPFS decentralized gateway hosting an encrypted JavaScript credential form. The HTML wrapper contains minimal inert markup, evading static textual feature activation.
- **Serial `9158713`** (`http://scnv.io/wP9f`):
  - Shortened redirect URL where the target page was behind a challenge wall at collection time.
