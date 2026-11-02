# Source Diversity Assessment: Mitigating Confounding in SMS-05

**Milestone:** SMS-05 Planning — Linkless Smishing Generalization  
**Scope:** Source Confounding Diagnostics, Telecom Dialects, and Balanced Stratification  
**Status:** Architecture Review Complete  
**Date:** November 2026  

---

## 1. Executive Summary & Lessons from SMS-03

The SMS-03 development cycle suffered from a fundamental methodological limitation: **Source-Label Confounding**.

In SMS-03:
- **100% of the positive training smishing instances originated from a single source:** WSPR-NCSU.
- **100% of positive training instances were link-bearing.**
- **Negative controls originated entirely from other sources:** UCI (Ham & Spam) and ExAIS (Ham & Spam).

Because WSPR messages were collected from modern US carrier gateways while UCI and ExAIS originated from European university studies and German research groups, the classifier learned to distinguish **carrier/regional syntax and URL presence** rather than intrinsic social engineering intent:

$$\text{SMS-03 Learned Rule: } \text{Contains URL} + \text{US Carrier Grammar} \implies \text{Smishing}$$

When tested on Mishra & Soni (which contained historical UK/Commonwealth phone scams and shortcode lures), SMS-03 collapsed (recall dropped from $96.67\%$ to $11.00\%$).

---

## 2. Multi-Source Target Architecture for SMS-05

To eliminate source confounding, **SMS-05 must ensure that every class (Smishing, Commercial Spam, Ham) receives contributions from multiple independent sources across geographic regions and telecom modalities**:

```
+---------------------------------------------------------------------------------------------------+
| SOURCE DIVERSITY COMPOSITION FOR SMS-05                                                           |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  CLASS 1: MALICIOUS SMISHING (Target: N ~ 2,500)                                                  |
|    - Modern URL-Bearing: WSPR-NCSU (US gateways, 2022–2024) [N ~ 1,000]                           |
|    - Modern Conversational & WhatsApp: IMC 2025 reportsmishing (Global, 2023–2025) [N ~ 1,000]    |
|    - Classical Phone Callback & Shortcodes: Mishra & Soni Remaining (UK/India) [N ~ 300]          |
|    - Multi-Threat Pretexting: Zenodo / WSPR Unmapped Linkless [N ~ 200]                           |
|                                                                                                   |
|  CLASS 2: COMMERCIAL MARKETING SPAM (Target: N ~ 1,800)                                           |
|    - Modern Marketing & Offers: ExAIS Commercial Spam [N ~ 1,200]                                 |
|    - Classical Shortcodes & Services: Mishra & Soni Remaining Spam [N ~ 300]                      |
|    - Historical Carrier Spam: UCI SMS Spam Collection [N ~ 300]                                   |
|                                                                                                   |
|  CLASS 3: BENIGN PERSONAL HAM (Target: N ~ 2,500)                                                 |
|    - Conversational Everyday Chat: ExAIS Ham [N ~ 1,200]                                          |
|    - Classical Personal & Transactional: Mishra & Soni Remaining Ham [N ~ 1,000]                  |
|    - International SMS Chat: UCI Ham [N ~ 300]                                                    |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Mitigating Telecom & Regional Dialect Artifacts

### 3.1 Currency Symbols and Phone Formats
- In Mishra & Soni, smishing frequently features the British Pound (`£`) and UK area codes (`090`, `087`).
- In WSPR-NCSU, smishing features US Dollars (`$`) and North American 10-digit formats.
- In IMC 2025, currencies include Euros (`€`), Brazilian Real (`R$`), and international formats.
- **Normalization Solution:** The text normalizer must collapse currency symbols into generic semantic tokens (or preserve them consistently without regional bias) while inertly masking telephone digits (`0906XXXXXXX` $\rightarrow$ `<PHONE_UK_PREMIUM>`) rather than stripping them entirely.

### 3.2 Breaking the Negative Intercept Trap
In SMS-03, words like `call`, `dial`, and `text` were heavily associated with commercial advertising spam (e.g., *"Text STOP to 88039"*), causing the logistic regression optimizer to assign them negative weights.
- When smishing datasets included phone callback lures, these negative weights overpowered the positive class.
- **SMS-05 Strategy:** By incorporating hundreds of linkless smishing messages into the positive training set, the optimizer will learn that terms like *"call urgently"*, *"verify your account by calling"*, and *"dial immediately"* are shared across social engineering attacks, neutralising the negative bias.

---

## 4. Metadata Isolation Guarantee

To prevent data leakage during training:
1. **Sanitized Text Only:** The model pipeline will receive exclusively `sanitized_message_text`.
2. **Metadata Separation:** Columns indicating origin (`source_dataset`), collection year, sender telecom type, user ID, and campaign ID will be strictly quarantined in separate audit manifests and never fed into feature vectorizers.
