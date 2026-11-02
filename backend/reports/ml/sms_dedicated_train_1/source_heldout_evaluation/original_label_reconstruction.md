# Original Label Reconstruction: Mishra & Soni SMS Phishing Dataset

**Milestone:** SMS-DEDICATED-TRAIN-1 — Source-Held-Out Evaluation Investigation  
**Investigation Scope:** Label Recovery, Normalization, Case Discrepancies, and Ambiguity Audit  
**Status:** Complete  
**Date:** November 2026  

---

## 1. Objective & Methodology

The project's baseline file `combined_reduced.json` merged commercial spam and smishing into a single positive class (`label = 1`). To evaluate the frozen SMS-03 classifier on true held-out smishing, we bypassed `combined_reduced.json` and inspected the raw, primary release of Mishra & Soni (`Dataset_5971.csv`).

Every message underwent:
1. Exact string case inspection of the `LABEL` column.
2. Standardized 3-class mapping.
3. Message normalization via `ml.text_normalization.normalize_for_model`.
4. Cryptographic SHA-256 hash generation on normalized text.
5. Cross-label ambiguity detection (identifying identical message texts carrying conflicting class labels).

---

## 2. Raw Label Inventory & Standardization

The raw `LABEL` column contains inconsistent casing across the 5,971 records:

| Raw Label Value | Raw Count | Standardized Category | Target Binary Semantic | Notes |
| :--- | :---: | :--- | :---: | :--- |
| `ham` | 4,844 | `ham` | `0` (Negative) | Standard benign communications |
| `Smishing` | 616 | `smishing` | `1` (Positive) | Malicious social engineering lures |
| `smishing` | 22 | `smishing` | `1` (Positive) | Malicious social engineering lures (lower case) |
| `spam` | 466 | `commercial_spam` | `0` (Negative) | Commercial marketing / nuisance spam |
| `Spam` | 23 | `commercial_spam` | `0` (Negative) | Commercial marketing / nuisance spam (title case) |
| **Total Raw** | **5,971** | — | — | **Zero null or unassigned labels** |

### Standardized 3-Class Summary
- **Benign Personal Ham:** **4,844** records ($81.13\%$)
- **Malicious Smishing:** **638** records ($10.68\%$)
- **Commercial Marketing Spam:** **489** records ($8.19\%$)

---

## 3. Internal Label Conflicts & Ambiguity Analysis

When messages are normalized (NFKC normalization, lowercase conversion, whitespace collapsing), identical text strings can reveal annotation inconsistencies in the parent corpus:

1. **Total Unique Normalized Text Hashes:** 5,831 unique hashes out of 5,971 records (140 duplicate occurrences).
2. **Harmonious Duplicates:** 106 duplicates share identical labels across instances.
3. **Conflicting Ambiguous Hashes:** Exactly **34 normalized text hashes** map to multiple conflicting labels in the raw dataset.

### Nature of Conflicts
- **All 34 conflicting hashes represent disputes between `commercial_spam` and `smishing`**.
- *Example Conflict 1:*
  `"UR awarded a City Break and could WIN a £200 Summer Shopping spree every WK. Txt STORE to 88039..."`  
  $\rightarrow$ Annotated once as `spam` and once as `smishing`.
- *Example Conflict 2:*
  `"SMS. ac Blind Date 4U!: Rodds1 is 21/m from Aberdeen, United Kingdom. Check Him out http://img. sms. ac/..."`  
  $\rightarrow$ Annotated once as `spam` and once as `smishing`.
- **Zero conflicts exist between `ham` and `smishing`**, and **zero conflicts exist between `ham` and `commercial_spam`**.

### Protocol for Handling Ambiguous Records
Because an objective evaluation cannot tolerate ground-truth label ambiguity:
- In the clean cohort (after excluding split and pilot leakage), exactly **31 ambiguous hashes** remain.
- **Rule:** All records associated with these 31 ambiguous hashes are **strictly quarantined and excluded** from the eligible evaluation cohort.

---

## 4. Recoverability Assessment

- **Smishing Recoverability:** **High / Verified.** 638 raw smishing records exist. After removing ambiguous spam/smishing collisions (112 occurrences) and exact duplicates, **526 pristine, unambiguous smishing records** are fully recoverable.
- **Commercial Spam Recoverability:** **High / Verified.** 489 raw spam records exist. After removing ambiguous collisions and duplicates, **435 pristine commercial spam records** are fully recoverable.
- **Ham Recoverability:** **100% Unambiguous.** No ham message in Mishra & Soni has ever been co-labeled as spam or smishing.
