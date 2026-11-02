# Source-Label Confounding Assessment & Mishra-Soni Augmentation Feasibility

**Milestone:** SMS-DEDICATED-TRAIN-1 Partition Optimization  
**Date:** 2026-11-02  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Output Path:** `backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v3/`  

---

## 1. The Core Methodological Challenge: Source-Label Confounding

In the current 5,400-record dataset:
- **100% of the positive class (`smishing`, $N=1,400$)** originates from **WSPR-NCSU**.
- **0% of the negative class (`ham` and `commercial_spam`, $N=4,000$)** originates from **WSPR-NCSU**.
- **0% of the positive class** originates from **UCI** or **ExAIS**.

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| SOURCE-LABEL CONFOUNDING MATRIX                                                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                                                                                   |
|  Source Dataset            Ground-Truth Category Represented             Confounding Risk         |
|  ───────────────────────────────────────────────────────────────────────────────────────────────  |
|  WSPR-NCSU                 100% Smishing (Malicious Phishing)            SEVERE (Source = Label)  |
|  UCI SMS Collection        100% Benign Ham & Commercial Spam             SEVERE (Source = Class 0)|
|  ExAIS SMS Dataset         100% Benign Ham & Commercial Spam             SEVERE (Source = Class 0)|
|                                                                                                   |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

### Consequences of Confounding:
When a machine learning model is trained on a perfectly confounded dataset:
1. The classifier may learn **telecom / feed artifacts** characteristic of the collection apparatus rather than true phishing intent:
   - WSPR was collected via US telecom aggregator gateways (frequent US carrier gateway shortcodes, US English phrasing, brand names like AT&T, Chase, USPS).
   - ExAIS was collected in Nigeria (Nigerian currency $\text{N}$, local network tags MTN/Glo/Airtel, West African English colloquialisms).
   - UCI was collected in the UK and Singapore in 2011 (early 2000s UK slang, currency symbols \$, £).
2. The classifier may implicitly act as a **WSPR vs. Non-WSPR detector**, rather than a true **Smishing vs. Non-Smishing detector**.

---

## 2. Exploration: Can Mishra & Soni Supply Diverse Smishing Training Data?

To break this 1-to-1 confounding, we investigated whether the **Mishra & Soni SMS Phishing Dataset (Mendeley Data 2022)** can be safely repurposed for training augmentation.

### 2.1 Reconstructed Mishra & Soni Ground Truth:
The raw Mishra & Soni dataset contains **5,971 records**:
- **Ham:** 4,844 records ($81.1\%$).
- **Smishing (Malicious Phishing):** **638 records** ($10.7\%$).
- **Commercial Spam:** **489 records** ($8.2\%$).

### 2.2 Technical Feasibility of Ingestion:
1. **Smishing Subcorpus ($N=638$):**
   - Mishra & Soni collected smishing messages from independent Asian and Indian telecom feeds, banking fraud alerts, and international phishing repositories.
   - These 638 smishing messages do **NOT** originate from WSPR-NCSU.
2. **Label Reconstruction:**
   - Unlike the naive binary mapping in `combined_reduced.json` (which merged commercial spam into label 1), the original Mendeley CSV preserves explicit 3-class annotations.
3. **Training Eligibility Assessment:**
   - Because Mishra & Soni was part of the original project corpus (`backend/data/raw/combined_reduced.json`), it **CANNOT be used as an independent external test set**.
   - However, for **exploratory development training**, adding the reconstructed 638 smishing messages into the training split would introduce non-WSPR phishing patterns, partially mitigating source-label confounding.

### 2.3 Safeguards Required if Mishra & Soni is Ingested:
- Strict deduplication against the 250-record evaluation pilot.
- Strict grouping of near-duplicates so that no Mishra & Soni template leaks between train and validation.
- Clear documentation that the model's development partition ingested historic project corpus data, requiring an entirely fresh, untouched third-party dataset for final external validation.

---

## 3. Conclusion & Recommendations

1. **For Immediate Model Fitting:**  
   Proceed with **Proposed V3** on the 5,400 clean candidates. Proposed V3 eliminates the source skew on the negative classes (50/50 UCI and ExAIS ham).
2. **For Next Research Milestone:**  
   Reconstruct the 638 smishing records from the original Mishra & Soni Mendeley release and run a controlled ablation study to test whether multi-source smishing improves cross-feed generalization.
