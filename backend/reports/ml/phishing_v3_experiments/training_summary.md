# Phishing Classifier V3 — Training & Comparative Evaluation Summary

**Experiment:** `phishing_v3_experiments`  
**Date (UTC):** 2026-10-31 14:09:19  
**Train Representatives:** 9,481  
**Validation Representatives:** 2,005  
**Split Protection:** Strictly verified V2 train & validation partitions. V2 test partition was **not touched**.

---

## 1. Overall Model Comparison on Validation Partition (Threshold = 0.50)

| Model Architecture | Precision | Recall | F1-Score | Specificity | Accuracy | ROC-AUC | Avg Precision | Fit Time |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Content-Only TF-IDF** | 0.8199 | 0.9383 | 0.8751 | 0.4039 | 0.8010 | 0.6852 | 0.8229 | 11.95s |
| **URL-Only TF-IDF** | 0.9092 | 0.8738 | 0.8912 | 0.7476 | 0.8414 | 0.9114 | 0.9689 | 37.64s |
| **Dual-Channel V3 (Combined)** | **0.9161** | **0.8718** | **0.8934** | **0.7689** | **0.8454** | **0.9167** | **0.9709** | 24.76s |

*(Reference V2 Baseline on Validation: F1 = 0.9021, Precision = 0.9133, Recall = 0.8912, Specificity = 0.7553, ROC-AUC = 0.9215)*

---

## 2. Key Subgroup Analysis on Validation

| Subgroup | Model | Sample Count | Precision | Recall | F1-Score | Specificity | FP | FN |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `html_messages` | content_only | 377 | 0.7200 | 0.5769 | 0.6406 | 0.8416 | 35 | 66 |
| `html_messages` | url_only | 377 | 0.6691 | 0.5833 | 0.6233 | 0.7964 | 45 | 65 |
| `html_messages` | dual_channel_v3 | 377 | 0.8421 | 0.5128 | 0.6374 | 0.9321 | 15 | 76 |
| `short_messages_le_100` | content_only | 1432 | 0.8162 | 0.9991 | 0.8985 | 0.0000 | 263 | 1 |
| `short_messages_le_100` | url_only | 1432 | 0.9363 | 0.9307 | 0.9335 | 0.7186 | 74 | 81 |
| `short_messages_le_100` | dual_channel_v3 | 1432 | 0.9183 | 0.9427 | 0.9304 | 0.6274 | 98 | 67 |
| `url_containing_messages` | content_only | 2004 | 0.8198 | 0.9382 | 0.8750 | 0.4039 | 307 | 92 |
| `url_containing_messages` | url_only | 2004 | 0.9092 | 0.8737 | 0.8911 | 0.7476 | 130 | 188 |
| `url_containing_messages` | dual_channel_v3 | 2004 | 0.9160 | 0.8717 | 0.8933 | 0.7689 | 119 | 191 |
| `messages_without_urls` | content_only | 1 | 1.0000 | 1.0000 | 1.0000 | N/A | 0 | 0 |
| `messages_without_urls` | url_only | 1 | 1.0000 | 1.0000 | 1.0000 | N/A | 0 | 0 |
| `messages_without_urls` | dual_channel_v3 | 1 | 1.0000 | 1.0000 | 1.0000 | N/A | 0 | 0 |

---

## 3. Threshold Optimization (Dual-Channel V3 on Validation Only)

* **Reference $\tau = 0.50$:** F1 = 0.8934, Precision = 0.9161, Recall = 0.8718, Specificity = 0.7689
* **Max F1 ($\tau = 0.35$):** F1 = 0.8978, Precision = 0.8766, Recall = 0.9201, Specificity = 0.6252
* **High Specificity $\ge 90\%$ ($\tau = 0.70$):** F1 = 0.8716, Precision = 0.9612, Recall = 0.7973, Specificity = 0.9068
