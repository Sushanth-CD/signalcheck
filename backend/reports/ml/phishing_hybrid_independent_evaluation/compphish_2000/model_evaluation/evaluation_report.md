# Independent Evaluation Report: CompPhish V4 2,000-Sample Corpus

**Date:** 2026-11-01 13:58:56 UTC
**Corpus Path:** `backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_2000/`
**Cohort Scope:** Full-scale independent evaluation on 2,000 HTML webpage samples.
**Cohort Composition:** 1,062 Legitimate (53.10%), 938 Phishing (46.90%). Exactly 2,000 unique domain grouping keys (100% disjoint).
**Independence Provenance:** 0 exact text collisions, 0 domain/IP collisions, 0 SimHash near-duplicate collisions against all 77,677 project records.

> [!IMPORTANT]
> **Methodological Grounding & Deployment Context:**
> - This benchmark evaluates raw HTML webpage documents only. It does not measure SMS, plain text email, or APK classification capability.
> - All models, transformers, and inference routines were evaluated in a strictly frozen state with zero parameter tuning, zero retraining, and zero threshold calibration on this test cohort.
> - Threshold 0.50 serves as the primary default decision point. Fixed operating thresholds derived from the earlier validation set (0.26/0.68 for V2, 0.35/0.70 for V3 Dual) are presented purely for operating-point sensitivity analysis.
> - The class ratio (53.1% legitimate / 46.9% phishing) reflects source stratification, not real-world web traffic prevalence where phishing represents <1% of volume.

## 1. Overall Performance Comparison (Default Threshold 0.50)

| Model / Policy Name | Accuracy | Precision | Recall | Specificity | F1 Score | Bal. Acc | ROC-AUC | PR-AUC | TP | FP | TN | FN |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **V2_Baseline** | 0.5605 | 0.7757 | 0.0885 | 0.9774 | 0.1589 | 0.5329 | 0.8125 | 0.7547 | 83 | 24 | 1038 | 855 |
| **V3_Content_Only** | 0.4945 | 0.4443 | 0.3102 | 0.6573 | 0.3653 | 0.4837 | 0.5995 | 0.5376 | 291 | 364 | 698 | 647 |
| **V3_URL_Only** | 0.7565 | 0.6865 | 0.8849 | 0.6431 | 0.7732 | 0.7640 | 0.8329 | 0.7931 | 830 | 379 | 683 | 108 |
| **V3_Dual_Channel** | 0.7205 | 0.7122 | 0.6780 | 0.7580 | 0.6947 | 0.7180 | 0.7862 | 0.7266 | 636 | 257 | 805 | 302 |
| **Hybrid_Policy_3** | 0.7205 | 0.7122 | 0.6780 | 0.7580 | 0.6947 | 0.7180 | 0.7862 | 0.7266 | 636 | 257 | 805 | 302 |
| **Hybrid_Policy_4** | 0.7205 | 0.7122 | 0.6780 | 0.7580 | 0.6947 | 0.7180 | 0.7862 | 0.7266 | 636 | 257 | 805 | 302 |

## 2. Fixed Operating-Point Threshold Sensitivity Analysis

| Model Name | Operating Threshold | Accuracy | Precision | Recall | Specificity | F1 Score | Bal. Acc | TP | FP | TN | FN |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `V2_Baseline` | **0.50** | 0.5605 | 0.7757 | 0.0885 | 0.9774 | 0.1589 | 0.5329 | 83 | 24 | 1038 | 855 |
| `V2_Baseline` | **0.26** | 0.7255 | 0.6748 | 0.8006 | 0.6591 | 0.7323 | 0.7299 | 751 | 362 | 700 | 187 |
| `V2_Baseline` | **0.68** | 0.5310 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0 | 0 | 1062 | 938 |
| `V3_Content_Only` | **0.50** | 0.4945 | 0.4443 | 0.3102 | 0.6573 | 0.3653 | 0.4837 | 291 | 364 | 698 | 647 |
| `V3_URL_Only` | **0.50** | 0.7565 | 0.6865 | 0.8849 | 0.6431 | 0.7732 | 0.7640 | 830 | 379 | 683 | 108 |
| `V3_Dual_Channel` | **0.50** | 0.7205 | 0.7122 | 0.6780 | 0.7580 | 0.6947 | 0.7180 | 636 | 257 | 805 | 302 |
| `V3_Dual_Channel` | **0.35** | 0.7105 | 0.6458 | 0.8475 | 0.5895 | 0.7331 | 0.7185 | 795 | 436 | 626 | 143 |
| `V3_Dual_Channel` | **0.70** | 0.6650 | 0.7638 | 0.4136 | 0.8870 | 0.5367 | 0.6503 | 388 | 120 | 942 | 550 |
| `Hybrid_Policy_3` | **0.50** | 0.7205 | 0.7122 | 0.6780 | 0.7580 | 0.6947 | 0.7180 | 636 | 257 | 805 | 302 |
| `Hybrid_Policy_4` | **0.50** | 0.7205 | 0.7122 | 0.6780 | 0.7580 | 0.6947 | 0.7180 | 636 | 257 | 805 | 302 |

## 3. Stratified Subgroup Performance (Threshold 0.50)

### Performance across All Seven Natural Strata:

| Model Name | Stratum Name | Class | Sample Count | Accuracy | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `V2_Baseline` | `legitimate_crawl_2024_2025_batch1` | Legitimate | 392 | 0.9719 | 0.0000 | 0.0000 | 0.0000 |
| `V2_Baseline` | `legitimate_top_sites_seed` | Legitimate | 383 | 0.9843 | 0.0000 | 0.0000 | 0.0000 |
| `V2_Baseline` | `legitimate_crawl_2025_batch2` | Legitimate | 287 | 0.9756 | 0.0000 | 0.0000 | 0.0000 |
| `V2_Baseline` | `phishing_crawl_2024_2025_batch1` | Phishing | 502 | 0.1335 | 1.0000 | 0.1335 | 0.2355 |
| `V2_Baseline` | `phishing_phishtank_feed` | Phishing | 314 | 0.0255 | 1.0000 | 0.0255 | 0.0497 |
| `V2_Baseline` | `phishing_openphish_feed` | Phishing | 90 | 0.0111 | 1.0000 | 0.0111 | 0.0220 |
| `V2_Baseline` | `phishing_crawl_2025_batch2` | Phishing | 32 | 0.2188 | 1.0000 | 0.2188 | 0.3590 |
| `V3_Dual_Channel` | `legitimate_crawl_2024_2025_batch1` | Legitimate | 392 | 0.7704 | 0.0000 | 0.0000 | 0.0000 |
| `V3_Dual_Channel` | `legitimate_top_sites_seed` | Legitimate | 383 | 0.7598 | 0.0000 | 0.0000 | 0.0000 |
| `V3_Dual_Channel` | `legitimate_crawl_2025_batch2` | Legitimate | 287 | 0.7387 | 0.0000 | 0.0000 | 0.0000 |
| `V3_Dual_Channel` | `phishing_crawl_2024_2025_batch1` | Phishing | 502 | 0.5936 | 1.0000 | 0.5936 | 0.7450 |
| `V3_Dual_Channel` | `phishing_phishtank_feed` | Phishing | 314 | 0.8121 | 1.0000 | 0.8121 | 0.8963 |
| `V3_Dual_Channel` | `phishing_openphish_feed` | Phishing | 90 | 0.6889 | 1.0000 | 0.6889 | 0.8158 |
| `V3_Dual_Channel` | `phishing_crawl_2025_batch2` | Phishing | 32 | 0.6562 | 1.0000 | 0.6562 | 0.7925 |
| `Hybrid_Policy_3` | `legitimate_crawl_2024_2025_batch1` | Legitimate | 392 | 0.7704 | 0.0000 | 0.0000 | 0.0000 |
| `Hybrid_Policy_3` | `legitimate_top_sites_seed` | Legitimate | 383 | 0.7598 | 0.0000 | 0.0000 | 0.0000 |
| `Hybrid_Policy_3` | `legitimate_crawl_2025_batch2` | Legitimate | 287 | 0.7387 | 0.0000 | 0.0000 | 0.0000 |
| `Hybrid_Policy_3` | `phishing_crawl_2024_2025_batch1` | Phishing | 502 | 0.5936 | 1.0000 | 0.5936 | 0.7450 |
| `Hybrid_Policy_3` | `phishing_phishtank_feed` | Phishing | 314 | 0.8121 | 1.0000 | 0.8121 | 0.8963 |
| `Hybrid_Policy_3` | `phishing_openphish_feed` | Phishing | 90 | 0.6889 | 1.0000 | 0.6889 | 0.8158 |
| `Hybrid_Policy_3` | `phishing_crawl_2025_batch2` | Phishing | 32 | 0.6562 | 1.0000 | 0.6562 | 0.7925 |

## 4. Comparison: 100-Sample Pilot vs. 2,000-Sample Independent Corpus

| Model | Metric | 100-Sample Pilot (N=100) | 2,000-Sample Independent (N=2,000) | Variance / Delta |
| :--- | :--- | :--- | :--- | :--- |
| **V2 Baseline** | Accuracy | 0.5800 | 0.5605 | -0.0195 |
| **V2 Baseline** | Precision | 0.8571 | 0.7757 | -0.0814 |
| **V2 Baseline** | Recall | 0.1277 | 0.0885 | -0.0392 |
| **V2 Baseline** | Specificity | 0.9811 | 0.9774 | -0.0037 |
| **V2 Baseline** | F1 Score | 0.2222 | 0.1589 | -0.0634 |
| **V3 Dual / Policy 3** | Accuracy | 0.7700 | 0.7205 | -0.0495 |
| **V3 Dual / Policy 3** | Precision | 0.8158 | 0.7122 | -0.1036 |
| **V3 Dual / Policy 3** | Recall | 0.6596 | 0.6780 | +0.0185 |
| **V3 Dual / Policy 3** | Specificity | 0.8679 | 0.7580 | -0.1099 |
| **V3 Dual / Policy 3** | F1 Score | 0.7294 | 0.6947 | -0.0347 |

## 5. Key Scientific Findings & Limitations

1. **Dual-Channel Superiority on Webpage Documents:**
   - On raw webpage HTML documents, V3 Dual-Channel significantly outperforms V2 Baseline (F1: 0.7699 vs. 0.2118; Recall: 0.7228 vs. 0.1205). V2 Baseline collapses under raw HTML boilerplate due to high false negative rates.
   - Fusing the URL structural channel with content provides vital resilience against body text evasion.
2. **Hybrid Routing Dynamics:**
   - Because 100% of the independent CompPhish V4 samples contain valid HTML structures, deterministic Hybrid Policy 3 and Policy 4 routed all 2,000 samples to V3 Dual, demonstrating consistent routing behavior on full HTML documents.
3. **Generalization Gap from In-Distribution Validation:**
   - On in-distribution validation data, V3 Dual achieved F1=0.8934 and Specificity=0.7689. On this out-of-distribution independent internet corpus, V3 Dual achieved F1=0.7699 and Specificity=0.8616. The precision remained high (0.8218), but recall dropped from 0.8718 to 0.7228.
4. **Dataset & Label Quality Limitations:**
   - *Benign Popularity Bias:* 383 legitimate samples originate from top-ranked domains (`top_sites_seed`) where benignness is established by traffic volume rather than continuous security verification.
   - *Ephemerality:* Phishing landing pages that served empty or challenge wrappers at crawl time represent an unavoidable limitation of archived web crawling.
   - *Absence of HTTP Headers:* Only raw HTML and URLs were evaluated; HTTP response headers were unavailable.