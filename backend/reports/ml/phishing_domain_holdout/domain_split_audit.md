# Phishing registrable-domain holdout audit

This is an exploratory within-dataset experiment. The test set is composed of held-out domain-connected components from the same combined source file; it is not independent real-world validation.

## Data, target, and preserved workflow

- Candidate source: `backend\data\processed\phishing_text_candidates.jsonl`; SHA-256: `9d351c5da6ae6304a9036bc8b08d4f7a923013544ee8caa3b29fa1425f5147cc`.
- Candidate records: 77,676; unique normalized text groups: 77,411; existing near-duplicate components: 75,532.
- Target: `label_original`, 0=benign according to source and 1=phishing according to source. All records come from `combined_reduced.json`; finer row-level source provenance is unavailable.
- Original label counts: 0=44,975; 1=32,701.
- Eligible unique-text class counts before split: 0=34,143; 1=30,205. Eligible source-record class counts: 0=34,172; 1=30,399.
- Reused existing exact/near-duplicate grouping: NFKC/casefold/whitespace normalization, unique 5-character shingles, 64-bit SHA-256 SimHash radius 3, Jaccard threshold 0.90.
- Explicit promotional review flags: 696; all baseline quarantine groups remain quarantined, and quarantine propagates to any connected domain component.
- Training records use text only. The TF-IDF vocabulary is fit by the sklearn pipeline on training groups only.

## URL and domain inventory before partitioning

- URL-like records identified syntactically: 62,691.
- Distinct normalized destination hostnames: 46,806.
- Hostnames mapped by the local PSL to registrable domains: 46,314.
- Distinct registrable domains: 39,802.
- Hostnames handled as IP or exact-host fallback (not registrable-domain keys): 492.
- Bare dotted candidates without a PSL mapping that were intentionally ignored instead of exact-host grouped: 14,226.
- Records with at least one selected destination hostname: 55,240; records without one: 22,436.
- Malformed/unusable URL candidate tokens: 34,122; URL parser status counts: `{'normalized_hostname': 105284, 'invalid_hostname_label': 1847, 'unsupported_or_missing_authority': 23108, 'ip_literal': 534, 'invalid_hostname_length': 4094, 'empty_candidate': 282, 'malformed_url': 1848, 'unqualified_hostname': 2943}`.
- Existing normalized-text groups: 77,411; existing near-duplicate components: 75,532.
- Combined connected components after PSL/domain linking (including quarantined): 53,095; eligible components: 52,574; quarantined components: 521.
- Connected component sizes in unique normalized text groups: `{"groups": 53095, "median": 1.0, "p90_nearest_rank": 1.0, "p95_nearest_rank": 2.0, "maximum": 12341}`.
- Connected component sizes in source records: `{"groups": 53095, "median": 1.0, "p90_nearest_rank": 1.0, "p95_nearest_rank": 2.0, "maximum": 12372}`.
- Components containing both labels among non-conflicting unique text groups: 77.
- Largest eligible component: 145 unique texts (0.23% of eligible unique texts). Components larger than 15% of the eligible unique text pool: 0.

### Largest connected components

| Component | Unique texts | Source records | Unique texts label 0 | Unique texts label 1 | Domain keys | Quarantined |
|---|---:|---:|---:|---:|---:|---|
| `33ad9b084ea1` | 12,341 | 12,372 | 10,772 | 1,569 | 7,221 | True |
| `35f86e9661a0` | 145 | 145 | 145 | 0 | 1 | False |
| `110dd2b2e1a5` | 141 | 141 | 141 | 0 | 1 | False |
| `36fe5d27827d` | 118 | 118 | 118 | 0 | 1 | False |
| `7142eaec0918` | 105 | 105 | 105 | 0 | 1 | False |
| `c86ee9c0c31a` | 105 | 105 | 105 | 0 | 1 | False |
| `e01db696e13d` | 101 | 101 | 101 | 0 | 1 | False |
| `a05f9c782a78` | 92 | 92 | 92 | 0 | 1 | False |
| `8499df502f81` | 88 | 88 | 87 | 1 | 1 | False |
| `4f8b6f4d0af1` | 87 | 89 | 0 | 87 | 0 | False |

Largest component detail: `33ad9b084ea1fb4f024863df94d45639593b39eec7ff61a8dd62502e4b046093`; quarantine reasons: `['near_duplicate_component_has_conflicting_original_labels', 'promotional_review_flag_in_near_duplicate_component']`; example domain group keys: `['exact_host_fallback:addons.mozilla.orgfirefox', 'exact_host_fallback:akkabay.comifyou', 'exact_host_fallback:aol.comsite', 'exact_host_fallback:beast.gtk.orgthere', 'exact_host_fallback:begintodaystarttomorrow.s5.com.comhave', 'exact_host_fallback:econofist.comsubscribe', 'exact_host_fallback:endeavors.comhttp', 'exact_host_fallback:enigmail.mozdev.orgiqevawubpxne16hbxyzzsab3aqh2kqf', 'exact_host_fallback:fluxbox.sf.neti', 'exact_host_fallback:foxinternet.netsite', 'exact_host_fallback:home.comsite', 'exact_host_fallback:mailplus.yahoo.comto', 'exact_host_fallback:orleantraders.4yoursuccess.orgtradelinks', 'exact_host_fallback:uk.my.yahoo.comm', 'exact_host_fallback:webcamzz.dr.aggo', 'exact_host_fallback:www.all-life', 'exact_host_fallback:www.astartetours.comkind', 'exact_host_fallback:www.bankofamerica.com.html', 'exact_host_fallback:www.ben4prez.orggreg', 'exact_host_fallback:www.cashbynet.netthe']`.
Existing near-duplicate quarantine records before domain propagation: 781. Records assigned to quarantine after conservative domain-component propagation: 13,105 (labels 0=10,803, 1=2,302). These records remain in the complete split manifest but are excluded from primary fitting/evaluation under the existing review policy; this is explicitly reported and is not a metric-driven removal.

## Split and class distribution

The deterministic `StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=20261026)` assignment maps folds 0–2 to test, 3–5 to validation, and 6–19 to training. Each connected component is indivisible. The percentages below are based on unique normalized text groups; source-record percentages are included as a secondary accounting measure.

| Partition | Unique texts | Source records | Unique-text label 0 | Unique-text label 1 | Unique-text % | Record % | Deviation from target (unique text / records, pp) |
|---|---:|---:|---:|---:|---:|---:|---:|
| train | 45,034 | 45,196 | 23,895 | 21,139 | 69.99% | 69.99% | -0.01 / -0.01 |
| validation | 9,658 | 9,693 | 5,124 | 4,534 | 15.01% | 15.01% | +0.01 / +0.01 |
| test | 9,656 | 9,682 | 5,124 | 4,532 | 15.01% | 14.99% | +0.01 / -0.01 |

## Leakage and quarantine verification

- Source records in manifest: 77,676; unique source record IDs: 77,676; each input line appears once.
- Registrable-domain key intersections (train/validation, train/test, validation/test): 0 / 0 / 0.
- All domain grouping key intersections, including exact IP and exact-host fallback (same pairs): 0 / 0 / 0.
- Normalized-text group intersections (same pairs): 0 / 0 / 0.
- Existing near-duplicate component intersections (same pairs): 0 / 0 / 0.
- Quarantined records in primary splits: 0; all source records remain represented in the manifest.
- Host extraction is local URL parsing only. No URL was opened, no DNS was queried, and no external network request was made.

## Model and results

- Same baseline configuration: word TF-IDF unigrams+bigrams, min_df=2, max_df=0.995, max_features=200000, sublinear TF; LogisticRegression C=1, liblinear, max_iter=2000. Threshold=0.5.
- Runtime: Python 3.14.6, scikit-learn 1.8.0, NumPy 2.5.4, SciPy 1.18.1.
- Overall test metrics: `{"FN": 444, "FP": 634, "TN": 4490, "TP": 4088, "accuracy": 0.8883595691797845, "average_precision_pr_auc": 0.958431190626743, "class_counts": {"0": 5124, "1": 4532}, "confusion_matrix_labels_0_1": [[4490, 634], [444, 4088]], "f1": 0.8835098335854765, "false_negative_rate": 0.09796999117387467, "false_positive_rate": 0.12373145979703357, "precision": 0.86573485811097, "recall": 0.9020300088261254, "records": 9656, "roc_auc": 0.9644819724150856, "specificity": 0.8762685402029664, "undefined_metric_note": null}`.
- URL-containing test metrics: `{"FN": 357, "FP": 592, "TN": 3238, "TP": 3257, "accuracy": 0.8725147770016121, "average_precision_pr_auc": 0.9513615474311823, "class_counts": {"0": 3830, "1": 3614}, "confusion_matrix_labels_0_1": [[3238, 592], [357, 3257]], "f1": 0.8728393407476887, "false_negative_rate": 0.0987825124515772, "false_positive_rate": 0.15456919060052218, "precision": 0.846193816575734, "recall": 0.9012174875484228, "records": 7444, "roc_auc": 0.9551773925306432, "specificity": 0.8454308093994778, "undefined_metric_note": null}`.
- Non-URL-containing test metrics: `{"FN": 87, "FP": 42, "TN": 1252, "TP": 831, "accuracy": 0.9416817359855335, "average_precision_pr_auc": 0.9839420576476788, "class_counts": {"0": 1294, "1": 918}, "confusion_matrix_labels_0_1": [[1252, 42], [87, 831]], "f1": 0.9279731993299832, "false_negative_rate": 0.09477124183006536, "false_positive_rate": 0.03245749613601236, "precision": 0.9518900343642611, "recall": 0.9052287581699346, "records": 2212, "roc_auc": 0.9897734810908736, "specificity": 0.9675425038639877, "undefined_metric_note": null}`.
- URL test by host-group status: `{"url_with_ip_or_exact_host_fallback": {"FN": 1, "FP": 0, "TN": 6, "TP": 25, "accuracy": 0.96875, "average_precision_pr_auc": 1.0, "class_counts": {"0": 6, "1": 26}, "confusion_matrix_labels_0_1": [[6, 0], [1, 25]], "f1": 0.9803921568627451, "false_negative_rate": 0.038461538461538464, "false_positive_rate": 0.0, "precision": 1.0, "recall": 0.9615384615384616, "records": 32, "roc_auc": 1.0, "specificity": 1.0, "undefined_metric_note": null}, "url_with_registrable_domain": {"FN": 321, "FP": 555, "TN": 2798, "TP": 2698, "accuracy": 0.8625235404896422, "average_precision_pr_auc": 0.9432668894629236, "class_counts": {"0": 3353, "1": 3019}, "confusion_matrix_labels_0_1": [[2798, 555], [321, 2698]], "f1": 0.8603316326530612, "false_negative_rate": 0.10632659821132825, "false_positive_rate": 0.1655234118699672, "precision": 0.8293882569935445, "recall": 0.8936734017886717, "records": 6372, "roc_auc": 0.9496175775906583, "specificity": 0.8344765881300328, "undefined_metric_note": null}, "url_without_extractable_destination": {"FN": 35, "FP": 37, "TN": 434, "TP": 534, "accuracy": 0.9307692307692308, "average_precision_pr_auc": 0.9807710231157611, "class_counts": {"0": 471, "1": 569}, "confusion_matrix_labels_0_1": [[434, 37], [35, 534]], "f1": 0.9368421052631579, "false_negative_rate": 0.061511423550087874, "false_positive_rate": 0.07855626326963906, "precision": 0.9352014010507881, "recall": 0.9384885764499121, "records": 1040, "roc_auc": 0.9787685774946921, "specificity": 0.921443736730361, "undefined_metric_note": null}}`.
- Test class reports by overall, URL/non-URL, and inferred input type are in `classification_report.txt`; detailed metrics are in `metrics.json`.

## Comparison with the existing grouped-text baseline

The saved grouped-text baseline test set contains 11,496 unique normalized texts and reported F1=0.898775, specificity=0.925497, ROC-AUC=0.973857. This new test partition is selected by connected registrable-domain components and has a different set of examples, while the old split was grouped by text/near-duplicates. The existing test set was already inspected. The experiments are therefore not paired or directly equivalent; differences are descriptive and do not establish domain generalization beyond this source corpus.

## Caveats and interpretation

- URL records with registrable domains can test whether the model transfers to domains held out by this split. The no-domain and exact-host fallback slices do not establish unseen registrable-domain generalization.
- Multiple HTML anchor/form destinations are all grouped; this can connect otherwise unrelated pages and enlarge components. Resource URLs (images, scripts, stylesheets) are excluded to reduce unrelated joins. Component sizes and deviations are reported rather than weakening grouping.
- Exact-host fallback is used only for IP literals or clearly URL-shaped authorities (scheme, protocol-relative, `www`, or URL-only records) when the PSL has no registrable result. Bare dotted prose without a PSL result is ignored, not treated as a destination host. Such exact-host keys do not merge subdomains.
- The split is within one combined source file; per-record source IDs, independently adjudicated labels, and independent modern-domain samples are unavailable.
- The existing development baseline used scikit-learn 1.9.1; this run records its active runtime version separately. The pipeline configuration is matched, but library versions and test partitions differ.
- No test-set tuning was performed; threshold remained fixed at 0.5.

## Artifacts

- `experiment_config.json` — input hashes, environment, feature/model setup, split, and artifact paths.
- `split_manifest.csv` — one row per source record with text, near-duplicate, domain component, label, domain, partition, and quarantine identifiers.
- `metrics.json` — overall, URL, non-URL, input-type, and domain-status test metrics plus leakage checks.
- `classification_report.txt` — classification reports by slice.
- `domain_split_audit.md` — this audit and interpretation.
- `model.joblib` — separately saved pipeline; existing models are untouched.
