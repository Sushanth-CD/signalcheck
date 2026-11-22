# Phishing TF-IDF + Logistic Regression baseline

Dataset-source evaluation only; this does not establish real-world detection accuracy.

- Target: label_original 0=benign, 1=phishing; threshold=0.5.
- Seed=20261026; Python=3.14.6; scikit-learn=1.9.1.
- Eligible primary unique texts=76,641; explicitly flagged promotional records=696; additional propagated quarantine records=85.
- Promotional examples retain original label 1. Their labels have not been independently adjudicated; supplementary results below are source-label agreement only.

## Primary test results

- Unique test texts: 11,496.
- Confusion matrix [[TN, FP], [FN, TP]]: [[6236, 502], [465, 4293]].
- TN=6236, FP=502, FN=465, TP=4293.
- Precision=0.895308; recall=0.902270; F1=0.898775; specificity=0.925497; accuracy=0.915884; ROC-AUC=0.9738565944644512.

## Split sizes and classes

| Partition | Unique normalized texts | Source records | Label 0 | Label 1 |
|---|---:|---:|---:|---:|
| train | 53,649 | 53,829 | 31,449 | 22,200 |
| validation | 11,496 | 11,545 | 6,738 | 4,758 |
| test | 11,496 | 11,521 | 6,738 | 4,758 |

## Validation and input-type results

Validation metrics: {"records": 11496, "class_counts": {"0": 6738, "1": 4758}, "confusion_matrix_labels_0_1": [[6270, 468], [446, 4312]], "TN": 6270, "FP": 468, "FN": 446, "TP": 4312, "precision": 0.902092050209205, "recall": 0.9062631357713324, "f1": 0.9041727825539946, "specificity": 0.9305431878895815, "accuracy": 0.9204940848990953, "roc_auc": 0.9778633127428071, "roc_auc_note": null}

- email: n=190, classes={'0': 159, '1': 31}, confusion=[[153, 6], [1, 30]], precision=0.8333333333333334, recall=0.967741935483871, F1=0.8955223880597015, specificity=0.9622641509433962, accuracy=0.9631578947368421, ROC-AUC=0.9977683100020288
- html: n=2303, classes={'0': 1475, '1': 828}, confusion=[[1421, 54], [78, 750]], precision=0.9328358208955224, recall=0.9057971014492754, F1=0.9191176470588235, specificity=0.9633898305084746, accuracy=0.9426834563612679, ROC-AUC=0.9838180627200522
- plain_text: n=2818, classes={'0': 1739, '1': 1079}, confusion=[[1702, 37], [133, 946]], precision=0.9623601220752798, recall=0.8767377201112141, F1=0.9175557710960233, specificity=0.9787234042553191, accuracy=0.9396735273243435, ROC-AUC=0.9908041064154881
- url: n=6185, classes={'0': 3365, '1': 2820}, confusion=[[2960, 405], [253, 2567]], precision=0.8637281292059219, recall=0.9102836879432624, F1=0.8863950276243094, specificity=0.8796433878157504, accuracy=0.8936135812449475, ROC-AUC=0.9594666097604669

## Promotional quarantine (supplementary; unadjudicated)

- Explicit review-flagged records scored: 696.
- Confusion matrix and metrics versus unchanged original labels: {"records": 696, "class_counts": {"0": 0, "1": 696}, "confusion_matrix_labels_0_1": [[0, 0], [63, 633]], "TN": 0, "FP": 0, "FN": 63, "TP": 633, "precision": 1.0, "recall": 0.9094827586206896, "f1": 0.9525959367945824, "specificity": null, "accuracy": 0.9094827586206896, "roc_auc": null, "roc_auc_note": "Undefined: this subset has only one class."}
- These records were not used in primary fitting or primary test metrics. Their labels have not been independently adjudicated.

## Error review

- Primary test false positives: 502; false negatives: 465.
- All primary test errors are in C:\Projects\cyber-security-awareness-platform\backend\reports\ml\text_phishing_baseline\test_error_analysis.csv. Representative examples are in metrics.json.

## Reproduction

- Candidate SHA-256: 9d351c5da6ae6304a9036bc8b08d4f7a923013544ee8caa3b29fa1425f5147cc.
- Saved pipeline: backend\models\text\phishing_tfidf_logreg.joblib.
- Split manifest: backend\reports\ml\text_phishing_baseline\split_manifest.csv.
- The test set was not used for tuning. Model features contain text only.
