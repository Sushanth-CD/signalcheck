# Phishing Classifier V2 — domain-held-out experiment

This is a within-dataset, domain-grouped evaluation. It is not an independent real-world validation and does not establish general accuracy.

- Python 3.14.6, scikit-learn 1.8.0; seed 20261026; threshold 0.5.
- Source rows joined and checked: 77,677; model-eligible split rows: 13,545.
- Unique normalized-text representatives: train 9,481, validation 2,005, test 1,997.
- Training used only 9,481 training representatives; TF-IDF was fit within the pipeline on those texts only.
- The original source labels were preserved (0=benign according to source, 1=phishing according to source).
- No model or score tuning used validation or test data; threshold 0.5 was fixed before evaluation.
- Saved-model reload and exact prediction reproduction: True.

## Test: primary unseen-domain cohort

- Unique normalized-text examples: 1,993; records with confident destination keys in the split manifest: 1,993.
- Confusion matrix [[TN, FP], [FN, TP]]: [[383, 130], [176, 1304]].
- Precision 0.909344; recall 0.881081; F1 0.894990; specificity 0.746589; accuracy 0.846463; ROC-AUC 0.911333; average precision 0.965102.

## Test: secondary model-eligible examples without a confident destination key

- Unique normalized-text examples: 4.
- Confusion matrix [[TN, FP], [FN, TP]]: [[0, 0], [0, 4]].
- Precision 1.0; recall 1.0; F1 1.0; specificity None; accuracy 1.0; ROC-AUC None; average precision None.

## Validation

Validation metrics are reported in metrics.json and the classification report. Validation did not alter the fixed 0.5 threshold or model configuration.

## Limitations

- The source labels have not been independently validated.
- The primary destination-bearing cohort is a selected subset of the source; records with no confident destination or hard unresolved candidates are not counted as unseen-domain test examples.
- The test partition is from the same dataset whose prior baseline results were inspected during development.
- Logistic Regression scores are model outputs and are not demonstrated to be calibrated probabilities.
- No FastAPI integration, real-world accuracy claim, or detector change is part of this experiment.
