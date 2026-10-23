# Synthetic detection evaluation

## Purpose

This directory provides a repeatable, independent check of the current deterministic analyzer against labelled synthetic examples. It does not change rules or score weights, and it does not establish detection accuracy on actual messages.

## Dataset

`cases.jsonl` contains 80 synthetic cases: 40 labelled suspicious and 40 benign. Cases cover all eight enabled rules in the current contract (`PH001`, `PH011`, `DA001`, `DA002`, `APP001`, `APP002`, `URL001`, and `URL002`), along with near-misses, educational discussion, routine banking notices, malformed links, and messages with multiple indicators. The examples are authored for exercising known rule scope; they do not represent actual incidents or a wider population.

Each JSONL record has `case_id`, `content`, `expected_label`, `expected_category`, `rationale`, and `source_type`. All records use `source_type: synthetic`. A category is a grouping for analysis, not a separate prediction target.

## Run

From the repository root, with the backend environment active:

```powershell
cd backend
python evaluation/evaluate.py
```

The evaluator imports and calls `app.analyzer.analyze_content` directly. It does not call the HTTP endpoint, open URLs, or make network requests. It uses only the Python standard library and project code.

Before evaluating, it checks JSON parsing, required fields, duplicate IDs, labels, empty content, synthetic source labels, total count, and the expected 40/40 class split. A validation error stops evaluation. It does not modify or relabel cases to improve results.

## Metrics

- **True positive (TP):** suspicious case predicted suspicious.
- **False positive (FP):** benign case predicted suspicious.
- **True negative (TN):** benign case predicted benign.
- **False negative (FN):** suspicious case predicted benign.
- **Precision:** TP / (TP + FP), the share of suspicious predictions that match labels.
- **Recall:** TP / (TP + FN), the share of labelled suspicious cases detected.
- **F1:** harmonic mean of precision and recall.
- **Specificity:** TN / (TN + FP), the share of labelled benign cases correctly predicted.

Undefined ratios with a zero denominator print as 0.000. The confusion matrix uses expected labels as rows and predictions as columns. Category metrics group cases by their declared `expected_category`; groups smaller than five are omitted from the category summary to avoid suggesting stable interpretation from very small counts. Category grouping is not a measure of rule-level accuracy.

False-positive and false-negative lists include case IDs and short rationales to make misses and overmatches reviewable.

## Limitations

All cases are synthetic and intentionally exercise phrases and combinations already represented in the current rules. This creates a narrow, hand-authored evaluation set and can favor known wording. It does not sample the diversity, language, obfuscation, context, or base rates of real communications. Expected labels are author judgements for these examples, not incident findings.

A passing evaluation means only that the implementation produced certain outputs for this fixed set. It cannot guarantee detection of real scams, safety of benign-looking content, or performance on future or unseen messages. A detector may miss supported patterns or flag educational content; report those results rather than changing expected labels to improve metrics. No real-world performance or accuracy claim is made.
