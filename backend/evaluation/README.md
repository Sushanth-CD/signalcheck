# Synthetic detection evaluation

> **Historical tooling:** The deterministic rule-based analyzer has been
> removed from the active application. `evaluate.py` and
> `evaluate_challenge.py` still describe its former synthetic evaluations,
> but they depend on the retired `app.analyzer` package and are no longer
> executable. Their datasets and prior reports are retained as historical
> records. The active ML-only architecture is documented in
> `docs/ml-only-architecture.md`.

## Purpose

This directory provides a repeatable, independent check of the current deterministic analyzer against labelled synthetic examples. It does not change rules or score weights, and it does not establish detection accuracy on actual messages.

## Dataset

`cases.jsonl` contains 80 synthetic cases: 40 labelled suspicious and 40 benign. Cases cover all eight enabled rules in the current contract (`PH001`, `PH011`, `DA001`, `DA002`, `APP001`, `APP002`, `URL001`, and `URL002`), along with near-misses, educational discussion, routine banking notices, malformed links, and messages with multiple indicators. The examples are authored for exercising known rule scope; they do not represent actual incidents or a wider population.

Each JSONL record has `case_id`, `content`, `expected_label`, `expected_category`, `rationale`, `source_type`, and `evaluation_scope`. All records use `source_type: synthetic`. A category is a grouping for analysis, not a separate prediction target. `evaluation_scope` is either `in_scope` or `out_of_scope`.

The dataset has 79 in-scope examples and one out-of-scope challenge case, S027. S027 is labelled suspicious and retained unchanged, but its generic request to update identity details with an ordinary URL does not meet the conditions of an enabled Version 1 rule. PH010, which covers broader sensitive identity or financial information requests, is not enabled. The enabled PH011 rule requires an account threat, a KYC/account-verification request, and a URL or explicit link instruction; S027 does not establish that combination. The scope annotation describes current contract coverage, not whether the case is suspicious in general.

## Run

From the repository root, with the backend environment active:

```powershell
cd backend
python evaluation/evaluate.py
```

The evaluator imports and calls `app.analyzer.analyze_content` directly. It does not call the HTTP endpoint, open URLs, or make network requests. It uses only the Python standard library and project code.

Before evaluating, it checks JSON parsing, required fields (including valid scope values), duplicate IDs, labels, empty content, synthetic source labels, total count, the expected 40/40 class split, the expected 79/1 scope split, and the out-of-scope case ID. A validation error stops evaluation. It does not modify or relabel cases to improve results.

The evaluator reports two views. **Overall evaluation** includes all 80 cases, including out-of-scope challenge cases, preserving the original all-case result for comparison. **In-scope evaluation** uses only records marked `in_scope`. Out-of-scope IDs and their predictions are printed separately; they are not silently removed from reporting. Scope labels must be justified from the documented rule contract and applied independently of the detector's prediction. This distinction must not be used to conceal supported-rule misses: those remain in scope and count as false negatives. Challenge cases remain visible in the overall evaluation and should prompt contract review if expectations change.

## Development baseline and synthetic challenge

`cases.jsonl` and `evaluate.py` are the development evaluation. These examples have influenced rule implementation and are not an independent test set. Preserve their results as a development baseline; do not describe them as independent or validated detection accuracy.

`challenge_cases.jsonl` and `evaluate_challenge.py` form a separate 40-case synthetic challenge set (20 suspicious and 20 benign) written with alternate wording, borderline cases, educational content, routine notices, partial conditions, URL variations, and overlapping indicators. All challenge cases are marked `in_scope` for the enabled Version 1 contract. Run it from `backend` with:

```powershell
python evaluation/evaluate_challenge.py
```

The challenge evaluator uses the current analyzer as-is, makes no network requests, preserves expected labels, and reports its own confusion counts, metrics, false positives, and false negatives. Do not tune the detector against challenge outcomes and then continue calling the same set an independent challenge; once it informs rule changes, it becomes development data.

Future validation should use suitable public or independently collected data with documented provenance, representative variation, careful label review, and separation from rule development. A synthetic challenge is still hand-authored and cannot represent all real-world scams, benign messages, language variation, or class rates. Neither development results nor synthetic challenge metrics establish real-world accuracy.

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

A passing evaluation means only that the implementation produced certain outputs for this fixed set. It cannot guarantee detection of real scams, safety of benign-looking content, or performance on future or unseen messages. A detector may miss supported patterns or flag educational content; report those results rather than changing expected labels or scope to improve metrics. Synthetic evaluation results do not establish real-world accuracy: the cases are hand-authored, narrow, and do not represent real communications, populations, language variation, or real-world class rates. No real-world performance or accuracy claim is made.
