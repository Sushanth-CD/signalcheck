"""Evaluate an independent synthetic challenge set using the local V1 analyzer."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzer import analyze_content  # noqa: E402

DATASET_PATH = Path(__file__).with_name("challenge_cases.jsonl")
REQUIRED_FIELDS = {
    "case_id", "content", "expected_label", "expected_category", "rationale",
    "source_type", "evaluation_scope",
}
VALID_LABELS = {"suspicious", "benign"}
VALID_CATEGORIES = {"phishing", "digital_arrest", "malicious_application"}
VALID_SCOPES = {"in_scope", "out_of_scope"}


def load_cases(path: Path = DATASET_PATH) -> list[dict[str, Any]]:
    cases = []
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {number}: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Line {number} must be a JSON object")
        cases.append(record)
    return cases


def validate_cases(cases: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    ids: set[str] = set()
    label_counts: Counter[str] = Counter()
    scope_counts: Counter[str] = Counter()
    if len(cases) != 40:
        errors.append(f"Expected 40 cases, found {len(cases)}")
    for number, case in enumerate(cases, 1):
        missing = REQUIRED_FIELDS - case.keys()
        if missing:
            errors.append(f"Record {number}: missing fields {', '.join(sorted(missing))}")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(f"Record {number}: case_id must be a non-empty string")
        elif case_id in ids:
            errors.append(f"Duplicate case_id: {case_id}")
        else:
            ids.add(case_id)
        label = case.get("expected_label")
        if label not in VALID_LABELS:
            errors.append(f"Record {number}: invalid expected_label {label!r}")
        else:
            label_counts[label] += 1
        if not isinstance(case.get("content"), str) or not case["content"].strip():
            errors.append(f"Record {number}: content must be a non-empty string")
        if not isinstance(case.get("rationale"), str) or not case["rationale"].strip():
            errors.append(f"Record {number}: rationale must be a non-empty string")
        if case.get("source_type") != "synthetic":
            errors.append(f"Record {number}: source_type must be 'synthetic'")
        scope = case.get("evaluation_scope")
        if scope not in VALID_SCOPES:
            errors.append(f"Record {number}: invalid evaluation_scope {scope!r}")
        else:
            scope_counts[scope] += 1
        category = case.get("expected_category")
        if category is not None and category not in VALID_CATEGORIES:
            errors.append(f"Record {number}: unsupported expected_category {category!r}")
    if label_counts != Counter({"suspicious": 20, "benign": 20}):
        errors.append(f"Expected 20 suspicious and 20 benign cases, found {dict(label_counts)}")
    if scope_counts["out_of_scope"]:
        errors.append("Out-of-scope cases are not allowed in primary challenge metrics")
    if scope_counts["in_scope"] != len(cases):
        errors.append("In-scope count does not reconcile with total challenge cases")
    return errors


def safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def calculate_metrics(rows: list[dict[str, Any]]) -> dict[str, int | float]:
    tp = sum(r["expected"] == "suspicious" and r["predicted"] == "suspicious" for r in rows)
    fp = sum(r["expected"] == "benign" and r["predicted"] == "suspicious" for r in rows)
    tn = sum(r["expected"] == "benign" and r["predicted"] == "benign" for r in rows)
    fn = sum(r["expected"] == "suspicious" and r["predicted"] == "benign" for r in rows)
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = safe_ratio(2 * precision * recall, precision + recall)
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "specificity": safe_ratio(tn, tn + fp),
    }


def evaluate(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for case in cases:
        result = analyze_content(case["content"])
        findings = result.detected_indicators
        rows.append({
            "case_id": case["case_id"],
            "expected": case["expected_label"],
            "predicted": "suspicious" if findings else "benign",
            "rationale": case["rationale"],
            "rule_ids": [finding.rule_id for finding in findings],
        })
    return rows


def main() -> int:
    try:
        cases = load_cases()
    except (OSError, ValueError) as exc:
        print(f"Dataset error: {exc}", file=sys.stderr)
        return 2
    errors = validate_cases(cases)
    if errors:
        print("Challenge dataset validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 2

    print("Challenge dataset validation: PASS (40 cases; 20 suspicious, 20 benign; all in_scope)")
    print("Synthetic challenge only; not independent real-world validation or accuracy evidence.")
    rows = evaluate(cases)
    metrics = calculate_metrics(rows)
    print("\nChallenge evaluation (n=40)")
    print(f"  TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
    print("  Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f} Specificity={specificity:.3f}".format(**metrics))
    for title, predicate in (
        ("False positives", lambda row: row["expected"] == "benign" and row["predicted"] == "suspicious"),
        ("False negatives", lambda row: row["expected"] == "suspicious" and row["predicted"] == "benign"),
    ):
        errors = [row for row in rows if predicate(row)]
        print(f"\n{title} ({len(errors)})")
        if not errors:
            print("  None")
        for row in errors:
            print(f"  {row['case_id']}: expected={row['expected']} predicted={row['predicted']} rules={', '.join(row['rule_ids']) or 'none'}; {row['rationale']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
