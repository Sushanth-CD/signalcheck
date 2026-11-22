"""Evaluate the local rule analyzer against synthetic JSONL cases."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzer import analyze_content  # noqa: E402

DATASET_PATH = Path(__file__).with_name("cases.jsonl")
REQUIRED_FIELDS = {
    "case_id",
    "content",
    "expected_label",
    "expected_category",
    "rationale",
    "source_type",
    "evaluation_scope",
}
VALID_LABELS = {"suspicious", "benign"}
VALID_SCOPES = {"in_scope", "out_of_scope"}
EXPECTED_SCOPE_COUNTS = {"in_scope": 79, "out_of_scope": 1}
EXPECTED_OUT_OF_SCOPE_IDS = {"S027"}


def load_cases(path: Path = DATASET_PATH) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid JSON on line {line_number}: {error}") from error
        if not isinstance(record, dict):
            raise ValueError(f"Line {line_number} must contain a JSON object")
        cases.append(record)
    return cases


def validate_cases(cases: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    counts: Counter[str] = Counter()
    scope_counts: Counter[str] = Counter()
    out_of_scope_ids: set[str] = set()
    for index, case in enumerate(cases, 1):
        missing = REQUIRED_FIELDS - case.keys()
        if missing:
            errors.append(f"Record {index}: missing fields {', '.join(sorted(missing))}")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(f"Record {index}: case_id must be a non-empty string")
        elif case_id in seen_ids:
            errors.append(f"Duplicate case_id: {case_id}")
        else:
            seen_ids.add(case_id)
        label = case.get("expected_label")
        if label not in VALID_LABELS:
            errors.append(f"Record {index}: invalid expected_label {label!r}")
        else:
            counts[label] += 1
        if not isinstance(case.get("content"), str) or not case["content"].strip():
            errors.append(f"Record {index}: content must be a non-empty string")
        if not isinstance(case.get("rationale"), str) or not case["rationale"].strip():
            errors.append(f"Record {index}: rationale must be a non-empty string")
        if case.get("source_type") != "synthetic":
            errors.append(f"Record {index}: source_type must be 'synthetic'")
        scope = case.get("evaluation_scope")
        if scope not in VALID_SCOPES:
            errors.append(f"Record {index}: invalid evaluation_scope {scope!r}")
        else:
            scope_counts[scope] += 1
            if scope == "out_of_scope" and isinstance(case_id, str):
                out_of_scope_ids.add(case_id)
        category = case.get("expected_category")
        if category is not None and category not in {
            "phishing",
            "digital_arrest",
            "malicious_application",
        }:
            errors.append(f"Record {index}: unsupported expected_category {category!r}")
    if len(cases) != 80:
        errors.append(f"Expected 80 records, found {len(cases)}")
    for label in sorted(VALID_LABELS):
        if counts[label] != 40:
            errors.append(f"Expected 40 {label} records, found {counts[label]}")
    for scope, expected_count in EXPECTED_SCOPE_COUNTS.items():
        if scope_counts[scope] != expected_count:
            errors.append(f"Expected {expected_count} {scope} records, found {scope_counts[scope]}")
    if sum(scope_counts.values()) != len(cases):
        errors.append("Evaluation scope counts do not reconcile with total records")
    if out_of_scope_ids != EXPECTED_OUT_OF_SCOPE_IDS:
        errors.append(
            "Expected out-of-scope case IDs "
            f"{sorted(EXPECTED_OUT_OF_SCOPE_IDS)}, found {sorted(out_of_scope_ids)}"
        )
    return errors


def safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def calculate_metrics(rows: list[dict[str, Any]]) -> dict[str, int | float]:
    tp = sum(row["expected"] == "suspicious" and row["predicted"] == "suspicious" for row in rows)
    fp = sum(row["expected"] == "benign" and row["predicted"] == "suspicious" for row in rows)
    tn = sum(row["expected"] == "benign" and row["predicted"] == "benign" for row in rows)
    fn = sum(row["expected"] == "suspicious" and row["predicted"] == "benign" for row in rows)
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = safe_ratio(2 * precision * recall, precision + recall)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": safe_ratio(tn, tn + fp),
    }


def _print_metrics(title: str, metrics: dict[str, int | float]) -> None:
    print(title)
    print(f"  TP {metrics['tp']:>2}  FP {metrics['fp']:>2}")
    print(f"  FN {metrics['fn']:>2}  TN {metrics['tn']:>2}")
    print(
        "  Precision {precision:.3f}  Recall {recall:.3f}  F1 {f1:.3f}  Specificity {specificity:.3f}".format(
            **metrics
        )
    )


def _print_evaluation(title: str, rows: list[dict[str, Any]]) -> dict[str, int | float]:
    metrics = calculate_metrics(rows)
    print(f"\n{title} (n={len(rows)})")
    print("  Confusion matrix (rows = expected, columns = predicted)")
    print("                   Pred suspicious  Pred benign")
    print(f"  Expected suspicious       {metrics['tp']:>3}           {metrics['fn']:>3}")
    print(f"  Expected benign           {metrics['fp']:>3}           {metrics['tn']:>3}")
    _print_metrics("  Metrics", metrics)
    return metrics


def evaluate(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        result = analyze_content(case["content"])
        detected_categories = {item.category for item in result.detected_indicators}
        rows.append(
            {
                "case_id": case["case_id"],
                "evaluation_scope": case["evaluation_scope"],
                "expected": case["expected_label"],
                "predicted": "suspicious" if result.detected_indicators else "benign",
                "expected_category": case["expected_category"],
                "detected_categories": detected_categories,
                "rationale": case["rationale"],
                "rule_ids": [item.rule_id for item in result.detected_indicators],
            }
        )
    return rows


def main() -> int:
    try:
        cases = load_cases()
        errors = validate_cases(cases)
    except (OSError, ValueError) as error:
        print(f"Dataset error: {error}", file=sys.stderr)
        return 2
    if errors:
        print("Dataset validation FAILED:")
        for error in errors:
            print(f"- {error}")
        return 2

    print("Dataset validation: PASS (80 records; 40 suspicious, 40 benign; 79 in_scope, 1 out_of_scope; unique IDs; required fields present)")
    print("Source: synthetic examples only; not representative of real-world incidents or populations.")
    rows = evaluate(cases)
    in_scope_rows = [row for row in rows if row["evaluation_scope"] == "in_scope"]
    out_of_scope_rows = [row for row in rows if row["evaluation_scope"] == "out_of_scope"]
    if len(in_scope_rows) + len(out_of_scope_rows) != len(rows):
        print("Evaluation scope counts do not reconcile", file=sys.stderr)
        return 2
    _print_evaluation("Overall evaluation (all cases; includes out-of-scope challenge cases)", rows)
    _print_evaluation("In-scope evaluation (in_scope cases only)", in_scope_rows)

    print(f"\nOut-of-scope challenge cases ({len(out_of_scope_rows)}; included in overall metrics, excluded from in-scope metrics)")
    if not out_of_scope_rows:
        print("  None")
    for row in out_of_scope_rows:
        print(
            f"  {row['case_id']}: expected={row['expected']}, predicted={row['predicted']}, "
            f"rules={', '.join(row['rule_ids']) or 'none'}; {row['rationale']}"
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["expected_category"]:
            grouped[row["expected_category"]].append(row)
    print("\nPer-category metrics (category-labelled cases; n >= 5)")
    printed = False
    for category in sorted(grouped):
        group = grouped[category]
        if len(group) < 5:
            continue
        printed = True
        _print_metrics(f"{category} (n={len(group)})", calculate_metrics(group))
    if not printed:
        print("  No category reached n=5.")

    errors_by_type = {
        "Overall false positives": [row for row in rows if row["expected"] == "benign" and row["predicted"] == "suspicious"],
        "Overall false negatives": [row for row in rows if row["expected"] == "suspicious" and row["predicted"] == "benign"],
        "In-scope false positives": [row for row in in_scope_rows if row["expected"] == "benign" and row["predicted"] == "suspicious"],
        "In-scope false negatives": [row for row in in_scope_rows if row["expected"] == "suspicious" and row["predicted"] == "benign"],
    }
    for title, items in errors_by_type.items():
        print(f"\n{title} ({len(items)})")
        if not items:
            print("  None")
        for row in items:
            print(f"  {row['case_id']} — {row['rationale']} (rules: {', '.join(row['rule_ids']) or 'none'})")
    print("\nLIMITATION: These synthetic results are not validated real-world performance and do not establish detection accuracy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
