"""Train and evaluate the separate phishing V2 model on the saved domain split.

Run from the repository root with the project ML environment:
    backend/.venv-ml/Scripts/python.exe backend/notebooks/train_phishing_domain_holdout_v2.py

This fits only training-partition normalized-text representatives. It does not
modify the source data, split, existing model, API, or frontend.
"""
from __future__ import annotations

import csv
import hashlib
import json
import platform
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import scipy
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.ml import train_text_baseline as baseline
from backend.ml.text_normalization import normalize_for_model
from backend.notebooks.prepare_ml_datasets import iter_json_array

SOURCE = ROOT / "backend/data/raw/combined_reduced.json"
SPLIT_DIR = ROOT / "backend/reports/ml/phishing_domain_extraction_v2/domain_holdout_split_v2"
MANIFEST = SPLIT_DIR / "split_manifest.csv"
SPLIT_CONFIG = SPLIT_DIR / "split_config.json"
LEAKAGE = SPLIT_DIR / "leakage_invariants.json"
SPLIT_SUMMARY = SPLIT_DIR / "split_summary.json"
COMPONENT_ASSIGNMENTS = SPLIT_DIR / "component_assignments.csv"
GRAPH_DIR = ROOT / "backend/reports/ml/phishing_domain_extraction_v2/combined_graph_review"
GRAPH_INVARIANTS = GRAPH_DIR / "combined_graph_invariants.json"
DOMAIN_EDGES = GRAPH_DIR / "record_domain_edges.csv"
OUTPUT = ROOT / "backend/reports/ml/phishing_domain_holdout_v2"
SEED = baseline.SEED
THRESHOLD = 0.5
PARTITIONS = {"train", "validation", "test"}
COHORT_PARTITIONS = {
    "no_destination_cohort", "uncertain_destination_cohort", "excluded_empty_text", "quarantined_data_quality"
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def parse_bool(value: str, field: str, index: int) -> bool:
    if value not in {"True", "False"}:
        raise ValueError(f"Manifest record {index}: invalid {field}={value!r}")
    return value == "True"


def validate_inputs() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if OUTPUT.exists():
        raise FileExistsError(f"Refusing to overwrite existing experiment output directory: {OUTPUT}")
    required = [SOURCE, MANIFEST, SPLIT_CONFIG, LEAKAGE, SPLIT_SUMMARY, COMPONENT_ASSIGNMENTS,
                GRAPH_INVARIANTS, DOMAIN_EDGES]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise FileNotFoundError(f"Required training/split input(s) missing: {missing}")

    config = read_json(SPLIT_CONFIG)
    leakage = read_json(LEAKAGE)
    split_summary = read_json(SPLIT_SUMMARY)
    graph_facts = read_json(GRAPH_INVARIANTS)
    if leakage.get("all_checks_passed") is not True:
        raise ValueError("Saved split leakage_invariants.json does not report all_checks_passed=true")
    violations = leakage.get("violations")
    if not isinstance(violations, dict) or any(int(v) != 0 for v in violations.values()):
        raise ValueError(f"Saved split contains leakage violations: {violations}")
    if config.get("allocation_uses_row_level_splitting") is not False:
        raise ValueError("Split config does not confirm component-level partitioning")
    if config.get("primary_policy", "").startswith("Scenario A/D") is False:
        raise ValueError("Split config is not the required Scenario A/D policy")
    if config.get("model_training_performed") is not False:
        raise ValueError("Split config unexpectedly indicates training was already performed")
    if config.get("source_sha256") != sha256_file(SOURCE):
        raise ValueError("Raw source SHA-256 differs from the saved split config")
    if config.get("graph_invariants_sha256") != sha256_file(GRAPH_INVARIANTS):
        raise ValueError("Graph-invariants SHA-256 differs from the saved split config")
    if config.get("source_count") != 77677 or split_summary.get("source_records") != 77677:
        raise ValueError("Split source count is not the verified 77,677 records")

    manifest_rows = read_csv(MANIFEST)
    if len(manifest_rows) != 77677:
        raise ValueError(f"Expected 77,677 manifest records, found {len(manifest_rows)}")
    manifest_by_index: dict[int, dict[str, Any]] = {}
    for row in manifest_rows:
        index = int(row["source_record_index"])
        if index in manifest_by_index:
            raise ValueError(f"Duplicate split manifest source index: {index}")
        expected_id = f"combined_reduced.json:source_record_{index}"
        if row["source_record_id"] != expected_id:
            raise ValueError(f"Unexpected source ID for index {index}: {row['source_record_id']!r}")
        parsed = dict(row)
        parsed["source_record_index"] = index
        parsed["label"] = int(row["label"])
        for name in ("model_eligible", "has_confident_destination_key", "has_domain_key", "has_ip_key",
                     "domain_evaluation_eligible", "has_unresolved_candidate", "has_hard_unresolved_candidate",
                     "is_quarantined_component"):
            parsed[name] = parse_bool(row[name], name, index)
        if row["partition"] not in PARTITIONS | COHORT_PARTITIONS:
            raise ValueError(f"Unknown partition {row['partition']!r} at source index {index}")
        if parsed["partition"] in PARTITIONS and not parsed["model_eligible"]:
            raise ValueError(f"Empty/non-model-eligible record entered a model partition: {index}")
        if parsed["domain_evaluation_eligible"] and not (
            parsed["partition"] in PARTITIONS and parsed["model_eligible"] and parsed["has_confident_destination_key"]
        ):
            raise ValueError(f"Invalid domain-evaluation eligibility at source index {index}")
        manifest_by_index[index] = parsed
    if set(manifest_by_index) != set(range(1, 77678)):
        raise ValueError("Split manifest source indexes are not exactly 1..77,677")

    # Verify indivisible component, normalized-text, near-duplicate and
    # destination-key isolation independently from the saved invariant flag.
    component_parts: dict[str, set[str]] = defaultdict(set)
    norm_parts: dict[str, set[str]] = defaultdict(set)
    near_parts: dict[str, set[str]] = defaultdict(set)
    for row in manifest_by_index.values():
        component_parts[row["component_id"]].add(row["partition"])
        if row["normalized_text_group_id"]:
            norm_parts[row["normalized_text_group_id"]].add(row["partition"])
        if row["near_duplicate_component_id"]:
            near_parts[row["near_duplicate_component_id"]].add(row["partition"])
    for name, mapping in (("component", component_parts), ("normalized text", norm_parts), ("near-duplicate", near_parts)):
        bad = [key for key, parts in mapping.items() if len(parts) > 1]
        if bad:
            raise ValueError(f"Saved split has {len(bad)} {name} groups crossing partitions")

    component_rows = read_csv(COMPONENT_ASSIGNMENTS)
    component_by_id = {r["component_id"]: r for r in component_rows}
    if len(component_by_id) != len(component_rows) or len(component_by_id) != int(leakage["combined_components_checked"]):
        raise ValueError("Component assignment inventory count/IDs do not match leakage report")
    for cid, rows in _group_by(manifest_by_index.values(), "component_id").items():
        assignment = component_by_id.get(cid)
        if assignment is None:
            raise ValueError(f"Manifest component missing from component_assignments.csv: {cid}")
        parts = {r["partition"] for r in rows}
        if len(parts) != 1 or next(iter(parts)) != assignment["partition"]:
            raise ValueError(f"Manifest/component assignment mismatch for {cid}")
        if any(r["partition"] in PARTITIONS for r in rows) and assignment["cohort"] != "primary_destination_cohort":
            raise ValueError(f"Non-primary component entered train/validation/test: {cid}")

    keys_by_partition: dict[str, set[str]] = {p: set() for p in PARTITIONS}
    key_parts: dict[str, set[str]] = defaultdict(set)
    record_keys: dict[int, set[str]] = defaultdict(set)
    with DOMAIN_EDGES.open("r", encoding="utf-8", newline="") as stream:
        for edge in csv.DictReader(stream):
            index = int(edge["source_record_index"])
            row = manifest_by_index[index]
            if edge["source_record_id"] != row["source_record_id"] or int(edge["label_original"]) != row["label"]:
                raise ValueError(f"Domain edge source join mismatch at index {index}")
            key = edge["domain_grouping_key"]
            record_keys[index].add(key)
            if key.startswith(("registrable:", "ip:")) and row["partition"] in PARTITIONS:
                keys_by_partition[row["partition"]].add(key)
                key_parts[key].add(row["partition"])
    for index, row in manifest_by_index.items():
        keys = record_keys.get(index, set())
        has_domain = any(k.startswith("registrable:") for k in keys)
        has_ip = any(k.startswith("ip:") for k in keys)
        if row["has_confident_destination_key"] != bool(keys) or row["has_domain_key"] != has_domain or row["has_ip_key"] != has_ip:
            raise ValueError(f"Manifest destination-key flags do not match V2 edge lineage at index {index}")
        component = component_by_id[row["component_id"]]
        expected_domain_eval = bool(row["partition"] in PARTITIONS and row["model_eligible"] and keys
                                     and component["cohort"] == "primary_destination_cohort")
        if row["domain_evaluation_eligible"] != expected_domain_eval:
            raise ValueError(f"Manifest domain_evaluation_eligible does not match key/component lineage at index {index}")
    cross_keys = {k: parts for k, parts in key_parts.items() if len(parts) > 1}
    if cross_keys:
        raise ValueError(f"Destination keys cross train/validation/test: {len(cross_keys)}")

    # Match every source index and original label, and verify text-group hashes.
    selected: dict[int, dict[str, Any]] = {}
    source_labels: Counter[int] = Counter()
    raw_count = 0
    for index, raw in enumerate(iter_json_array(SOURCE), start=1):
        raw_count += 1
        row = manifest_by_index.get(index)
        if row is None:
            raise ValueError(f"Raw source index is missing from split manifest: {index}")
        if set(raw) != {"label", "text"} or not isinstance(raw["text"], str) or raw["label"] not in (0, 1):
            raise ValueError(f"Unexpected raw record schema/type at index {index}")
        label = int(raw["label"])
        source_labels[label] += 1
        if row["label"] != label:
            raise ValueError(f"Original label differs from split at index {index}")
        normalized_group_text = baseline.normalize_for_group(raw["text"])
        norm_hash = baseline.sha256_text(normalized_group_text) if normalized_group_text else ""
        if row["normalized_text_group_id"] != norm_hash:
            raise ValueError(f"Normalized-text group ID does not match source text at index {index}")
        model_eligible = bool(normalize_for_model(raw["text"]))
        if row["model_eligible"] != model_eligible:
            raise ValueError(f"Model eligibility does not match source text at index {index}")
        if row["partition"] in PARTITIONS and model_eligible:
            selected[index] = {"text": raw["text"], "label": label, "normalized_hash": norm_hash}
    if raw_count != 77677 or dict(sorted((str(k), v) for k, v in source_labels.items())) != read_json(SPLIT_SUMMARY)["source_label_counts"]:
        raise ValueError("Raw source count/label inventory differs from the verified split summary")

    # One deterministic representative per normalized-text group in each
    # partition, matching the existing baseline's representative policy.
    group_members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, source in selected.items():
        row = manifest_by_index[index]
        group_members[row["normalized_text_group_id"]].append({**row, **source})
    groups_by_partition: dict[str, list[dict[str, Any]]] = {p: [] for p in PARTITIONS}
    for norm_id, members in group_members.items():
        labels = {m["label"] for m in members}
        parts = {m["partition"] for m in members}
        domain_flags = {m["domain_evaluation_eligible"] for m in members}
        if len(labels) != 1 or len(parts) != 1 or len(domain_flags) != 1:
            raise ValueError(f"Normalized text group has inconsistent labels, partitions, or domain eligibility: {norm_id}")
        representative = min(members, key=lambda m: m["source_record_index"])
        groups_by_partition[representative["partition"]].append({
            "source_record_id": representative["source_record_id"],
            "source_record_index": representative["source_record_index"],
            "component_id": representative["component_id"],
            "normalized_text_group_id": norm_id,
            "label": representative["label"],
            "domain_evaluation_eligible": representative["domain_evaluation_eligible"],
            "text": representative["text"],
            "source_record_count_in_group": len(members),
        })
    for part in PARTITIONS:
        groups_by_partition[part].sort(key=lambda g: g["source_record_index"])
        if not groups_by_partition[part]:
            raise ValueError(f"No normalized-text representatives for {part}")
        if len({g["label"] for g in groups_by_partition[part]}) != 2:
            raise ValueError(f"Partition {part} does not contain both source classes")

    return groups_by_partition, {
        "source_records": raw_count,
        "source_label_counts": {str(k): v for k, v in sorted(source_labels.items())},
        "model_partition_records": {p: sum(1 for r in manifest_by_index.values() if r["partition"] == p) for p in PARTITIONS},
        "normalized_text_groups": {p: len(groups_by_partition[p]) for p in PARTITIONS},
        "partition_labels_unique_text": {
            p: {str(label): sum(g["label"] == label for g in groups_by_partition[p]) for label in (0, 1)}
            for p in PARTITIONS
        },
        "domain_evaluation_groups": {
            p: sum(bool(g["domain_evaluation_eligible"]) for g in groups_by_partition[p]) for p in PARTITIONS
        },
        "domainless_secondary_groups": {
            p: sum(not g["domain_evaluation_eligible"] for g in groups_by_partition[p]) for p in PARTITIONS
        },
        "domain_key_counts_by_partition": {p: len(keys_by_partition[p]) for p in PARTITIONS},
        "joined_source_records": len(selected),
        "manifest_records": len(manifest_by_index),
        "split_config_sha256": sha256_file(SPLIT_CONFIG),
        "split_manifest_sha256": sha256_file(MANIFEST),
        "source_sha256": sha256_file(SOURCE),
    }, {"split_config": config, "leakage_invariants": leakage, "split_summary": split_summary}


def _group_by(values: Any, key: str) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in values:
        result[str(row[key])].append(row)
    return result


def make_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            preprocessor=normalize_for_model,
            lowercase=False,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.995,
            sublinear_tf=True,
            max_features=200000,
        )),
        ("classifier", LogisticRegression(
            C=1.0,
            solver="liblinear",
            class_weight=None,
            max_iter=2000,
            random_state=SEED,
        )),
    ])


def calculate_metrics(groups: list[dict[str, Any]], scores: np.ndarray) -> dict[str, Any]:
    y_true = np.asarray([g["label"] for g in groups], dtype=np.int8)
    y_pred = (scores >= THRESHOLD).astype(np.int8)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = map(int, (cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]))
    both_classes = len(set(y_true.tolist())) == 2
    return {
        "records": int(len(groups)),
        "class_counts": {"0": int(np.sum(y_true == 0)), "1": int(np.sum(y_true == 1))},
        "confusion_matrix_labels_0_1": [[tn, fp], [fn, tp]],
        "TN": tn, "FP": fp, "FN": fn, "TP": tp,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "specificity": float(tn / (tn + fp)) if tn + fp else None,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if both_classes else None,
        "average_precision": float(average_precision_score(y_true, scores)) if both_classes else None,
        "undefined_ranking_metric_note": None if both_classes else "ROC-AUC and average precision are undefined for a one-class subset.",
    }


def predictions(groups: list[dict[str, Any]], scores: np.ndarray) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for group, score in zip(groups, scores.tolist()):
        output.append({
            "source_record_id": group["source_record_id"],
            "source_record_index": group["source_record_index"],
            "component_id": group["component_id"],
            "normalized_text_group_id": group["normalized_text_group_id"],
            "source_record_count_in_group": group["source_record_count_in_group"],
            "evaluation_scope": "primary_domain" if group["domain_evaluation_eligible"] else "secondary_no_confident_destination",
            "domain_evaluation_eligible": group["domain_evaluation_eligible"],
            "label_original": group["label"],
            "prediction": int(score >= THRESHOLD),
            "score_phishing_class_uncalibrated": float(score),
            "threshold": THRESHOLD,
        })
    return output


def csv_write(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = list(rows[0]) if rows else ["source_record_id", "source_record_index"]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def evaluate_slices(groups: list[dict[str, Any]], scores: np.ndarray) -> dict[str, Any]:
    scopes = {
        "all_model_eligible_unique_texts": list(range(len(groups))),
        "primary_domain_evaluation": [i for i, g in enumerate(groups) if g["domain_evaluation_eligible"]],
        "secondary_no_confident_destination": [i for i, g in enumerate(groups) if not g["domain_evaluation_eligible"]],
    }
    return {
        name: calculate_metrics([groups[i] for i in indices], scores[indices]) if indices else None
        for name, indices in scopes.items()
    }


def write_classification_reports(path: Path, validation: list[dict[str, Any]], validation_scores: np.ndarray,
                                 test: list[dict[str, Any]], test_scores: np.ndarray) -> None:
    chunks: list[str] = []
    for name, groups, scores in (
        ("Validation: all model-eligible unique texts", validation, validation_scores),
        ("Validation: primary destination cohort", [g for g in validation if g["domain_evaluation_eligible"]], validation_scores[[i for i, g in enumerate(validation) if g["domain_evaluation_eligible"]]]),
        ("Validation: secondary non-destination records", [g for g in validation if not g["domain_evaluation_eligible"]], validation_scores[[i for i, g in enumerate(validation) if not g["domain_evaluation_eligible"]]]),
        ("Test: primary domain-evaluation records", [g for g in test if g["domain_evaluation_eligible"]], test_scores[[i for i, g in enumerate(test) if g["domain_evaluation_eligible"]]]),
        ("Test: secondary model-eligible records without confident destination keys", [g for g in test if not g["domain_evaluation_eligible"]], test_scores[[i for i, g in enumerate(test) if not g["domain_evaluation_eligible"]]]),
    ):
        chunks.append(f"## {name}\n")
        if groups:
            y = [g["label"] for g in groups]
            pred = [int(score >= THRESHOLD) for score in scores]
            chunks.append(classification_report(y, pred, labels=[0, 1], target_names=["benign_source_label_0", "phishing_source_label_1"], zero_division=0))
            chunks.append("\n")
        else:
            chunks.append("No examples in this subset.\n")
    path.write_text("\n".join(chunks), encoding="utf-8")


def write_outputs(model: Pipeline, groups: dict[str, list[dict[str, Any]]], scores: dict[str, np.ndarray],
                  metrics_report: dict[str, Any], preflight: dict[str, Any]) -> dict[str, int]:
    if OUTPUT.exists():
        raise FileExistsError(f"Refusing to overwrite existing experiment output directory: {OUTPUT}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".phishing_domain_holdout_v2_", dir=OUTPUT.parent))
    try:
        joblib.dump(model, stage / "model.joblib")
        loaded = joblib.load(stage / "model.joblib")
        validation_check = loaded.predict_proba([g["text"] for g in groups["validation"]])[:, 1]
        test_check = loaded.predict_proba([g["text"] for g in groups["test"]])[:, 1]
        if not np.array_equal(validation_check, scores["validation"]):
            raise RuntimeError("Reloaded model validation predictions are not exactly reproducible")
        if not np.array_equal(test_check, scores["test"]):
            raise RuntimeError("Reloaded model test predictions are not exactly reproducible")
        metrics_report["model_reload_verification"] = {
            "passed": True,
            "validation_scores_exactly_equal": True,
            "test_scores_exactly_equal": True,
            "model_classes": [int(x) for x in loaded.classes_],
            "model_feature_count": int(len(loaded.named_steps["tfidf"].vocabulary_)),
        }
        metrics_report["outputs"] = {
            "model": "model.joblib", "metrics": "metrics.json", "config": "experiment_config.json",
            "classification_report": "classification_report.txt", "test_predictions": "test_predictions.csv",
            "validation_predictions": "validation_predictions.csv", "training_summary": "training_summary.md",
        }
        (stage / "metrics.json").write_text(json.dumps(metrics_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        config = metrics_report["experiment_config"]
        (stage / "experiment_config.json").write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        test_rows = predictions(groups["test"], scores["test"])
        validation_rows = predictions(groups["validation"], scores["validation"])
        csv_write(stage / "test_predictions.csv", test_rows)
        csv_write(stage / "validation_predictions.csv", validation_rows)
        write_classification_reports(stage / "classification_report.txt", groups["validation"], scores["validation"], groups["test"], scores["test"])
        summary = metrics_report["summary"]
        primary = metrics_report["test_metrics"]["primary_domain_evaluation"]
        secondary = metrics_report["test_metrics"]["secondary_no_confident_destination"]
        report = [
            "# Phishing Classifier V2 — domain-held-out experiment", "",
            "This is a within-dataset, domain-grouped evaluation. It is not an independent real-world validation and does not establish general accuracy.", "",
            f"- Python {platform.python_version()}, scikit-learn {sklearn.__version__}; seed {SEED}; threshold {THRESHOLD}.",
            f"- Source rows joined and checked: {preflight['source_records']:,}; model-eligible split rows: {preflight['joined_source_records']:,}.",
            f"- Unique normalized-text representatives: train {summary['training_unique_text_groups']:,}, validation {summary['validation_unique_text_groups']:,}, test {summary['test_unique_text_groups']:,}.",
            f"- Training used only {summary['training_unique_text_groups']:,} training representatives; TF-IDF was fit within the pipeline on those texts only.",
            "- The original source labels were preserved (0=benign according to source, 1=phishing according to source).",
            "- No model or score tuning used validation or test data; threshold 0.5 was fixed before evaluation.",
            f"- Saved-model reload and exact prediction reproduction: {metrics_report['model_reload_verification']['passed']}.", "",
            "## Test: primary unseen-domain cohort", "",
            f"- Unique normalized-text examples: {primary['records']:,}; records with confident destination keys in the split manifest: {summary['test_domain_evaluation_records']:,}.",
            f"- Confusion matrix [[TN, FP], [FN, TP]]: {primary['confusion_matrix_labels_0_1']}.",
            f"- Precision {primary['precision']:.6f}; recall {primary['recall']:.6f}; F1 {primary['f1']:.6f}; specificity {primary['specificity']:.6f}; accuracy {primary['accuracy']:.6f}; ROC-AUC {primary['roc_auc']:.6f}; average precision {primary['average_precision']:.6f}.", "",
            "## Test: secondary model-eligible examples without a confident destination key", "",
            f"- Unique normalized-text examples: {secondary['records'] if secondary else 0}.",
        ]
        if secondary:
            report.append(f"- Confusion matrix [[TN, FP], [FN, TP]]: {secondary['confusion_matrix_labels_0_1']}.")
            report.append(f"- Precision {secondary['precision']}; recall {secondary['recall']}; F1 {secondary['f1']}; specificity {secondary['specificity']}; accuracy {secondary['accuracy']}; ROC-AUC {secondary['roc_auc']}; average precision {secondary['average_precision']}.")
        else:
            report.append("- No secondary test examples were present.")
        report += ["", "## Validation", "", "Validation metrics are reported in metrics.json and the classification report. Validation did not alter the fixed 0.5 threshold or model configuration.", "",
                   "## Limitations", "", "- The source labels have not been independently validated.",
                   "- The primary destination-bearing cohort is a selected subset of the source; records with no confident destination or hard unresolved candidates are not counted as unseen-domain test examples.",
                   "- The test partition is from the same dataset whose prior baseline results were inspected during development.",
                   "- Logistic Regression scores are model outputs and are not demonstrated to be calibrated probabilities.",
                   "- No FastAPI integration, real-world accuracy claim, or detector change is part of this experiment.", ""]
        (stage / "training_summary.md").write_text("\n".join(report), encoding="utf-8")
        if OUTPUT.exists():
            raise FileExistsError(f"Refusing to overwrite existing experiment output directory: {OUTPUT}")
        stage.rename(OUTPUT)
    except Exception:
        if stage.exists():
            shutil.rmtree(stage)
        raise
    return {p.name: p.stat().st_size for p in OUTPUT.iterdir() if p.is_file()}


def run() -> None:
    groups, preflight, split_info = validate_inputs()
    train_groups = groups["train"]
    y_train = [g["label"] for g in train_groups]
    if len(set(y_train)) != 2:
        raise ValueError("Training representatives do not contain both original labels")
    model = make_pipeline()
    model.fit([g["text"] for g in train_groups], y_train)

    # Validation is evaluated first; no threshold or hyperparameter tuning is
    # performed. The test set is never consulted during fitting or selection.
    scores = {
        p: model.predict_proba([g["text"] for g in groups[p]])[:, 1].astype(float)
        for p in ("validation", "test")
    }
    val_metrics = evaluate_slices(groups["validation"], scores["validation"])
    test_metrics = evaluate_slices(groups["test"], scores["test"])
    if not test_metrics["primary_domain_evaluation"]:
        raise ValueError("The primary domain-held-out test cohort is empty")
    train_label_counts = {str(lab): sum(g["label"] == lab for g in train_groups) for lab in (0, 1)}
    summary = {
        "training_partition_manifest_records": preflight["model_partition_records"]["train"],
        "validation_partition_manifest_records": preflight["model_partition_records"]["validation"],
        "test_partition_manifest_records": preflight["model_partition_records"]["test"],
        "training_unique_text_groups": len(groups["train"]),
        "validation_unique_text_groups": len(groups["validation"]),
        "test_unique_text_groups": len(groups["test"]),
        "training_label_counts_after_representative_selection": train_label_counts,
        "validation_domain_evaluation_groups": preflight["domain_evaluation_groups"]["validation"],
        "validation_secondary_groups": preflight["domainless_secondary_groups"]["validation"],
        "test_domain_evaluation_records": preflight["domain_evaluation_groups"]["test"],
        "test_secondary_model_eligible_records": preflight["domainless_secondary_groups"]["test"],
        "source_records_joined": preflight["source_records"],
        "model_eligible_partition_records_joined": preflight["joined_source_records"],
        "partition_record_counts": preflight["model_partition_records"],
        "partition_unique_text_counts": preflight["normalized_text_groups"],
        "partition_unique_text_label_counts": preflight["partition_labels_unique_text"],
        "domain_group_key_counts": preflight["domain_key_counts_by_partition"],
        "representative_policy": "Minimum source_record_index within each normalized_text_group_id; one representative per normalized-text group in each partition.",
    }
    model_config = {
        "pipeline": ["TfidfVectorizer", "LogisticRegression"],
        "vectorizer": {
            "analyzer": "word", "ngram_range": [1, 2], "min_df": 2, "max_df": 0.995,
            "max_features": 200000, "sublinear_tf": True,
            "preprocessing": "Unicode NFKC, lowercase, collapsed whitespace via backend.ml.text_normalization.normalize_for_model",
            "lowercase": False,
            "fit_data": "training partition normalized-text representatives only",
        },
        "logistic_regression": {"C": 1.0, "solver": "liblinear", "class_weight": None,
                                "max_iter": 2000, "random_state": SEED},
        "model_input_fields": ["raw source text only"],
    }
    experiment_config = {
        "experiment": "Phishing Classifier V2: domain-held-out TF-IDF + Logistic Regression",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "interpretation": "Within-dataset domain-held-out evaluation; not independent real-world validation.",
        "target": {"field": "label", "0": "benign according to source", "1": "phishing according to source", "positive_label": 1},
        "classification_threshold": THRESHOLD,
        "threshold_selection": "Fixed at 0.5; no threshold tuning performed.",
        "random_seed": SEED,
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                     "scipy": scipy.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
        "source": {"path": str(SOURCE.relative_to(ROOT)), "sha256": preflight["source_sha256"],
                   "record_count": preflight["source_records"], "label_counts": preflight["source_label_counts"]},
        "split": {"path": str(SPLIT_DIR.relative_to(ROOT)),
                  "manifest_sha256": preflight["split_manifest_sha256"],
                  "config_sha256": preflight["split_config_sha256"],
                  "policy": split_info["split_config"]["primary_policy"],
                  "leakage_invariants_sha256": sha256_file(LEAKAGE),
                  "leakage_invariants_passed": True,
                  "target_proportions": split_info["split_config"]["target_proportions"],
                  "row_level_splitting": False},
        "grouping": {"normalized_text": "Existing baseline NFKC/casefold/whitespace-collapse SHA-256 ID from split manifest",
                     "near_duplicate_and_domain_grouping": "Existing verified Scenario A/D split; no grouping rules modified",
                     "representative_per_normalized_text_group": True},
        "model_configuration": model_config,
        "summary": summary,
        "outputs": {"model": "model.joblib", "metrics": "metrics.json", "config": "experiment_config.json",
                    "classification_report": "classification_report.txt", "test_predictions": "test_predictions.csv",
                    "validation_predictions": "validation_predictions.csv", "training_summary": "training_summary.md"},
    }
    metrics_report = {
        "experiment": experiment_config["experiment"],
        "created_utc": experiment_config["created_utc"],
        "interpretation": experiment_config["interpretation"],
        "classification_threshold": THRESHOLD,
        "threshold_selection": experiment_config["threshold_selection"],
        "versions": experiment_config["versions"],
        "summary": summary,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "metric_unit": "one representative per normalized-text group",
        "score_kind": "uncalibrated logistic-regression model score from predict_proba; calibration was not assessed",
        "experiment_config": experiment_config,
        "validation_reproducibility": "checked against reloaded joblib pipeline before publishing outputs",
    }
    artifacts = write_outputs(model, groups, scores, metrics_report, preflight)
    print(json.dumps({"output_directory": str(OUTPUT.relative_to(ROOT)), "artifact_sizes_bytes": artifacts,
                      "summary": summary, "validation_metrics": val_metrics, "test_metrics": test_metrics,
                      "model_reload_verification": metrics_report["model_reload_verification"]},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run()
