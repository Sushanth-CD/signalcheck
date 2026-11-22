"""Train the phishing-only TF-IDF + Logistic Regression baseline.

From the repository root, using the active backend environment:
    python backend/ml/train_text_baseline.py

The script does not alter source data, open URLs, relabel records, use the
Hinglish data, or tune on the test partition.
"""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import scipy
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from backend.ml.text_normalization import normalize_for_model

INPUT = ROOT / "backend" / "data" / "processed" / "phishing_text_candidates.jsonl"
OUTPUT_DIR = ROOT / "backend" / "reports" / "ml" / "text_phishing_baseline"
MODEL_PATH = ROOT / "backend" / "models" / "text" / "phishing_tfidf_logreg.joblib"
SEED = 20261026
THRESHOLD = 0.5
PROMO_REASON = "possible_promotional_or_non_phishing_spam_review"
SHINGLE_SIZE = 5
SIMHASH_RADIUS = 3
JACCARD_MIN = 0.90


def normalize_for_group(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"\s+", " ", value).strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_records(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    schema: set[str] | None = None
    labels: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    input_types: Counter[str] = Counter()
    sources: set[str] = set()
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            keys = set(record)
            if schema is None:
                schema = keys
            elif keys != schema:
                raise ValueError(f"Inconsistent JSONL schema at line {line_no}")
            text = record.get("text")
            label = str(record.get("label_original"))
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"Empty text at JSONL line {line_no}")
            if label not in {"0", "1"}:
                raise ValueError(f"Invalid original label at line {line_no}: {label!r}")
            if not isinstance(record.get("review_required"), bool):
                raise ValueError(f"Invalid review_required at JSONL line {line_no}")
            record["_line_no"] = line_no
            record["_label"] = int(label)
            record["_normalized"] = normalize_for_group(text)
            record["_normalized_hash"] = sha256_text(record["_normalized"])
            record["_promo"] = PROMO_REASON in record.get("review_reason", [])
            records.append(record)
            labels[label] += 1
            sources.add(str(record.get("source_dataset")))
            input_types[str(record.get("inferred_input_type", "unknown"))] += 1
            reasons.update(map(str, record.get("review_reason", [])))
    if sources != {"combined_reduced.json"}:
        raise ValueError(f"Unexpected source_dataset values: {sorted(sources)}")
    if not records:
        raise ValueError("The phishing candidate file is empty")
    return records, {
        "candidate_records": len(records),
        "schema_fields": sorted(schema or []),
        "label_counts": {str(k): int(v) for k, v in sorted(labels.items())},
        "review_reason_counts": dict(reasons),
        "input_type_counts": dict(input_types),
        "source_dataset_values": sorted(sources),
    }


class DisjointSet:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a == b:
            return
        if self.rank[a] < self.rank[b]:
            a, b = b, a
        self.parent[b] = a
        if self.rank[a] == self.rank[b]:
            self.rank[a] += 1


class BKTree:
    """Hamming-distance index for deterministic 64-bit SimHash values."""

    @staticmethod
    def distance(a: int, b: int) -> int:
        return (a ^ b).bit_count()

    def __init__(self) -> None:
        self.root: list[Any] | None = None

    def add(self, fingerprint: int, index: int) -> None:
        if self.root is None:
            self.root = [fingerprint, [index], {}]
            return
        node = self.root
        while True:
            distance = self.distance(fingerprint, node[0])
            if distance == 0:
                node[1].append(index)
                return
            child = node[2].get(distance)
            if child is None:
                node[2][distance] = [fingerprint, [index], {}]
                return
            node = child

    def query(self, fingerprint: int, radius: int) -> Iterable[int]:
        if self.root is None:
            return
        pending = [self.root]
        while pending:
            node = pending.pop()
            distance = self.distance(fingerprint, node[0])
            if distance <= radius:
                yield from node[1]
            low, high = distance - radius, distance + radius
            pending.extend(child for edge, child in node[2].items() if low <= edge <= high)


def shingles(text: str) -> set[str]:
    if len(text) < SHINGLE_SIZE:
        return {text} if text else set()
    return {text[i : i + SHINGLE_SIZE] for i in range(len(text) - SHINGLE_SIZE + 1)}


def simhash64(text: str) -> int:
    grams = shingles(text)
    if not grams:
        return 0
    votes = [0] * 64
    for gram in grams:
        value = int.from_bytes(hashlib.sha256(gram.encode("utf-8")).digest()[:8], "big")
        for bit in range(64):
            votes[bit] += 1 if (value >> bit) & 1 else -1
    result = 0
    for bit, vote in enumerate(votes):
        if vote >= 0:
            result |= 1 << bit
    return result


def jaccard_match(left: str, right: str) -> bool:
    a, b = shingles(left), shingles(right)
    if not a or not b:
        return a == b and left == right
    if min(len(a), len(b)) / max(len(a), len(b)) < JACCARD_MIN:
        return False
    intersection = len(a & b)
    return intersection / (len(a) + len(b) - intersection) >= JACCARD_MIN


def create_groups(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_normalized: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record["_normalized_hash"]
        group = by_normalized.setdefault(
            key,
            {
                "normalized_hash": key,
                "normalized_text": record["_normalized"],
                "records": [],
                "labels": set(),
                "has_promo": False,
            },
        )
        group["records"].append(record)
        group["labels"].add(record["_label"])
        group["has_promo"] |= record["_promo"]
    groups = list(by_normalized.values())
    dsu = DisjointSet(len(groups))
    index = BKTree()
    near_pairs = 0
    for current, group in enumerate(groups):
        fingerprint = simhash64(group["normalized_text"])
        text = group["normalized_text"]
        for prior in index.query(fingerprint, SIMHASH_RADIUS):
            if jaccard_match(text, groups[prior]["normalized_text"]):
                dsu.union(current, prior)
                near_pairs += 1
        index.add(fingerprint, current)

    components: dict[int, list[int]] = defaultdict(list)
    for i in range(len(groups)):
        components[dsu.find(i)].append(i)
    component_by_index: dict[int, str] = {}
    component_info: dict[str, dict[str, Any]] = {}
    for members in components.values():
        component_id = sha256_text("\n".join(sorted(groups[i]["normalized_hash"] for i in members)))
        all_labels = {label for i in members for label in groups[i]["labels"]}
        reasons: list[str] = []
        if any(groups[i]["has_promo"] for i in members):
            reasons.append("promotional_review_flag_in_near_duplicate_component")
        if any(len(groups[i]["labels"]) > 1 for i in members):
            reasons.append("normalized_text_has_conflicting_original_labels")
        if len(all_labels) > 1:
            reasons.append("near_duplicate_component_has_conflicting_original_labels")
        component_info[component_id] = {
            "members": members,
            "labels": all_labels,
            "reasons": reasons,
            "size": len(members),
        }
        for i in members:
            component_by_index[i] = component_id
    for i, group in enumerate(groups):
        component_id = component_by_index[i]
        info = component_info[component_id]
        group["component_id"] = component_id
        group["quarantine_reasons"] = info["reasons"]
        group["component_size"] = info["size"]
        group["source_record_count"] = len(group["records"])
        group["label"] = next(iter(group["labels"])) if len(group["labels"]) == 1 else None
        group["representative"] = min(group["records"], key=lambda r: r["_line_no"])
    return groups, {
        "normalized_text_groups": len(groups),
        "near_duplicate_pairs_joined": near_pairs,
        "near_duplicate_components": len(components),
        "quarantined_components": sum(bool(x["reasons"]) for x in component_info.values()),
        "near_duplicate_method": {
            "normalization": "Unicode NFKC, casefold, collapsed whitespace",
            "shingles": f"unique character {SHINGLE_SIZE}-grams",
            "simhash": "first 64 bits of SHA-256 per shingle",
            "maximum_simhash_hamming_distance": SIMHASH_RADIUS,
            "minimum_character_shingle_jaccard": JACCARD_MIN,
            "connected_component_id": "SHA-256 of sorted normalized-text hashes",
        },
    }


def label_counts(values: Iterable[int]) -> dict[str, int]:
    counts = Counter(map(int, values))
    return {"0": int(counts.get(0, 0)), "1": int(counts.get(1, 0))}


def metrics(y_true: list[int], y_pred: list[int], p1: list[float]) -> dict[str, Any]:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = map(int, (matrix[0, 0], matrix[0, 1], matrix[1, 0], matrix[1, 1]))
    two_classes = len(set(y_true)) == 2
    return {
        "records": len(y_true),
        "class_counts": label_counts(y_true),
        "confusion_matrix_labels_0_1": [[tn, fp], [fn, tp]],
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)) if y_true else None,
        "recall": float(recall_score(y_true, y_pred, zero_division=0)) if y_true else None,
        "f1": float(f1_score(y_true, y_pred, zero_division=0)) if y_true else None,
        "specificity": float(tn / (tn + fp)) if tn + fp else None,
        "accuracy": float(accuracy_score(y_true, y_pred)) if y_true else None,
        "roc_auc": float(roc_auc_score(y_true, p1)) if two_classes else None,
        "roc_auc_note": None if two_classes else "Undefined: this subset has only one class.",
    }


def write_csv(path: Path, header: list[str], rows: Iterable[list[Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> int:
    if not INPUT.is_file():
        raise FileNotFoundError(f"Candidate input does not exist: {INPUT}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    records, source_summary = load_records(INPUT)
    groups, group_summary = create_groups(records)

    eligible = [g for g in groups if not g["quarantine_reasons"]]
    quarantined = [g for g in groups if g["quarantine_reasons"]]
    if len({g["label"] for g in eligible}) != 2 or len(eligible) < 20:
        raise ValueError("Eligible primary groups do not support the planned 20-fold split")

    y = np.asarray([int(g["label"]) for g in eligible], dtype=np.int8)
    group_ids = np.asarray([g["component_id"] for g in eligible], dtype=object)
    folds = np.full(len(eligible), -1, dtype=np.int8)
    splitter = StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=SEED)
    dummy = np.zeros((len(eligible), 1), dtype=np.uint8)
    for fold, (_, test_index) in enumerate(splitter.split(dummy, y, group_ids)):
        folds[test_index] = fold
    if (folds < 0).any():
        raise RuntimeError("Some groups were not assigned a split fold")
    split_names: dict[str, str] = {}
    for i, group in enumerate(eligible):
        fold = int(folds[i])
        part = "test" if fold < 3 else "validation" if fold < 6 else "train"
        group["fold"] = fold
        group["partition"] = part
        previous = split_names.setdefault(group["component_id"], part)
        if previous != part:
            raise RuntimeError("A near-duplicate component crossed split boundaries")
    for group in quarantined:
        group["fold"] = None
        group["partition"] = "quarantine"

    normalized_by_part = {p: set() for p in ("train", "validation", "test")}
    components_by_part = {p: set() for p in ("train", "validation", "test")}
    for group in eligible:
        normalized_by_part[group["partition"]].add(group["normalized_hash"])
        components_by_part[group["partition"]].add(group["component_id"])
    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if normalized_by_part[a] & normalized_by_part[b]:
            raise RuntimeError(f"Normalized-text overlap between {a} and {b}")
        if components_by_part[a] & components_by_part[b]:
            raise RuntimeError(f"Near-duplicate group overlap between {a} and {b}")
    quarantine_hashes = {g["normalized_hash"] for g in quarantined}
    if any(quarantine_hashes & hashes for hashes in normalized_by_part.values()):
        raise RuntimeError("Quarantined text overlaps a primary split")

    manifest_rows = []
    for group in groups:
        for record in group["records"]:
            manifest_rows.append(
                [
                    record.get("source_record_index", record["_line_no"]),
                    record["_label"],
                    record.get("inferred_input_type", "unknown"),
                    record["_normalized_hash"],
                    group["component_id"],
                    group["partition"],
                    group["fold"],
                    record["_promo"],
                    ";".join(group["quarantine_reasons"]),
                    group["source_record_count"],
                ]
            )
    manifest_rows.sort(key=lambda r: int(r[0]))
    manifest_path = OUTPUT_DIR / "split_manifest.csv"
    write_csv(
        manifest_path,
        ["source_record_index", "label_original", "inferred_input_type", "normalized_text_sha256",
         "near_duplicate_component_id", "partition", "stratified_fold", "promotional_review_flag",
         "quarantine_reason", "normalized_group_record_count"],
        manifest_rows,
    )

    partitions = {p: [g for g in eligible if g["partition"] == p] for p in ("train", "validation", "test")}
    model = Pipeline(
        [
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
        ]
    )
    train_text = [g["representative"]["text"] for g in partitions["train"]]
    train_y = [int(g["label"]) for g in partitions["train"]]
    model.fit(train_text, train_y)

    def score_partition(part: str) -> tuple[dict[str, Any], list[int], list[float]]:
        selected = partitions[part]
        texts = [g["representative"]["text"] for g in selected]
        actual = [int(g["label"]) for g in selected]
        probabilities = model.predict_proba(texts)[:, 1].astype(float).tolist()
        predicted = [int(p >= THRESHOLD) for p in probabilities]
        return metrics(actual, predicted, probabilities), predicted, probabilities

    validation_metrics, _, _ = score_partition("validation")
    test_metrics, test_pred, test_prob = score_partition("test")
    test_groups = partitions["test"]
    prediction_rows = []
    error_rows = []
    error_records = []
    by_type: dict[str, dict[str, list[Any]]] = defaultdict(lambda: {"y": [], "pred": [], "p1": []})
    for group, pred, probability in zip(test_groups, test_pred, test_prob):
        record = group["representative"]
        actual = int(group["label"])
        kind = str(record.get("inferred_input_type", "unknown"))
        prediction_rows.append([record.get("source_record_index", record["_line_no"]), group["component_id"], kind, actual, pred, probability])
        by_type[kind]["y"].append(actual)
        by_type[kind]["pred"].append(pred)
        by_type[kind]["p1"].append(probability)
        if actual != pred:
            error = {
                "source_record_index": record.get("source_record_index", record["_line_no"]),
                "near_duplicate_component_id": group["component_id"],
                "inferred_input_type": kind,
                "label_original": actual,
                "prediction": pred,
                "probability_phishing": probability,
                "error": "false_positive" if pred == 1 else "false_negative",
                "text": record["text"],
            }
            error_records.append(error)
            error_rows.append([error[k] for k in ("source_record_index", "near_duplicate_component_id", "inferred_input_type", "label_original", "prediction", "probability_phishing", "error", "text")])
    by_type_metrics = {
        kind: metrics(values["y"], values["pred"], values["p1"])
        for kind, values in sorted(by_type.items())
    }
    write_csv(OUTPUT_DIR / "test_predictions.csv",
              ["source_record_index", "near_duplicate_component_id", "inferred_input_type", "label_original", "prediction", "probability_phishing"],
              prediction_rows)
    write_csv(OUTPUT_DIR / "test_error_analysis.csv",
              ["source_record_index", "near_duplicate_component_id", "inferred_input_type", "label_original", "prediction", "probability_phishing", "error", "text"],
              error_rows)

    promo_records = [r for r in records if r["_promo"]]
    quarantine_prob: dict[str, float] = {}
    if quarantined:
        q_texts = [g["representative"]["text"] for g in quarantined]
        q_prob = model.predict_proba(q_texts)[:, 1].astype(float).tolist()
        quarantine_prob = {g["normalized_hash"]: p for g, p in zip(quarantined, q_prob)}
    promo_y = [r["_label"] for r in promo_records]
    promo_prob = [quarantine_prob[r["_normalized_hash"]] for r in promo_records]
    promo_pred = [int(p >= THRESHOLD) for p in promo_prob]
    promo_unadjudicated = metrics(promo_y, promo_pred, promo_prob) if promo_y else None
    quarantine_rows = []
    for record in sorted((r for g in quarantined for r in g["records"]),
                         key=lambda r: int(r.get("source_record_index", r["_line_no"]))):
        probability = quarantine_prob[record["_normalized_hash"]]
        component = next(g for g in quarantined if g["normalized_hash"] == record["_normalized_hash"])
        quarantine_rows.append([
            record.get("source_record_index", record["_line_no"]), record["_label"], int(probability >= THRESHOLD),
            probability, record["_promo"], ";".join(record.get("review_reason", [])),
            ";".join(component["quarantine_reasons"]),
        ])
    write_csv(OUTPUT_DIR / "quarantine_predictions.csv",
              ["source_record_index", "label_original_unadjudicated", "prediction", "probability_phishing",
               "explicit_promotional_review_flag", "source_review_reason", "quarantine_reason"],
              quarantine_rows)

    primary_test_hashes = {g["normalized_hash"] for g in test_groups}
    promo_hashes = {r["_normalized_hash"] for r in promo_records}
    if primary_test_hashes & promo_hashes:
        raise RuntimeError("Promotional text overlaps primary test data")
    primary_components = {g["component_id"] for g in eligible}
    if primary_components & {g["component_id"] for g in quarantined}:
        raise RuntimeError("Quarantined near-duplicate component overlaps primary data")

    split_record_counts = {
        p: sum(g["source_record_count"] for g in groups if g["partition"] == p)
        for p in ("train", "validation", "test", "quarantine")
    }
    split_group_counts = {p: len(partitions[p]) for p in ("train", "validation", "test")}
    split_labels = {p: label_counts(int(g["label"]) for g in partitions[p]) for p in partitions}
    explicit_promo_count = len(promo_records)
    extra_quarantine_count = sum(len(g["records"]) for g in quarantined) - explicit_promo_count
    metrics_report: dict[str, Any] = {
        "experiment": "Phishing text TF-IDF + Logistic Regression baseline",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "interpretation": "Dataset-source evaluation only; this does not establish real-world accuracy.",
        "target": {"field": "label_original", "0": "benign according to source", "1": "phishing according to source", "positive_label": 1},
        "classification_threshold": THRESHOLD,
        "random_seed": SEED,
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "scipy": scipy.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
        "input": {"path": str(INPUT.relative_to(ROOT)), "sha256": sha256_file(INPUT), **source_summary},
        "model_configuration": {
            "pipeline": ["TfidfVectorizer", "LogisticRegression"],
            "vectorizer": {"analyzer": "word", "ngram_range": [1, 2], "min_df": 2, "max_df": 0.995, "max_features": 200000, "sublinear_tf": True, "preprocessing": "Unicode NFKC, lowercase, collapsed whitespace"},
            "logistic_regression": {"C": 1.0, "solver": "liblinear", "class_weight": None, "max_iter": 2000, "random_state": SEED},
            "model_input_fields": ["text only"],
        },
        "grouping": group_summary,
        "split": {
            "method": "StratifiedGroupKFold",
            "n_splits": 20,
            "shuffle": True,
            "random_state": SEED,
            "folds": {"test": [0, 1, 2], "validation": [3, 4, 5], "train": list(range(6, 20))},
            "target_proportions": {"train": 0.70, "validation": 0.15, "test": 0.15},
            "actual_unique_text_overlap": {"train_validation": 0, "train_test": 0, "validation_test": 0, "quarantine_primary_test": 0},
            "near_duplicate_component_overlap": 0,
        },
        "counts": {
            "candidate_records": len(records),
            "normalized_text_groups": len(groups),
            "eligible_primary_unique_texts": len(eligible),
            "source_records_by_partition": split_record_counts,
            "unique_text_groups_by_partition": split_group_counts,
            "class_counts_by_primary_partition": split_labels,
            "explicit_promotional_quarantined_records": explicit_promo_count,
            "additional_component_quarantined_records": extra_quarantine_count,
            "total_quarantined_records": split_record_counts["quarantine"],
            "quarantined_unique_text_groups": len(quarantined),
        },
        "validation_metrics": validation_metrics,
        "primary_test_metrics": test_metrics,
        "primary_test_metrics_by_inferred_input_type": by_type_metrics,
        "promotional_quarantine": {
            "records_flagged": explicit_promo_count,
            "metrics_vs_original_labels_unadjudicated": promo_unadjudicated,
            "interpretation": "Original label 1 is retained, but labels have not been independently adjudicated; these are source-label agreement results only.",
        },
        "representative_false_positives": [
            {k: e[k] for k in ("source_record_index", "inferred_input_type", "label_original", "prediction", "probability_phishing", "text")}
            for e in [x for x in error_records if x["error"] == "false_positive"][:5]
        ],
        "representative_false_negatives": [
            {k: e[k] for k in ("source_record_index", "inferred_input_type", "label_original", "prediction", "probability_phishing", "text")}
            for e in [x for x in error_records if x["error"] == "false_negative"][:5]
        ],
        "limitations": [
            "Source labels have not been independently validated.",
            "Promotional/spam-like label-1 examples remain unadjudicated.",
            "Inferred input types are heuristics.",
            "Results do not establish real-world detection accuracy.",
        ],
        "outputs": {
            "pipeline": str(MODEL_PATH.relative_to(ROOT)),
            "metrics": str((OUTPUT_DIR / "metrics.json").relative_to(ROOT)),
            "report": str((OUTPUT_DIR / "experiment_report.md").relative_to(ROOT)),
            "split_manifest": str(manifest_path.relative_to(ROOT)),
            "test_predictions": str((OUTPUT_DIR / "test_predictions.csv").relative_to(ROOT)),
            "test_error_analysis": str((OUTPUT_DIR / "test_error_analysis.csv").relative_to(ROOT)),
            "quarantine_predictions": str((OUTPUT_DIR / "quarantine_predictions.csv").relative_to(ROOT)),
        },
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    metrics_path = OUTPUT_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_lines = [
        "# Phishing TF-IDF + Logistic Regression baseline",
        "",
        "Dataset-source evaluation only; this does not establish real-world detection accuracy.",
        "",
        f"- Target: label_original 0=benign, 1=phishing; threshold={THRESHOLD}.",
        f"- Seed={SEED}; Python={platform.python_version()}; scikit-learn={sklearn.__version__}.",
        f"- Eligible primary unique texts={len(eligible):,}; explicitly flagged promotional records={explicit_promo_count:,}; additional propagated quarantine records={extra_quarantine_count:,}.",
        "- Promotional examples retain original label 1. Their labels have not been independently adjudicated; supplementary results below are source-label agreement only.",
        "",
        "## Primary test results",
        "",
        f"- Unique test texts: {test_metrics['records']:,}.",
        f"- Confusion matrix [[TN, FP], [FN, TP]]: {test_metrics['confusion_matrix_labels_0_1']}.",
        f"- TN={test_metrics['TN']}, FP={test_metrics['FP']}, FN={test_metrics['FN']}, TP={test_metrics['TP']}.",
        f"- Precision={test_metrics['precision']:.6f}; recall={test_metrics['recall']:.6f}; F1={test_metrics['f1']:.6f}; specificity={test_metrics['specificity']:.6f}; accuracy={test_metrics['accuracy']:.6f}; ROC-AUC={test_metrics['roc_auc'] if test_metrics['roc_auc'] is not None else 'undefined'}.",
        "",
        "## Split sizes and classes",
        "",
        "| Partition | Unique normalized texts | Source records | Label 0 | Label 1 |",
        "|---|---:|---:|---:|---:|",
    ]
    for part in ("train", "validation", "test"):
        counts = split_labels[part]
        report_lines.append(f"| {part} | {split_group_counts[part]:,} | {split_record_counts[part]:,} | {counts['0']:,} | {counts['1']:,} |")
    report_lines.extend(["", "## Validation and input-type results", "", f"Validation metrics: {json.dumps(validation_metrics, ensure_ascii=False)}", ""])
    for kind, result in sorted(by_type_metrics.items()):
        report_lines.append(
            f"- {kind}: n={result['records']}, classes={result['class_counts']}, confusion={result['confusion_matrix_labels_0_1']}, "
            f"precision={result['precision']}, recall={result['recall']}, F1={result['f1']}, "
            f"specificity={result['specificity']}, accuracy={result['accuracy']}, ROC-AUC={result['roc_auc']}"
        )
    report_lines.extend([
        "",
        "## Promotional quarantine (supplementary; unadjudicated)",
        "",
        f"- Explicit review-flagged records scored: {explicit_promo_count:,}.",
        f"- Confusion matrix and metrics versus unchanged original labels: {json.dumps(promo_unadjudicated, ensure_ascii=False)}",
        "- These records were not used in primary fitting or primary test metrics. Their labels have not been independently adjudicated.",
        "",
        "## Error review",
        "",
        f"- Primary test false positives: {test_metrics['FP']:,}; false negatives: {test_metrics['FN']:,}.",
        f"- All primary test errors are in {OUTPUT_DIR / 'test_error_analysis.csv'}. Representative examples are in metrics.json.",
        "",
        "## Reproduction",
        "",
        f"- Candidate SHA-256: {metrics_report['input']['sha256']}.",
        f"- Saved pipeline: {MODEL_PATH.relative_to(ROOT)}.",
        f"- Split manifest: {manifest_path.relative_to(ROOT)}.",
        "- The test set was not used for tuning. Model features contain text only.",
        "",
    ])
    (OUTPUT_DIR / "experiment_report.md").write_text("\n".join(report_lines), encoding="utf-8")
    print(json.dumps({
        "metrics_path": str(metrics_path.relative_to(ROOT)),
        "report_path": str((OUTPUT_DIR / "experiment_report.md").relative_to(ROOT)),
        "model_path": str(MODEL_PATH.relative_to(ROOT)),
        "primary_test_metrics": test_metrics,
        "counts": metrics_report["counts"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
