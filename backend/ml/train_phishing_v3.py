"""Training and comparative evaluation runner for Phishing Classifier V3.

Trains three model variants strictly on the V2 training representatives:
  1. Content-Only TF-IDF model
  2. URL-Only TF-IDF model
  3. Combined Dual-Channel TF-IDF model

Evaluates all models on the V2 validation partition (and its subgroups:
HTML, short messages, long messages, URL-containing, no URLs).

Strict test-set protection:
The V2 test set is NOT touched or evaluated for model selection.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ijson
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from ml.dual_channel import (
    build_content_only_feature_pipeline,
    build_dual_channel_feature_pipeline,
    build_url_only_feature_pipeline,
    extract_single_content,
    extract_single_urls,
)

MANIFEST_PATH = ROOT / "backend" / "reports" / "ml" / "phishing_domain_extraction_v2" / "domain_holdout_split_v2" / "split_manifest.csv"
SOURCE_JSON = ROOT / "backend" / "data" / "raw" / "combined_reduced.json"
OUT_DIR = ROOT / "backend" / "reports" / "ml" / "phishing_v3_experiments"
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEED = 20261026
LR_CONFIG = {
    "C": 1.0,
    "solver": "liblinear",
    "class_weight": None,
    "max_iter": 2000,
    "random_state": SEED,
}


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray) -> dict[str, Any]:
    """Compute precision, recall, f1, specificity, roc_auc, average_precision, and confusion matrix."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    prec = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    rec = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else None
    acc = accuracy_score(y_true, y_pred)

    try:
        roc = roc_auc_score(y_true, y_score)
    except Exception:
        roc = None

    try:
        ap = average_precision_score(y_true, y_score)
    except Exception:
        ap = None

    return {
        "n": int(len(y_true)),
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "precision": round(float(prec), 6),
        "recall": round(float(rec), 6),
        "f1": round(float(f1), 6),
        "specificity": round(float(spec), 6) if spec is not None else None,
        "accuracy": round(float(acc), 6),
        "roc_auc": round(float(roc), 6) if roc is not None else None,
        "average_precision": round(float(ap), 6) if ap is not None else None,
    }


def main() -> None:
    t0 = time.time()
    print("=== Phishing Classifier V3 Training & Comparative Evaluation ===")
    print(f"Started at {datetime.now(timezone.utc).isoformat()}")

    print("[1/6] Loading split manifest and identifying train/val representatives ...")
    manifest = pd.read_csv(MANIFEST_PATH)
    train_manifest = manifest[manifest["partition"] == "train"]
    val_manifest = manifest[manifest["partition"] == "validation"]

    # Deduplicate by normalized_text_group_id, selecting min source_record_index
    train_reps = train_manifest.sort_values("source_record_index").groupby("normalized_text_group_id").first().reset_index()
    val_reps = val_manifest.sort_values("source_record_index").groupby("normalized_text_group_id").first().reset_index()

    train_indices = set(train_reps["source_record_index"].astype(int))
    val_indices = set(val_reps["source_record_index"].astype(int))
    all_needed_indices = train_indices | val_indices

    print(f"  Train representatives: {len(train_reps):,}")
    print(f"  Validation representatives: {len(val_reps):,}")
    print(f"  Total source texts needed: {len(all_needed_indices):,}")

    print("[2/6] Streaming raw text for needed indices from combined_reduced.json ...")
    source_texts: dict[int, str] = {}
    rec_num = 0
    with open(SOURCE_JSON, "rb") as f:
        for item in ijson.items(f, "item"):
            rec_num += 1
            if rec_num in all_needed_indices:
                source_texts[rec_num] = item.get("text", "")
            if len(source_texts) == len(all_needed_indices):
                break

    print(f"  Loaded {len(source_texts):,} source texts from {rec_num:,} scanned records.")

    # Attach text to DataFrames
    train_reps["raw_text"] = train_reps["source_record_index"].map(source_texts)
    val_reps["raw_text"] = val_reps["source_record_index"].map(source_texts)

    X_train = train_reps["raw_text"].tolist()
    y_train = train_reps["label"].astype(int).values

    X_val = val_reps["raw_text"].tolist()
    y_val = val_reps["label"].astype(int).values

    print(f"  Train label distribution: {dict(pd.Series(y_train).value_counts())}")
    print(f"  Val label distribution:   {dict(pd.Series(y_val).value_counts())}")

    print("[3/6] Defining model variants ...")
    models = {
        "content_only": Pipeline([
            ("features", build_content_only_feature_pipeline()),
            ("classifier", LogisticRegression(**LR_CONFIG)),
        ]),
        "url_only": Pipeline([
            ("features", build_url_only_feature_pipeline()),
            ("classifier", LogisticRegression(**LR_CONFIG)),
        ]),
        "dual_channel_v3": Pipeline([
            ("features", build_dual_channel_feature_pipeline()),
            ("classifier", LogisticRegression(**LR_CONFIG)),
        ]),
    }

    validation_predictions_dict: dict[str, np.ndarray] = {}
    validation_scores_dict: dict[str, np.ndarray] = {}
    metrics_summary: list[dict[str, Any]] = []

    print("[4/6] Training all three models on training partition only ...")
    for name, pipe in models.items():
        print(f"  -> Fitting {name} ...")
        t_start = time.time()
        pipe.fit(X_train, y_train)
        fit_time = time.time() - t_start

        # Validate
        y_val_scores = pipe.predict_proba(X_val)[:, 1]
        y_val_preds = (y_val_scores >= 0.5).astype(int)

        validation_predictions_dict[name] = y_val_preds
        validation_scores_dict[name] = y_val_scores

        model_metrics = compute_binary_metrics(y_val, y_val_preds, y_val_scores)
        model_metrics["model"] = name
        model_metrics["fit_time_seconds"] = round(fit_time, 2)
        metrics_summary.append(model_metrics)

        # Save model joblib
        model_save_path = OUT_DIR / f"{name}_model.joblib"
        joblib.dump(pipe, model_save_path)
        print(f"     Fitted in {fit_time:.1f}s | F1: {model_metrics['f1']:.4f} | Prec: {model_metrics['precision']:.4f} | Rec: {model_metrics['recall']:.4f} | Spec: {model_metrics['specificity']:.4f} | Saved to {model_save_path.name}")

    # Add V2 baseline metrics on validation for direct comparison
    # V2 primary domain: F1=0.9021, Prec=0.9133, Rec=0.8912, Spec=0.7553, ROC=0.9215, AP=0.9698
    # V2 all unique texts: F1=0.9022, Prec=0.9133, Rec=0.8913, Spec=0.7553, ROC=0.9215, AP=0.9698

    print("[5/6] Performing subgroup evaluation on validation partition ...")
    # Subgroup masks on validation
    val_reps["text_len"] = val_reps["raw_text"].str.len()
    val_reps["is_html"] = val_reps["raw_text"].apply(
        lambda t: bool(re.search(r"(?is)<\s*(?:!doctype\s+html|html|head|body|meta|link|a|form|div|p)\b", t))
    )
    val_reps["extracted_urls"] = val_reps["raw_text"].apply(extract_single_urls)
    val_reps["has_urls"] = val_reps["extracted_urls"] != ""

    subgroups = {
        "all_validation": np.ones(len(val_reps), dtype=bool),
        "html_messages": val_reps["is_html"].values,
        "non_html_messages": (~val_reps["is_html"]).values,
        "short_messages_le_100": (val_reps["text_len"] <= 100).values,
        "medium_messages_101_1000": ((val_reps["text_len"] > 100) & (val_reps["text_len"] <= 1000)).values,
        "long_messages_gt_1000": (val_reps["text_len"] > 1000).values,
        "url_containing_messages": val_reps["has_urls"].values,
        "messages_without_urls": (~val_reps["has_urls"]).values,
        "primary_domain_cohort": (val_reps["domain_evaluation_eligible"] == True).values,
    }

    subgroup_rows: list[dict[str, Any]] = []
    for sub_name, mask in subgroups.items():
        n_sub = int(mask.sum())
        if n_sub == 0:
            continue
        y_sub = y_val[mask]

        for m_name in models.keys():
            y_pred_sub = validation_predictions_dict[m_name][mask]
            y_score_sub = validation_scores_dict[m_name][mask]
            sub_m = compute_binary_metrics(y_sub, y_pred_sub, y_score_sub)
            sub_m["subgroup"] = sub_name
            sub_m["model"] = m_name
            subgroup_rows.append(sub_m)

    subgroup_df = pd.DataFrame(subgroup_rows)
    subgroup_df.to_csv(OUT_DIR / "subgroup_metrics.csv", index=False)
    print("  Saved subgroup_metrics.csv")

    print("[6/6] Threshold analysis on validation data for Dual-Channel V3 ...")
    y_scores_dual = validation_scores_dict["dual_channel_v3"]
    threshold_sweep: list[dict[str, Any]] = []
    thresholds = np.round(np.arange(0.05, 0.96, 0.01), 2)

    for t in thresholds:
        yh = (y_scores_dual >= t).astype(int)
        m = compute_binary_metrics(y_val, yh, y_scores_dual)
        m["threshold"] = float(t)
        threshold_sweep.append(m)

    tdf = pd.DataFrame(threshold_sweep)
    best_f1_row = tdf.loc[tdf["f1"].idxmax()]
    spec90_rows = tdf[tdf["specificity"].fillna(0) >= 0.90]
    best_spec90_row = spec90_rows.loc[spec90_rows["f1"].idxmax()] if not spec90_rows.empty else None

    threshold_analysis = {
        "note": "Evaluated strictly on the V2 validation partition. Do not tune against test data.",
        "reference_threshold_0_5": tdf[tdf["threshold"] == 0.50].iloc[0].to_dict(),
        "best_f1_threshold": best_f1_row.to_dict(),
        "best_specificity_ge90_threshold": best_spec90_row.to_dict() if best_spec90_row is not None else None,
        "threshold_sweep": threshold_sweep,
    }

    with open(OUT_DIR / "threshold_analysis.json", "w") as f:
        json.dump(threshold_analysis, f, indent=2, default=str)
    print("  Saved threshold_analysis.json")

    # Save model comparison CSV
    model_comp_df = pd.DataFrame(metrics_summary)
    model_comp_df.to_csv(OUT_DIR / "model_comparison.csv", index=False)
    print("  Saved model_comparison.csv")

    # Save validation metrics JSON
    with open(OUT_DIR / "validation_metrics.json", "w") as f:
        json.dump({
            "experiment": "Phishing Classifier V3: Dual-Channel Content + URL TF-IDF",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "sample_counts": {
                "training_representatives": len(train_reps),
                "validation_representatives": len(val_reps),
            },
            "overall_validation_metrics": metrics_summary,
            "subgroups": subgroup_rows,
        }, f, indent=2, default=str)
    print("  Saved validation_metrics.json")

    # Save experiment config JSON
    with open(OUT_DIR / "experiment_config.json", "w") as f:
        json.dump({
            "experiment": "Phishing Classifier V3 Dual-Channel",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "training_partition_manifest_records": len(train_reps),
            "validation_partition_manifest_records": len(val_reps),
            "random_seed": SEED,
            "classifier": LR_CONFIG,
            "feature_channels": {
                "channel_1_content": "HTML body visible text, anchor text, title; HTML markup/scripts excluded; URLs stripped in plain text",
                "channel_2_url": "Offline V2 candidate parser; hostname, subdomains, path tokens, param names; values and ambiguous bare domains excluded",
            },
            "models": list(models.keys()),
        }, f, indent=2)
    print("  Saved experiment_config.json")

    # Save training summary Markdown
    summary_md = f"""# Phishing Classifier V3 — Training & Comparative Evaluation Summary

**Experiment:** `phishing_v3_experiments`  
**Date (UTC):** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}  
**Train Representatives:** {len(train_reps):,}  
**Validation Representatives:** {len(val_reps):,}  
**Split Protection:** Strictly verified V2 train & validation partitions. V2 test partition was **not touched**.

---

## 1. Overall Model Comparison on Validation Partition (Threshold = 0.50)

| Model Architecture | Precision | Recall | F1-Score | Specificity | Accuracy | ROC-AUC | Avg Precision | Fit Time |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Content-Only TF-IDF** | {metrics_summary[0]['precision']:.4f} | {metrics_summary[0]['recall']:.4f} | {metrics_summary[0]['f1']:.4f} | {metrics_summary[0]['specificity']:.4f} | {metrics_summary[0]['accuracy']:.4f} | {metrics_summary[0]['roc_auc']:.4f} | {metrics_summary[0]['average_precision']:.4f} | {metrics_summary[0]['fit_time_seconds']}s |
| **URL-Only TF-IDF** | {metrics_summary[1]['precision']:.4f} | {metrics_summary[1]['recall']:.4f} | {metrics_summary[1]['f1']:.4f} | {metrics_summary[1]['specificity']:.4f} | {metrics_summary[1]['accuracy']:.4f} | {metrics_summary[1]['roc_auc']:.4f} | {metrics_summary[1]['average_precision']:.4f} | {metrics_summary[1]['fit_time_seconds']}s |
| **Dual-Channel V3 (Combined)** | **{metrics_summary[2]['precision']:.4f}** | **{metrics_summary[2]['recall']:.4f}** | **{metrics_summary[2]['f1']:.4f}** | **{metrics_summary[2]['specificity']:.4f}** | **{metrics_summary[2]['accuracy']:.4f}** | **{metrics_summary[2]['roc_auc']:.4f}** | **{metrics_summary[2]['average_precision']:.4f}** | {metrics_summary[2]['fit_time_seconds']}s |

*(Reference V2 Baseline on Validation: F1 = 0.9021, Precision = 0.9133, Recall = 0.8912, Specificity = 0.7553, ROC-AUC = 0.9215)*

---

## 2. Key Subgroup Analysis on Validation

| Subgroup | Model | Sample Count | Precision | Recall | F1-Score | Specificity | FP | FN |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
"""
    for sub in ["html_messages", "short_messages_le_100", "url_containing_messages", "messages_without_urls"]:
        for m_item in subgroup_rows:
            if m_item["subgroup"] == sub:
                spec_str = f"{m_item['specificity']:.4f}" if m_item['specificity'] is not None else "N/A"
                summary_md += f"| `{sub}` | {m_item['model']} | {m_item['n']} | {m_item['precision']:.4f} | {m_item['recall']:.4f} | {m_item['f1']:.4f} | {spec_str} | {m_item['FP']} | {m_item['FN']} |\n"

    summary_md += f"""
---

## 3. Threshold Optimization (Dual-Channel V3 on Validation Only)

* **Reference $\\tau = 0.50$:** F1 = {threshold_analysis['reference_threshold_0_5']['f1']:.4f}, Precision = {threshold_analysis['reference_threshold_0_5']['precision']:.4f}, Recall = {threshold_analysis['reference_threshold_0_5']['recall']:.4f}, Specificity = {threshold_analysis['reference_threshold_0_5']['specificity']:.4f}
* **Max F1 ($\\tau = {threshold_analysis['best_f1_threshold']['threshold']:.2f}$):** F1 = {threshold_analysis['best_f1_threshold']['f1']:.4f}, Precision = {threshold_analysis['best_f1_threshold']['precision']:.4f}, Recall = {threshold_analysis['best_f1_threshold']['recall']:.4f}, Specificity = {threshold_analysis['best_f1_threshold']['specificity']:.4f}
"""
    if threshold_analysis['best_specificity_ge90_threshold']:
        best_spec = threshold_analysis['best_specificity_ge90_threshold']
        summary_md += f"* **High Specificity $\\ge 90\\%$ ($\\tau = {best_spec['threshold']:.2f}$):** F1 = {best_spec['f1']:.4f}, Precision = {best_spec['precision']:.4f}, Recall = {best_spec['recall']:.4f}, Specificity = {best_spec['specificity']:.4f}\n"

    with open(OUT_DIR / "training_summary.md", "w") as f:
        f.write(summary_md)
    print("  Saved training_summary.md")

    total_time = time.time() - t0
    print(f"\nAll experiments successfully completed in {total_time:.1f}s.")


if __name__ == "__main__":
    main()
