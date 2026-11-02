"""TEXT-EVAL-1 SMS Pilot: Frozen Model Evaluation Runner.

Evaluates frozen models (V2, V3 Content-Only, V3 Dual-Channel, V3 URL-Only)
on the 250 sanitized SMS messages.

Outputs saved to:
backend/reports/ml/text_eval_1_acquisition/sms_pilot/model_evaluation/
"""
import csv
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
import sklearn.metrics as metrics
import joblib

PROJECT_ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
if str(PROJECT_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.dual_channel import *
from notebooks.phishing_url_extraction_v2 import extract_candidates

PILOT_DIR = PROJECT_ROOT / "backend/reports/ml/text_eval_1_acquisition/sms_pilot"
OUT_DIR = PILOT_DIR / "model_evaluation"
MANIFEST_PATH = PILOT_DIR / "sample_manifest.csv"
FREEZE_MANIFEST_PATH = PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/model_implementation_freeze_manifest.json"

THRESHOLD = 0.50

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def compute_metrics(y_true, y_pred, y_prob):
    """Compute binary classification metrics."""
    if len(y_true) == 0:
        return {}
    
    # Check if single class
    unique_classes = set(y_true)
    tn, fp, fn, tp = 0, 0, 0, 0
    for yt, yp in zip(y_true, y_pred):
        if yt == 1 and yp == 1:
            tp += 1
        elif yt == 1 and yp == 0:
            fn += 1
        elif yt == 0 and yp == 1:
            fp += 1
        elif yt == 0 and yp == 0:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    balanced_acc = (recall + specificity) / 2.0
    acc = (tp + tn) / len(y_true)

    roc_auc = None
    avg_prec = None
    if len(unique_classes) > 1 and y_prob is not None:
        try:
            roc_auc = float(metrics.roc_auc_score(y_true, y_prob))
        except Exception:
            pass
        try:
            avg_prec = float(metrics.average_precision_score(y_true, y_prob))
        except Exception:
            pass

    return {
        "n_samples": len(y_true),
        "n_pos": int(sum(y_true)),
        "n_neg": int(len(y_true) - sum(y_true)),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "precision": float(round(precision, 4)),
        "recall": float(round(recall, 4)),
        "specificity": float(round(specificity, 4)),
        "f1": float(round(f1, 4)),
        "balanced_accuracy": float(round(balanced_acc, 4)),
        "accuracy": float(round(acc, 4)),
        "roc_auc": float(round(roc_auc, 4)) if roc_auc is not None else None,
        "average_precision": float(round(avg_prec, 4)) if avg_prec is not None else None,
    }

def main():
    print("=" * 70)
    print("TEXT-EVAL-1 SMS PILOT: FROZEN MODEL EVALUATION PIPELINE")
    print("=" * 70)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Verify Model Integrity against Freeze Manifest
    print("\n--- Verifying Frozen Model Hashes ---")
    with open(FREEZE_MANIFEST_PATH, encoding="utf-8") as f:
        freeze_data = json.load(f)

    model_integrity = {
        "status": "PASS",
        "freeze_manifest_referenced": str(FREEZE_MANIFEST_PATH),
        "verified_models": {},
        "verified_code": {}
    }

    for name, m_info in freeze_data["frozen_model_artifacts"].items():
        actual_path = PROJECT_ROOT / m_info["relative_path"]
        actual_sha = sha256_file(actual_path)
        expected_sha = m_info["sha256"]
        match = (actual_sha == expected_sha)
        print(f"Model [{name}]: expected {expected_sha[:10]}... got {actual_sha[:10]}... Match: {match}")
        model_integrity["verified_models"][name] = {
            "path": m_info["relative_path"],
            "expected_sha256": expected_sha,
            "actual_sha256": actual_sha,
            "match": match
        }
        if not match:
            model_integrity["status"] = "FAIL"
            raise RuntimeError(f"Model hash mismatch for {name}")

    for name, c_info in freeze_data["frozen_inference_implementations"].items():
        actual_path = PROJECT_ROOT / c_info["relative_path"]
        actual_sha = sha256_file(actual_path)
        expected_sha = c_info["sha256"]
        match = (actual_sha == expected_sha)
        print(f"Code [{name}]: expected {expected_sha[:10]}... got {actual_sha[:10]}... Match: {match}")
        model_integrity["verified_code"][name] = {
            "path": c_info["relative_path"],
            "expected_sha256": expected_sha,
            "actual_sha256": actual_sha,
            "match": match
        }
        if not match:
            model_integrity["status"] = "FAIL"
            raise RuntimeError(f"Code hash mismatch for {name}")

    with open(OUT_DIR / "model_integrity_check.json", "w", encoding="utf-8") as f:
        json.dump(model_integrity, f, indent=2)
    print(f"Saved: {OUT_DIR / 'model_integrity_check.json'}")

    # 2. Load Models
    print("\n--- Loading Frozen Models ---")
    v2_model = joblib.load(PROJECT_ROOT / freeze_data["frozen_model_artifacts"]["v2_baseline"]["relative_path"])
    v3_dual = joblib.load(PROJECT_ROOT / freeze_data["frozen_model_artifacts"]["v3_dual_channel"]["relative_path"])
    v3_content = joblib.load(PROJECT_ROOT / freeze_data["frozen_model_artifacts"]["v3_content_only"]["relative_path"])
    v3_url = joblib.load(PROJECT_ROOT / freeze_data["frozen_model_artifacts"]["v3_url_only"]["relative_path"])
    print("All 4 frozen models loaded into memory successfully.")

    # 3. Load Sample Manifest
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        samples = list(csv.DictReader(f))
    print(f"\nLoaded {len(samples)} samples from manifest.")

    # 4. Run Inference
    print("\n--- Running Inference on 250 Pilot Messages ---")
    predictions = []

    texts = [r["sanitized_message_text"] for r in samples]

    # Batch inference
    p_v2 = v2_model.predict_proba(texts)[:, 1]
    p_v3_dual = v3_dual.predict_proba(texts)[:, 1]
    p_v3_content = v3_content.predict_proba(texts)[:, 1]
    p_v3_url_raw = v3_url.predict_proba(texts)[:, 1]

    for idx, r in enumerate(samples):
        msg_text = r["sanitized_message_text"]
        cands = extract_candidates("m", msg_text)
        url_count = len(cands)
        has_url = url_count > 0
        extracted_urls = ";".join([c.candidate_text for c in cands])

        prob_v2 = float(p_v2[idx])
        pred_v2 = 1 if prob_v2 >= THRESHOLD else 0

        prob_dual = float(p_v3_dual[idx])
        pred_dual = 1 if prob_dual >= THRESHOLD else 0

        prob_content = float(p_v3_content[idx])
        pred_content = 1 if prob_content >= THRESHOLD else 0

        # V3 URL-Only: evaluate only on messages containing extractable URLs
        if has_url:
            prob_url = float(p_v3_url_raw[idx])
            pred_url = 1 if prob_url >= THRESHOLD else 0
        else:
            prob_url = None
            pred_url = None

        char_len = len(msg_text)
        len_group = "short" if char_len < 129 else "long"

        predictions.append({
            "pilot_serial_number": int(r["pilot_serial_number"]),
            "cohort": r["cohort"],
            "ground_truth_label": int(r["ground_truth_label"]),
            "evaluation_label": r["evaluation_label"],
            "source_dataset": r["source_dataset"],
            "source_record_id": r["source_record_id"],
            "campaign_id": r["campaign_id"],
            "message_length": char_len,
            "length_subgroup": len_group,
            "url_count": url_count,
            "has_url": has_url,
            "extracted_urls": extracted_urls,
            "prob_v2": round(prob_v2, 6),
            "pred_v2": pred_v2,
            "prob_v3_dual": round(prob_dual, 6),
            "pred_v3_dual": pred_dual,
            "prob_v3_content": round(prob_content, 6),
            "pred_v3_content": pred_content,
            "prob_v3_url": round(prob_url, 6) if prob_url is not None else "",
            "pred_v3_url": pred_url if pred_url is not None else "",
        })

    # Save predictions.csv
    pred_path = OUT_DIR / "predictions.csv"
    with open(pred_path, "w", encoding="utf-8", newline="") as f:
        fields = list(predictions[0].keys())
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(predictions)
    print(f"Saved: {pred_path}")

    # 5. Compute Metrics Across Evaluation Benchmarks
    print("\n--- Computing Performance Metrics ---")

    # Primary Benchmark: Phishing (Cohort A) vs Benign Ham (Cohort B)
    # Ground truth: Cohort A = 1, Cohort B = 0 (100 pos, 100 neg)
    primary_eval = [p for p in predictions if p["cohort"] in ("Cohort_A_Smishing", "Cohort_B_Legitimate_SMS")]

    # Commercial Spam Benchmark: Commercial Spam (Cohort C) False Positive Rate
    # Ground truth: 0 (Cohort C nuisance spam should NOT be classified as phishing)
    spam_eval = [p for p in predictions if p["cohort"] == "Cohort_C_Commercial_Spam"]

    # Overall 3-Cohort Evaluation: Cohort A (1) vs (Cohort B + C) (0)
    all_eval = predictions

    models = ["v2", "v3_dual", "v3_content", "v3_url"]

    metrics_dict = {
        "evaluation_timestamp": "2026-11-02",
        "threshold": THRESHOLD,
        "sample_counts": {
            "total": len(predictions),
            "cohort_a_smishing": 100,
            "cohort_b_ham": 100,
            "cohort_c_spam": 50,
        },
        "primary_benchmark_smishing_vs_ham": {},
        "all_cohorts_smishing_vs_non_smishing": {},
        "commercial_spam_fp_audit": {},
    }

    for m in models:
        # 1. Primary Benchmark (Smishing vs Ham)
        if m == "v3_url":
            sub_eval = [p for p in primary_eval if p["has_url"]]
        else:
            sub_eval = primary_eval
        
        y_true = [p["ground_truth_label"] for p in sub_eval]
        y_pred = [p[f"pred_{m}"] for p in sub_eval]
        y_prob = [p[f"prob_{m}"] for p in sub_eval]
        metrics_dict["primary_benchmark_smishing_vs_ham"][m] = compute_metrics(y_true, y_pred, y_prob)

        # 2. All Cohorts (Smishing vs Ham+Spam)
        if m == "v3_url":
            sub_all = [p for p in all_eval if p["has_url"]]
        else:
            sub_all = all_eval
        y_true_all = [p["ground_truth_label"] for p in sub_all]
        y_pred_all = [p[f"pred_{m}"] for p in sub_all]
        y_prob_all = [p[f"prob_{m}"] for p in sub_all]
        metrics_dict["all_cohorts_smishing_vs_non_smishing"][m] = compute_metrics(y_true_all, y_pred_all, y_prob_all)

        # 3. Commercial Spam FP Audit
        if m == "v3_url":
            sub_spam = [p for p in spam_eval if p["has_url"]]
        else:
            sub_spam = spam_eval
        fp_count = sum(1 for p in sub_spam if p[f"pred_{m}"] == 1)
        total_sub_spam = len(sub_spam)
        metrics_dict["commercial_spam_fp_audit"][m] = {
            "n_samples": total_sub_spam,
            "fp_count": fp_count,
            "fp_rate": round(fp_count / total_sub_spam, 4) if total_sub_spam > 0 else 0.0,
            "tn_count": total_sub_spam - fp_count,
        }

    metrics_path = OUT_DIR / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_dict, f, indent=2)
    print(f"Saved: {metrics_path}")

    # 6. Compute Subgroup Metrics (URL-Present vs URL-Absent, Short vs Long)
    print("\n--- Computing Subgroup Metrics ---")
    subgroup_rows = []

    subgroups = [
        ("Cohort_A_Smishing", lambda p: p["cohort"] == "Cohort_A_Smishing"),
        ("Cohort_B_Legitimate_SMS", lambda p: p["cohort"] == "Cohort_B_Legitimate_SMS"),
        ("Cohort_C_Commercial_Spam", lambda p: p["cohort"] == "Cohort_C_Commercial_Spam"),
        ("URL_Present", lambda p: p["has_url"]),
        ("URL_Absent", lambda p: not p["has_url"]),
        ("Length_Short (<129 chars)", lambda p: p["length_subgroup"] == "short"),
        ("Length_Long (>=129 chars)", lambda p: p["length_subgroup"] == "long"),
        ("Primary_URL_Present", lambda p: p["cohort"] in ("Cohort_A_Smishing", "Cohort_B_Legitimate_SMS") and p["has_url"]),
        ("Primary_URL_Absent", lambda p: p["cohort"] in ("Cohort_A_Smishing", "Cohort_B_Legitimate_SMS") and not p["has_url"]),
        ("Primary_Short", lambda p: p["cohort"] in ("Cohort_A_Smishing", "Cohort_B_Legitimate_SMS") and p["length_subgroup"] == "short"),
        ("Primary_Long", lambda p: p["cohort"] in ("Cohort_A_Smishing", "Cohort_B_Legitimate_SMS") and p["length_subgroup"] == "long"),
    ]

    for sg_name, filt in subgroups:
        subset = [p for p in predictions if filt(p)]
        if not subset:
            continue
        for m in models:
            if m == "v3_url" and not all(p["has_url"] for p in subset):
                valid_subset = [p for p in subset if p["has_url"]]
                if not valid_subset:
                    continue
            else:
                valid_subset = subset

            y_true = [p["ground_truth_label"] for p in valid_subset]
            y_pred = [p[f"pred_{m}"] for p in valid_subset]
            y_prob = [p[f"prob_{m}"] for p in valid_subset]
            m_res = compute_metrics(y_true, y_pred, y_prob)

            row = {
                "subgroup": sg_name,
                "model": m,
                "n_samples": m_res["n_samples"],
                "n_pos": m_res["n_pos"],
                "n_neg": m_res["n_neg"],
                "tp": m_res["tp"],
                "fp": m_res["fp"],
                "tn": m_res["tn"],
                "fn": m_res["fn"],
                "precision": m_res["precision"],
                "recall": m_res["recall"],
                "specificity": m_res["specificity"],
                "f1": m_res["f1"],
                "balanced_accuracy": m_res["balanced_accuracy"],
                "roc_auc": m_res["roc_auc"] if m_res["roc_auc"] is not None else "",
                "average_precision": m_res["average_precision"] if m_res["average_precision"] is not None else "",
            }
            subgroup_rows.append(row)

    sg_path = OUT_DIR / "subgroup_metrics.csv"
    with open(sg_path, "w", encoding="utf-8", newline="") as f:
        fields = list(subgroup_rows[0].keys())
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(subgroup_rows)
    print(f"Saved: {sg_path}")

    print("\nInference and Metric Generation Completed Successfully!")

if __name__ == "__main__":
    main()
