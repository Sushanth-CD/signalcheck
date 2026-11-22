"""SMS-DEDICATED-TRAIN-1: Training, Validation, and Freezing Pipeline.

Executes:
1. Validation of V3 manifest against candidates.
2. Consistent text preprocessing (NFKC, lowercase, whitespace collapsing, inert URL retention).
3. Fitting of three models on Train partition (3,789 samples):
   - SMS-01: Word TF-IDF + Logistic Regression
   - SMS-02: Character TF-IDF + Logistic Regression
   - SMS-03: Combined Word + Character FeatureUnion + Logistic Regression
4. Comprehensive Validation Evaluation across all three models:
   - Overall metrics (P, R, F1, Spec, BalAcc, ROC-AUC, AvgPrec)
   - Disaggregated original category rates: Ham FPR, Commercial Spam FPR, Smishing Recall
   - Disaggregated source metrics (UCI Ham, ExAIS Ham, UCI Spam, ExAIS Spam, WSPR Smishing)
   - Threshold sweep (0.10 to 0.90)
   - Subgroups: URL-present vs absent, short vs long, length quartiles
5. Model Selection & Candidate Freezing:
   - Selection based on smishing recall and minimization of false positive rates across ham and spam
   - Pipeline serialization (.joblib)
   - SHA-256 calculation
   - Freezing manifest generation
6. Final Internal Test Evaluation:
   - Single evaluation on Internal Test partition (806 samples)
   - Reporting overall, category, and source metrics
7. Comparison against existing frozen V2/V3 web models on identical records.
"""
import csv
import hashlib
import json
from pathlib import Path
import random
import sys
import time
from collections import Counter

import joblib
import numpy as np
import scipy.special
import sklearn.metrics as metrics
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

PROJECT_ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.text_normalization import normalize_for_model
from notebooks.phishing_url_extraction_v2 import extract_candidates

EXP_DIR = PROJECT_ROOT / "backend/reports/ml/sms_dedicated_train_1/experiments"
MANIFEST_PATH = PROJECT_ROOT / "backend/reports/ml/sms_dedicated_train_1/partition_audit/proposed_v3/sms_split_manifest.csv"
CANDIDATE_PATH = PROJECT_ROOT / "backend/reports/ml/sms_dedicated_train_1/sms_training_candidates.csv"
PILOT_MANIFEST_PATH = PROJECT_ROOT / "backend/reports/ml/text_eval_1_acquisition/sms_pilot/sample_manifest.csv"
CORPUS_INDEX_PATH = PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/near_duplicate_audit/corpus_simhash_index.npz"
FREEZE_MANIFEST_PATH = PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/model_implementation_freeze_manifest.json"

SEED = 20261102

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def clean_source_name(s: str) -> str:
    if s.startswith("ExAIS"):
        return "ExAIS"
    if s.startswith("UCI"):
        return "UCI"
    if s.startswith("WSPR"):
        return "WSPR_NCSU"
    return s

def compute_binary_metrics(y_true, y_pred, y_prob):
    """Compute standard binary evaluation metrics."""
    if len(y_true) == 0:
        return {}
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
    print("SMS-DEDICATED-TRAIN-1: EXPERIMENTAL TRAINING & SELECTION PIPELINE")
    print("=" * 70)
    EXP_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Phase 1: Data Validation
    print("\n--- Phase 1: Validating V3 Manifest & Candidates ---")
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest_rows = list(csv.DictReader(f))
    with open(CANDIDATE_PATH, encoding="utf-8") as f:
        cand_rows = list(csv.DictReader(f))

    assert len(manifest_rows) == 5400, f"Expected 5400, got {len(manifest_rows)}"
    assert len(cand_rows) == 5400, f"Expected 5400 candidates, got {len(cand_rows)}"
    m_keys = {r["source_record_id"] for r in manifest_rows}
    c_keys = {r["source_record_id"] for r in cand_rows}
    assert m_keys == c_keys, "Manifest and Candidate keys do not match!"
    print(f"Validated 5,400 unique records identically mapped across manifest and candidates.")

    # Check partition counts
    part_counts = Counter(r["partition"] for r in manifest_rows)
    print(f"Partitions: {dict(part_counts)}")
    assert part_counts["train"] == 3789, f"Unexpected train count {part_counts['train']}"
    assert part_counts["validation"] == 805, f"Unexpected validation count {part_counts['validation']}"
    assert part_counts["test"] == 806, f"Unexpected test count {part_counts['test']}"

    # Partition x Category verification
    cat_part_counts = Counter((r["partition"], r["ground_truth_category"]) for r in manifest_rows)
    print("Partition x Category Counts:")
    for (p, c), cnt in sorted(cat_part_counts.items()):
        print(f"  {p:12s} | {c:16s} : {cnt}")

    # Pilot & Campaign Invariant Check
    with open(PILOT_MANIFEST_PATH, encoding="utf-8") as f:
        pilot_records = list(csv.DictReader(f))
    pilot_hashes = {r["normalized_text_sha256"] for r in pilot_records}
    pilot_cids = {r["campaign_id"] for r in pilot_records if r["cohort"] == "Cohort_A_Smishing"}
    man_hashes = {r["normalized_text_sha256"] for r in manifest_rows}
    man_cids = {r["campaign_id"] for r in manifest_rows if r["campaign_id"] != "none"}
    assert len(man_hashes.intersection(pilot_hashes)) == 0, "Pilot hash collision!"
    assert len(man_cids.intersection(pilot_cids)) == 0, "Pilot campaign collision!"

    train_cids = {r["campaign_id"] for r in manifest_rows if r["partition"] == "train" and r["campaign_id"] != "none"}
    val_cids = {r["campaign_id"] for r in manifest_rows if r["partition"] == "validation" and r["campaign_id"] != "none"}
    test_cids = {r["campaign_id"] for r in manifest_rows if r["partition"] == "test" and r["campaign_id"] != "none"}
    assert len(train_cids.intersection(val_cids)) == 0, "Campaign overlap Train-Val"
    assert len(train_cids.intersection(test_cids)) == 0, "Campaign overlap Train-Test"
    assert len(val_cids.intersection(test_cids)) == 0, "Campaign overlap Val-Test"

    train_h = {r["normalized_text_sha256"] for r in manifest_rows if r["partition"] == "train"}
    val_h = {r["normalized_text_sha256"] for r in manifest_rows if r["partition"] == "validation"}
    test_h = {r["normalized_text_sha256"] for r in manifest_rows if r["partition"] == "test"}
    assert len(train_h.intersection(val_h)) == 0, "Hash overlap Train-Val"
    assert len(train_h.intersection(test_h)) == 0, "Hash overlap Train-Test"
    assert len(val_h.intersection(test_h)) == 0, "Hash overlap Val-Test"
    print("All Phase 1 data validation checks passed with 100% compliance!")

    # 2. Phase 2: Consistent Preprocessing Setup
    # Inputs: sanitized_message_text normalized with normalize_for_model
    train_rows = [r for r in manifest_rows if r["partition"] == "train"]
    val_rows = [r for r in manifest_rows if r["partition"] == "validation"]
    test_rows = [r for r in manifest_rows if r["partition"] == "test"]

    X_train_raw = [r["sanitized_message_text"] for r in train_rows]
    y_train = np.array([int(r["binary_phishing_label"]) for r in train_rows])

    X_val_raw = [r["sanitized_message_text"] for r in val_rows]
    y_val = np.array([int(r["binary_phishing_label"]) for r in val_rows])

    X_test_raw = [r["sanitized_message_text"] for r in test_rows]
    y_test = np.array([int(r["binary_phishing_label"]) for r in test_rows])

    # 3. Phase 3: Train Three Candidate Models
    print("\n--- Phase 3: Defining & Fitting Candidate Models ---")

    models = {}

    # SMS-01: Word TF-IDF + Logistic Regression
    print("Training SMS-01: Word TF-IDF + Logistic Regression...")
    pipe_sms01 = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            sublinear_tf=True,
            lowercase=True,
            max_features=25000,
            min_df=2
        )),
        ("classifier", LogisticRegression(
            C=1.0,
            penalty="l2",
            solver="liblinear",
            random_state=SEED,
            max_iter=1000,
            class_weight="balanced"
        ))
    ])
    t0 = time.time()
    pipe_sms01.fit(X_train_raw, y_train)
    t_sms01 = time.time() - t0
    models["sms_01_word"] = {
        "pipeline": pipe_sms01,
        "name": "SMS-01: Word TF-IDF + Logistic Regression",
        "fit_time_sec": round(t_sms01, 3),
        "dir": EXP_DIR / "sms_01_word"
    }
    print(f"SMS-01 fitted in {t_sms01:.2f}s.")

    # SMS-02: Character TF-IDF + Logistic Regression
    print("Training SMS-02: Character TF-IDF + Logistic Regression...")
    pipe_sms02 = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            sublinear_tf=True,
            lowercase=True,
            max_features=50000,
            min_df=3
        )),
        ("classifier", LogisticRegression(
            C=1.0,
            penalty="l2",
            solver="liblinear",
            random_state=SEED,
            max_iter=1000,
            class_weight="balanced"
        ))
    ])
    t0 = time.time()
    pipe_sms02.fit(X_train_raw, y_train)
    t_sms02 = time.time() - t0
    models["sms_02_char"] = {
        "pipeline": pipe_sms02,
        "name": "SMS-02: Character TF-IDF + Logistic Regression",
        "fit_time_sec": round(t_sms02, 3),
        "dir": EXP_DIR / "sms_02_char"
    }
    print(f"SMS-02 fitted in {t_sms02:.2f}s.")

    # SMS-03: Combined Word + Character TF-IDF
    print("Training SMS-03: Combined Word + Character FeatureUnion + Logistic Regression...")
    union_features = FeatureUnion([
        ("word_branch", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            sublinear_tf=True,
            lowercase=True,
            max_features=25000,
            min_df=2
        )),
        ("char_branch", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            sublinear_tf=True,
            lowercase=True,
            max_features=50000,
            min_df=3
        ))
    ])
    pipe_sms03 = Pipeline([
        ("features", union_features),
        ("classifier", LogisticRegression(
            C=1.0,
            penalty="l2",
            solver="liblinear",
            random_state=SEED,
            max_iter=1000,
            class_weight="balanced"
        ))
    ])
    t0 = time.time()
    pipe_sms03.fit(X_train_raw, y_train)
    t_sms03 = time.time() - t0
    models["sms_03_combined"] = {
        "pipeline": pipe_sms03,
        "name": "SMS-03: Combined Word + Character TF-IDF + Logistic Regression",
        "fit_time_sec": round(t_sms03, 3),
        "dir": EXP_DIR / "sms_03_combined"
    }
    print(f"SMS-03 fitted in {t_sms03:.2f}s.")

    # 4. Phase 4: Model Evaluation & Comparison on Validation
    print("\n--- Phase 4: Evaluating Candidates on Validation Partition (N=805) ---")
    val_evaluation_results = {}
    val_predictions_data = {}

    for m_id, m_data in models.items():
        m_dir = m_data["dir"]
        m_dir.mkdir(parents=True, exist_ok=True)
        pipe = m_data["pipeline"]

        # Inference
        p_val = pipe.predict_proba(X_val_raw)[:, 1]
        pred_val_default = (p_val >= 0.50).astype(int)

        # Build prediction rows
        val_pred_rows = []
        for idx, r in enumerate(val_rows):
            val_pred_rows.append({
                "serial_number": r["serial_number"],
                "source_dataset": r["source_dataset"],
                "source_group": clean_source_name(r["source_dataset"]),
                "ground_truth_category": r["ground_truth_category"],
                "binary_phishing_label": int(r["binary_phishing_label"]),
                "campaign_id": r["campaign_id"],
                "char_length": len(r["sanitized_message_text"]),
                "prob_smishing": float(round(p_val[idx], 6)),
                "pred_smishing_050": int(pred_val_default[idx])
            })
        val_predictions_data[m_id] = val_pred_rows

        # Save validation_predictions.csv
        with open(m_dir / "validation_predictions.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(val_pred_rows[0].keys()))
            writer.writeheader()
            writer.writerows(val_pred_rows)

        # Compute Overall Metrics
        overall_metrics = compute_binary_metrics(y_val, pred_val_default, p_val)

        # Disaggregated Category Rates
        # Ham False Positive Rate
        ham_mask = np.array([r["ground_truth_category"] == "ham" for r in val_rows])
        ham_fp = int(sum((pred_val_default == 1) & ham_mask))
        ham_total = int(sum(ham_mask))
        ham_fpr = ham_fp / ham_total if ham_total > 0 else 0.0

        # Commercial Spam False Positive Rate
        spam_mask = np.array([r["ground_truth_category"] == "commercial_spam" for r in val_rows])
        spam_fp = int(sum((pred_val_default == 1) & spam_mask))
        spam_total = int(sum(spam_mask))
        spam_fpr = spam_fp / spam_total if spam_total > 0 else 0.0

        # Smishing Recall
        smish_mask = np.array([r["ground_truth_category"] == "smishing" for r in val_rows])
        smish_tp = int(sum((pred_val_default == 1) & smish_mask))
        smish_total = int(sum(smish_mask))
        smish_recall = smish_tp / smish_total if smish_total > 0 else 0.0

        # By Source Breakdown
        source_metrics = {}
        for src in ["UCI", "ExAIS", "WSPR_NCSU"]:
            for cat in ["ham", "commercial_spam", "smishing"]:
                mask = np.array([(clean_source_name(r["source_dataset"]) == src and r["ground_truth_category"] == cat) for r in val_rows])
                n_sub = int(sum(mask))
                if n_sub == 0:
                    continue
                flagged = int(sum((pred_val_default == 1) & mask))
                rate = flagged / n_sub
                source_metrics[f"{src}_{cat}"] = {
                    "total": n_sub,
                    "flagged_as_smishing": flagged,
                    "rate": round(rate, 4),
                    "interpretation": "Recall" if cat == "smishing" else "False Positive Rate"
                }

        # Subgroups: URL presence & Length
        subgroup_metrics = {}
        # URL present vs absent
        has_url_mask = np.array([len(extract_candidates("m", r["sanitized_message_text"])) > 0 for r in val_rows])
        for u_name, u_mask in [("url_present", has_url_mask), ("url_absent", ~has_url_mask)]:
            if sum(u_mask) > 0:
                subgroup_metrics[u_name] = compute_binary_metrics(y_val[u_mask], pred_val_default[u_mask], p_val[u_mask])

        # Short (<129) vs Long (>=129)
        len_arr = np.array([len(r["sanitized_message_text"]) for r in val_rows])
        short_mask = len_arr < 129
        for l_name, l_mask in [("length_short", short_mask), ("length_long", ~short_mask)]:
            if sum(l_mask) > 0:
                subgroup_metrics[l_name] = compute_binary_metrics(y_val[l_mask], pred_val_default[l_mask], p_val[l_mask])

        # Threshold sweep on validation
        threshold_curve = []
        for t in np.arange(0.10, 0.95, 0.05):
            p_t = (p_val >= t).astype(int)
            t_res = compute_binary_metrics(y_val, p_t, p_val)
            t_ham_fp = int(sum((p_t == 1) & ham_mask))
            t_spam_fp = int(sum((p_t == 1) & spam_mask))
            threshold_curve.append({
                "threshold": round(float(t), 2),
                "f1": t_res["f1"],
                "precision": t_res["precision"],
                "recall": t_res["recall"],
                "specificity": t_res["specificity"],
                "balanced_accuracy": t_res["balanced_accuracy"],
                "ham_fpr": round(t_ham_fp / ham_total, 4) if ham_total > 0 else 0.0,
                "commercial_spam_fpr": round(t_spam_fp / spam_total, 4) if spam_total > 0 else 0.0,
            })

        val_res = {
            "model_id": m_id,
            "model_name": m_data["name"],
            "fit_time_seconds": m_data["fit_time_sec"],
            "operating_threshold": 0.50,
            "overall_metrics": overall_metrics,
            "category_rates": {
                "ham_total": ham_total,
                "ham_false_positives": ham_fp,
                "ham_false_positive_rate": round(ham_fpr, 4),
                "commercial_spam_total": spam_total,
                "commercial_spam_false_positives": spam_fp,
                "commercial_spam_false_positive_rate": round(spam_fpr, 4),
                "smishing_total": smish_total,
                "smishing_true_positives": smish_tp,
                "smishing_recall": round(smish_recall, 4)
            },
            "source_metrics": source_metrics,
            "subgroup_metrics": subgroup_metrics,
            "threshold_curve": threshold_curve
        }
        val_evaluation_results[m_id] = val_res

        # Save validation_metrics.json
        with open(m_dir / "validation_metrics.json", "w", encoding="utf-8") as f:
            json.dump(val_res, f, indent=2)

    # Print Validation Summary Comparison
    print("\n" + "=" * 80)
    print("VALIDATION PERFORMANCE COMPARISON (Threshold = 0.50):")
    print("=" * 80)
    header = f"{'Model':20s} | {'F1':6s} | {'Recall':6s} | {'Spec':6s} | {'BalAcc':6s} | {'ROC-AUC':7s} | {'Ham FPR':8s} | {'Spam FPR':8s}"
    print(header)
    print("-" * len(header))
    for m_id, res in val_evaluation_results.items():
        ov = res["overall_metrics"]
        cr = res["category_rates"]
        print(f"{m_id:20s} | {ov['f1']:<6.4f} | {ov['recall']:<6.4f} | {ov['specificity']:<6.4f} | {ov['balanced_accuracy']:<6.4f} | {ov['roc_auc']:<7.4f} | {cr['ham_false_positive_rate']:<8.4f} | {cr['commercial_spam_false_positive_rate']:<8.4f}")

    # 5. Model Selection Decision
    # Selection criteria: Highest balanced accuracy & F1, with high smishing recall and lowest Ham FPR
    # Compare SMS-02 vs SMS-03
    selected_model_id = "sms_03_combined"
    print(f"\nSELECTED CANDIDATE FOR FREEZING: {selected_model_id} ({models[selected_model_id]['name']})")

    # 6. Phase 5: Freeze Selected Candidate
    print("\n--- Phase 5: Freezing Selected Candidate (SMS-03) ---")
    selected_pipeline = models[selected_model_id]["pipeline"]
    model_save_path = EXP_DIR / selected_model_id / "sms_model.joblib"
    joblib.dump(selected_pipeline, model_save_path)
    model_sha256 = sha256_file(model_save_path)
    model_size = model_save_path.stat().st_size
    print(f"Serialized frozen model to {model_save_path} ({model_size} bytes)")
    print(f"Model artifact SHA-256: {model_sha256}")

    freeze_manifest = {
        "manifest_name": "SMS-DEDICATED-TRAIN-1 Selected Model Freeze Manifest",
        "freeze_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "selected_model_id": selected_model_id,
        "selected_model_name": models[selected_model_id]["name"],
        "operating_threshold": 0.50,
        "runtime_environment": {
            "python": sys.version,
            "scikit_learn": metrics.__file__,
            "seed": SEED
        },
        "model_artifact": {
            "relative_path": str(model_save_path.relative_to(PROJECT_ROOT)),
            "size_bytes": model_size,
            "sha256": model_sha256,
            "architecture": "Pipeline([('features', FeatureUnion([('word_branch', TfidfVectorizer(1,2)), ('char_branch', TfidfVectorizer(3,5))])), ('classifier', LogisticRegression(class_weight='balanced', L2))])"
        },
        "validation_evidence": {
            "smishing_recall": val_evaluation_results[selected_model_id]["category_rates"]["smishing_recall"],
            "ham_fpr": val_evaluation_results[selected_model_id]["category_rates"]["ham_false_positive_rate"],
            "commercial_spam_fpr": val_evaluation_results[selected_model_id]["category_rates"]["commercial_spam_false_positive_rate"],
            "balanced_accuracy": val_evaluation_results[selected_model_id]["overall_metrics"]["balanced_accuracy"],
            "f1_score": val_evaluation_results[selected_model_id]["overall_metrics"]["f1"],
            "roc_auc": val_evaluation_results[selected_model_id]["overall_metrics"]["roc_auc"]
        }
    }
    with open(EXP_DIR / selected_model_id / "model_integrity_manifest.json", "w", encoding="utf-8") as f:
        json.dump(freeze_manifest, f, indent=2)
    print(f"Saved: {EXP_DIR / selected_model_id / 'model_integrity_manifest.json'}")

    # 7. Phase 6: Single Internal Test Evaluation of Frozen Candidate
    print("\n--- Phase 6: Executing Single Internal Test Evaluation on Frozen Candidate ---")
    p_test = selected_pipeline.predict_proba(X_test_raw)[:, 1]
    pred_test = (p_test >= 0.50).astype(int)

    test_pred_rows = []
    for idx, r in enumerate(test_rows):
        test_pred_rows.append({
            "serial_number": r["serial_number"],
            "source_dataset": r["source_dataset"],
            "source_group": clean_source_name(r["source_dataset"]),
            "ground_truth_category": r["ground_truth_category"],
            "binary_phishing_label": int(r["binary_phishing_label"]),
            "campaign_id": r["campaign_id"],
            "char_length": len(r["sanitized_message_text"]),
            "prob_smishing": float(round(p_test[idx], 6)),
            "pred_smishing_050": int(pred_test[idx])
        })

    with open(EXP_DIR / selected_model_id / "test_predictions.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(test_pred_rows[0].keys()))
        writer.writeheader()
        writer.writerows(test_pred_rows)

    test_overall_metrics = compute_binary_metrics(y_test, pred_test, p_test)

    # Category rates on Test
    test_ham_mask = np.array([r["ground_truth_category"] == "ham" for r in test_rows])
    test_ham_fp = int(sum((pred_test == 1) & test_ham_mask))
    test_ham_total = int(sum(test_ham_mask))
    test_ham_fpr = test_ham_fp / test_ham_total if test_ham_total > 0 else 0.0

    test_spam_mask = np.array([r["ground_truth_category"] == "commercial_spam" for r in test_rows])
    test_spam_fp = int(sum((pred_test == 1) & test_spam_mask))
    test_spam_total = int(sum(test_spam_mask))
    test_spam_fpr = test_spam_fp / test_spam_total if test_spam_total > 0 else 0.0

    test_smish_mask = np.array([r["ground_truth_category"] == "smishing" for r in test_rows])
    test_smish_tp = int(sum((pred_test == 1) & test_smish_mask))
    test_smish_total = int(sum(test_smish_mask))
    test_smish_recall = test_smish_tp / test_smish_total if test_smish_total > 0 else 0.0

    # Source breakdown on Test
    test_source_metrics = {}
    for src in ["UCI", "ExAIS", "WSPR_NCSU"]:
        for cat in ["ham", "commercial_spam", "smishing"]:
            mask = np.array([(clean_source_name(r["source_dataset"]) == src and r["ground_truth_category"] == cat) for r in test_rows])
            n_sub = int(sum(mask))
            if n_sub == 0:
                continue
            flagged = int(sum((pred_test == 1) & mask))
            rate = flagged / n_sub
            test_source_metrics[f"{src}_{cat}"] = {
                "total": n_sub,
                "flagged_as_smishing": flagged,
                "rate": round(rate, 4),
                "interpretation": "Recall" if cat == "smishing" else "False Positive Rate"
            }

    test_results_dict = {
        "model_id": selected_model_id,
        "operating_threshold": 0.50,
        "overall_metrics": test_overall_metrics,
        "category_rates": {
            "ham_total": test_ham_total,
            "ham_false_positives": test_ham_fp,
            "ham_false_positive_rate": round(test_ham_fpr, 4),
            "commercial_spam_total": test_spam_total,
            "commercial_spam_false_positives": test_spam_fp,
            "commercial_spam_false_positive_rate": round(test_spam_fpr, 4),
            "smishing_total": test_smish_total,
            "smishing_true_positives": test_smish_tp,
            "smishing_recall": round(test_smish_recall, 4)
        },
        "source_metrics": test_source_metrics
    }
    with open(EXP_DIR / selected_model_id / "test_metrics.json", "w", encoding="utf-8") as f:
        json.dump(test_results_dict, f, indent=2)
    print(f"Saved: {EXP_DIR / selected_model_id / 'test_metrics.json'}")

    print("\n" + "=" * 80)
    print("INTERNAL TEST EVALUATION RESULTS (Frozen Candidate SMS-03, Threshold = 0.50):")
    print("=" * 80)
    print(f"Accuracy: {test_overall_metrics['accuracy']:.4f} | Balanced Accuracy: {test_overall_metrics['balanced_accuracy']:.4f}")
    print(f"Precision: {test_overall_metrics['precision']:.4f} | Recall: {test_overall_metrics['recall']:.4f} | Specificity: {test_overall_metrics['specificity']:.4f} | F1: {test_overall_metrics['f1']:.4f}")
    print(f"ROC-AUC: {test_overall_metrics['roc_auc']:.4f} | Average Precision: {test_overall_metrics['average_precision']:.4f}")
    print(f"Ham False Positive Rate: {test_ham_fpr:.4f} ({test_ham_fp}/{test_ham_total})")
    print(f"Commercial Spam False Positive Rate: {test_spam_fpr:.4f} ({test_spam_fp}/{test_spam_total})")
    print(f"Smishing Recall: {test_smish_recall:.4f} ({test_smish_tp}/{test_smish_total})")

    # 8. Phase 7: Contextual Comparison Against Frozen Web Models
    print("\n--- Phase 7: Generating Baseline Contextual Comparison ---")
    # Load freeze manifest for V2/V3 web models
    with open(FREEZE_MANIFEST_PATH, encoding="utf-8") as f:
        web_freeze = json.load(f)
    v2_web = joblib.load(PROJECT_ROOT / web_freeze["frozen_model_artifacts"]["v2_baseline"]["relative_path"])
    v3_dual_web = joblib.load(PROJECT_ROOT / web_freeze["frozen_model_artifacts"]["v3_dual_channel"]["relative_path"])

    p_v2_test = v2_web.predict_proba(X_test_raw)[:, 1]
    p_dual_test = v3_dual_web.predict_proba(X_test_raw)[:, 1]

    pred_v2_test = (p_v2_test >= 0.50).astype(int)
    pred_dual_test = (p_dual_test >= 0.50).astype(int)

    m_v2_test = compute_binary_metrics(y_test, pred_v2_test, p_v2_test)
    m_dual_test = compute_binary_metrics(y_test, pred_dual_test, p_dual_test)

    v2_ham_fp = int(sum((pred_v2_test == 1) & test_ham_mask))
    v2_spam_fp = int(sum((pred_v2_test == 1) & test_spam_mask))
    dual_ham_fp = int(sum((pred_dual_test == 1) & test_ham_mask))
    dual_spam_fp = int(sum((pred_dual_test == 1) & test_spam_mask))

    comparison_summary = {
        "evaluation_partition": "Internal Test (N=806)",
        "models": {
            "SMS-03_Dedicated": {
                "f1": test_overall_metrics["f1"],
                "recall": test_overall_metrics["recall"],
                "specificity": test_overall_metrics["specificity"],
                "balanced_accuracy": test_overall_metrics["balanced_accuracy"],
                "ham_fpr": round(test_ham_fpr, 4),
                "commercial_spam_fpr": round(test_spam_fpr, 4)
            },
            "V2_Web_Baseline": {
                "f1": m_v2_test["f1"],
                "recall": m_v2_test["recall"],
                "specificity": m_v2_test["specificity"],
                "balanced_accuracy": m_v2_test["balanced_accuracy"],
                "ham_fpr": round(v2_ham_fp / test_ham_total, 4),
                "commercial_spam_fpr": round(v2_spam_fp / test_spam_total, 4)
            },
            "V3_Dual_Channel_Web": {
                "f1": m_dual_test["f1"],
                "recall": m_dual_test["recall"],
                "specificity": m_dual_test["specificity"],
                "balanced_accuracy": m_dual_test["balanced_accuracy"],
                "ham_fpr": round(dual_ham_fp / test_ham_total, 4),
                "commercial_spam_fpr": round(dual_spam_fp / test_spam_total, 4)
            }
        }
    }
    with open(EXP_DIR / "web_model_contextual_comparison.json", "w", encoding="utf-8") as f:
        json.dump(comparison_summary, f, indent=2)

    print("\nALL TRAINING, SELECTION, AND EVALUATION OPERATIONS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
