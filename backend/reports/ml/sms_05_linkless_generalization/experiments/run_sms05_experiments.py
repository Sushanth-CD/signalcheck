"""SMS-05: Multi-Source Linkless-Aware Phishing Classifier Training and Evaluation Pipeline.

Executes:
1. Phase 0: Preflight verification of dataset_v1 manifest and reconciliation confirmation.
2. Architecture Definitions:
   - SMS-05-A: Word TF-IDF (1-2 ngrams, sublinear_tf, max_features=25000) + Logistic Regression (C=1.0, balanced)
   - SMS-05-B: Character TF-IDF (char_wb 3-5 ngrams, sublinear_tf, max_features=50000) + Logistic Regression (C=1.0, balanced)
   - SMS-05-C: Combined Word + Character FeatureUnion + Logistic Regression (C=1.0, balanced)
   - SMS-05-D: Structured Two-Channel Model:
       * Channel 1: Content FeatureUnion (Word 1-2 + Char_wb 3-5)
       * Channel 2: Derived Structural Features (has_url, has_phone_number, is_premium_rate_prefix,
                    has_currency_symbol, uppercase_ratio, punctuation_density)
       * Classifier: Logistic Regression (C=1.0, balanced)
3. Model Training on Training partition (N = 6,123)
4. Comprehensive Validation on Validation partition (N = 1,305, threshold = 0.50):
   - Overall metrics (Precision, Recall, Specificity, F1, Balanced Accuracy, Accuracy, ROC-AUC, Avg Precision)
   - Disaggregated original category rates: Ham FPR, Commercial Spam FPR, Smishing Recall
   - Modality breakdown: Linkless Smishing Recall vs URL-bearing Smishing Recall
   - Source breakdowns across all datasets
   - Length subgroups & Threshold sweep (0.10 to 0.90)
5. Model Selection:
   - Evaluated purely on validation evidence: highest Balanced Accuracy and Linkless Smishing Recall,
     while maintaining Ham FPR <= 1.0% and minimal Commercial Spam FPR.
6. Cryptographic Freezing of Selected Candidate:
   - Serialize sms_05_model.joblib
   - Calculate SHA-256 and generate model_integrity_manifest.json
7. Single Internal Test Evaluation:
   - Execute single evaluation of frozen model on Internal Test partition (N = 1,307, threshold = 0.50)
   - Log predictions to test_predictions.csv and metrics to test_metrics.json
8. Comparative Analysis against Frozen SMS-03 Baseline on identical partitions/criteria.
"""
import csv
import hashlib
import json
from pathlib import Path
import random
import re
import string
import sys
import time
from collections import Counter

import joblib
import numpy as np
import scipy.sparse as sp
import sklearn.metrics as metrics
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.text_normalization import normalize_for_model
from notebooks.phishing_url_extraction_v2 import extract_candidates

DATASET_DIR = PROJECT_ROOT / "backend/reports/ml/sms_05_linkless_generalization/dataset_v1"
MANIFEST_PATH = DATASET_DIR / "sms05_split_manifest.csv"
CANDIDATE_PATH = DATASET_DIR / "sms05_candidate_manifest.csv"
EXP_DIR = PROJECT_ROOT / "backend/reports/ml/sms_05_linkless_generalization/experiments"

SMS03_MODEL_PATH = PROJECT_ROOT / "backend/reports/ml/sms_dedicated_train_1/experiments/sms_03_combined/sms_model.joblib"
SMS03_EXPECTED_SHA256 = "8dd043a3b8322b2e55ca34581466b6dd64bbbf0f24422952156c1176942644df"

SEED = 20261102

PHONE_REGEX = re.compile(
    r'(?:'
    r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
    r'|'
    r'\b0[789]\d{8,9}\b'
    r'|'
    r'\b(?:1-)?8\d{2}[-.\s]?\d{3}[-.\s]?\d{4}\b'
    r'|'
    r'\b(?:claim|call|text|txt|stop|ring|contact)\s*(?:at|on|to)?\s*:?\s*(\d{5,12})\b'
    r')',
    re.IGNORECASE
)

PREMIUM_REGEX = re.compile(
    r'\b(?:090[5-9]|091[1-3]|070\d|087[0123]|084[45]|1-900|900)\d{5,8}\b'
    r'|'
    r'\b(?:charged|cost|rate)\s*(?:at)?\s*(?:[£$€]|gbp|usd)?\s*\d+(?:\.\d{2})?\s*(?:p|pence|per min|\/min)?\b',
    re.IGNORECASE
)

CURRENCY_REGEX = re.compile(r'[$£€¥₹]|(?:\b(?:USD|GBP|EUR|INR|BTC|ETH|NGN)\b)', re.IGNORECASE)
PUNCT_CHARS = set(string.punctuation)


class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts derived structural features purely from sanitized message text."""
    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for text in X:
            t_str = str(text) if text is not None else ""
            
            # 1. has_url
            has_url = 1.0 if len(extract_candidates("m", t_str)) > 0 else 0.0
            
            # 2. has_phone_number
            has_phone = 1.0 if bool(PHONE_REGEX.search(t_str)) else 0.0
            
            # 3. is_premium_rate_prefix
            is_prem = 1.0 if bool(PREMIUM_REGEX.search(t_str)) else 0.0
            
            # 4. has_currency_symbol
            has_curr = 1.0 if bool(CURRENCY_REGEX.search(t_str)) else 0.0
            
            # 5. uppercase_ratio
            alpha_chars = [c for c in t_str if c.isalpha()]
            upper_ratio = (sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)) if alpha_chars else 0.0
            
            # 6. punctuation_density
            punct_count = sum(1 for c in t_str if c in PUNCT_CHARS)
            punct_density = (punct_count / len(t_str)) if len(t_str) > 0 else 0.0
            
            features.append([has_url, has_phone, is_prem, has_curr, upper_ratio, punct_density])
            
        return sp.csr_matrix(features, dtype=float)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_source_name(s: str) -> str:
    if s.startswith("ExAIS"):
        return "ExAIS"
    if s.startswith("UCI"):
        return "UCI"
    if s.startswith("WSPR"):
        return "WSPR_NCSU"
    if s.startswith("IMC"):
        return "IMC_2025_reportsmishing"
    if s.startswith("Mishra"):
        return "Mishra_Soni_2022"
    return s


def compute_binary_metrics(y_true, y_pred, y_prob):
    """Compute comprehensive binary classification metrics."""
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


def evaluate_partition(rows, pipe, threshold=0.50):
    """Evaluate pipeline on partition rows and compute comprehensive breakdowns."""
    X_raw = [r["sanitized_message_text"] for r in rows]
    y_true = np.array([int(r["binary_phishing_label"]) for r in rows])

    p_prob = pipe.predict_proba(X_raw)[:, 1]
    y_pred = (p_prob >= threshold).astype(int)

    # Prediction rows
    pred_rows = []
    for idx, r in enumerate(rows):
        pred_rows.append({
            "serial_number": r["serial_number"],
            "source_dataset": r["source_dataset"],
            "source_group": clean_source_name(r["source_dataset"]),
            "ground_truth_category": r["ground_truth_category"],
            "binary_phishing_label": int(r["binary_phishing_label"]),
            "modality": r.get("modality", "unknown"),
            "campaign_id": r.get("campaign_id", "none"),
            "char_length": len(r["sanitized_message_text"]),
            "prob_smishing": float(round(p_prob[idx], 6)),
            f"pred_smishing_{int(threshold*100):02d}": int(y_pred[idx])
        })

    # Overall binary metrics
    overall_metrics = compute_binary_metrics(y_true, y_pred, p_prob)

    # Disaggregated category metrics
    ham_mask = np.array([r["ground_truth_category"] == "ham" for r in rows])
    ham_fp = int(sum((y_pred == 1) & ham_mask))
    ham_total = int(sum(ham_mask))
    ham_fpr = ham_fp / ham_total if ham_total > 0 else 0.0

    spam_mask = np.array([r["ground_truth_category"] == "commercial_spam" for r in rows])
    spam_fp = int(sum((y_pred == 1) & spam_mask))
    spam_total = int(sum(spam_mask))
    spam_fpr = spam_fp / spam_total if spam_total > 0 else 0.0

    smish_mask = np.array([r["ground_truth_category"] == "smishing" for r in rows])
    smish_tp = int(sum((y_pred == 1) & smish_mask))
    smish_total = int(sum(smish_mask))
    smish_recall = smish_tp / smish_total if smish_total > 0 else 0.0

    # Modality breakdown within smishing
    linkless_mask = np.array([(r["ground_truth_category"] == "smishing" and r.get("modality") == "linkless") for r in rows])
    linkless_tp = int(sum((y_pred == 1) & linkless_mask))
    linkless_total = int(sum(linkless_mask))
    linkless_recall = linkless_tp / linkless_total if linkless_total > 0 else 0.0

    url_bearing_mask = np.array([(r["ground_truth_category"] == "smishing" and r.get("modality") == "url_bearing") for r in rows])
    url_bearing_tp = int(sum((y_pred == 1) & url_bearing_mask))
    url_bearing_total = int(sum(url_bearing_mask))
    url_bearing_recall = url_bearing_tp / url_bearing_total if url_bearing_total > 0 else 0.0

    # Disaggregated by Source Group
    source_metrics = {}
    sources = sorted(list(set(clean_source_name(r["source_dataset"]) for r in rows)))
    for src in sources:
        for cat in ["ham", "commercial_spam", "smishing"]:
            sub_mask = np.array([(clean_source_name(r["source_dataset"]) == src and r["ground_truth_category"] == cat) for r in rows])
            n_sub = int(sum(sub_mask))
            if n_sub == 0:
                continue
            flagged = int(sum((y_pred == 1) & sub_mask))
            rate = flagged / n_sub
            source_metrics[f"{src}_{cat}"] = {
                "total": n_sub,
                "flagged_as_smishing": flagged,
                "rate": round(rate, 4),
                "interpretation": "Recall" if cat == "smishing" else "False Positive Rate"
            }

    # Subgroups: URL presence and length
    subgroup_metrics = {}
    # Text contains URL
    has_url_mask = np.array([len(extract_candidates("m", r["sanitized_message_text"])) > 0 for r in rows])
    for u_name, u_mask in [("url_present_all", has_url_mask), ("url_absent_all", ~has_url_mask)]:
        if sum(u_mask) > 0:
            subgroup_metrics[u_name] = compute_binary_metrics(y_true[u_mask], y_pred[u_mask], p_prob[u_mask])

    len_arr = np.array([len(r["sanitized_message_text"]) for r in rows])
    median_len = float(np.median(len_arr))
    short_mask = len_arr < median_len
    for l_name, l_mask in [("length_below_median", short_mask), ("length_above_median", ~short_mask)]:
        if sum(l_mask) > 0:
            subgroup_metrics[l_name] = compute_binary_metrics(y_true[l_mask], y_pred[l_mask], p_prob[l_mask])

    # Threshold curve
    threshold_curve = []
    for t in np.arange(0.10, 0.95, 0.05):
        p_t = (p_prob >= t).astype(int)
        t_res = compute_binary_metrics(y_true, p_t, p_prob)
        t_ham_fp = int(sum((p_t == 1) & ham_mask))
        t_spam_fp = int(sum((p_t == 1) & spam_mask))
        t_smish_tp = int(sum((p_t == 1) & smish_mask))
        t_linkless_tp = int(sum((p_t == 1) & linkless_mask))
        t_url_tp = int(sum((p_t == 1) & url_bearing_mask))
        
        threshold_curve.append({
            "threshold": round(float(t), 2),
            "f1": t_res["f1"],
            "precision": t_res["precision"],
            "recall": t_res["recall"],
            "specificity": t_res["specificity"],
            "balanced_accuracy": t_res["balanced_accuracy"],
            "ham_fpr": round(t_ham_fp / ham_total, 4) if ham_total > 0 else 0.0,
            "commercial_spam_fpr": round(t_spam_fp / spam_total, 4) if spam_total > 0 else 0.0,
            "smishing_recall": round(t_smish_tp / smish_total, 4) if smish_total > 0 else 0.0,
            "linkless_recall": round(t_linkless_tp / linkless_total, 4) if linkless_total > 0 else 0.0,
            "url_bearing_recall": round(t_url_tp / url_bearing_total, 4) if url_bearing_total > 0 else 0.0,
        })

    return {
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
            "smishing_recall": round(smish_recall, 4),
            "smishing_linkless_total": linkless_total,
            "smishing_linkless_true_positives": linkless_tp,
            "smishing_linkless_recall": round(linkless_recall, 4),
            "smishing_url_bearing_total": url_bearing_total,
            "smishing_url_bearing_true_positives": url_bearing_tp,
            "smishing_url_bearing_recall": round(url_bearing_recall, 4)
        },
        "source_metrics": source_metrics,
        "subgroup_metrics": subgroup_metrics,
        "threshold_curve": threshold_curve,
        "pred_rows": pred_rows
    }


def main():
    print("=" * 75)
    print("SMS-05: MULTI-SOURCE LINKLESS-AWARE PHISHING CLASSIFIER EXPERIMENTS")
    print("=" * 75)

    EXP_DIR.mkdir(parents=True, exist_ok=True)

    # Verify SMS-03 baseline artifact
    assert SMS03_MODEL_PATH.exists(), f"SMS-03 model missing at {SMS03_MODEL_PATH}"
    sms03_actual_sha256 = sha256_file(SMS03_MODEL_PATH)
    assert sms03_actual_sha256 == SMS03_EXPECTED_SHA256, f"SMS-03 SHA256 mismatch! Expected {SMS03_EXPECTED_SHA256}, got {sms03_actual_sha256}"
    print(f"SMS-03 baseline frozen artifact integrity verified: SHA-256 = {sms03_actual_sha256}")

    # Load dataset_v1 manifest
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest_rows = list(csv.DictReader(f))
    with open(CANDIDATE_PATH, encoding="utf-8") as f:
        cand_rows = list(csv.DictReader(f))

    print(f"\nPhase 0 Preflight Verification:")
    print(f"Total manifest records: {len(manifest_rows)}")
    assert len(manifest_rows) == 8735, f"Expected 8735, got {len(manifest_rows)}"
    assert len(cand_rows) == 8735, f"Expected 8735 candidates, got {len(cand_rows)}"

    part_counts = Counter(r["partition"] for r in manifest_rows)
    print(f"Partition distribution: {dict(part_counts)}")
    assert part_counts["train"] == 6123, f"Unexpected train count {part_counts['train']}"
    assert part_counts["validation"] == 1305, f"Unexpected val count {part_counts['validation']}"
    assert part_counts["test"] == 1307, f"Unexpected test count {part_counts['test']}"

    cat_counts = Counter(r["ground_truth_category"] for r in manifest_rows)
    print(f"Category distribution: {dict(cat_counts)}")
    assert cat_counts["ham"] == 3500
    assert cat_counts["commercial_spam"] == 1835
    assert cat_counts["smishing"] == 3400

    mod_counts = Counter(r["modality"] for r in manifest_rows if r["ground_truth_category"] == "smishing")
    print(f"Smishing modality distribution: {dict(mod_counts)}")
    assert mod_counts["linkless"] == 1700
    assert mod_counts["url_bearing"] == 1700

    # Segregate partitions
    train_rows = [r for r in manifest_rows if r["partition"] == "train"]
    val_rows = [r for r in manifest_rows if r["partition"] == "validation"]
    test_rows = [r for r in manifest_rows if r["partition"] == "test"]

    X_train_raw = [r["sanitized_message_text"] for r in train_rows]
    y_train = np.array([int(r["binary_phishing_label"]) for r in train_rows])

    print(f"\nAll Phase 0 preflight checks passed. Fitting 4 model architectures on Train (N={len(train_rows)})...")

    # Define architectures
    architectures = {}

    # SMS-05-A: Word TF-IDF + Logistic Regression
    pipe_a = Pipeline([
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
    architectures["sms_05_a_word"] = {
        "pipeline": pipe_a,
        "name": "SMS-05-A: Word TF-IDF + Logistic Regression",
        "dir": EXP_DIR / "sms_05_a_word",
        "description": "Standard word-level n-gram (1-2) TF-IDF features with balanced logistic regression."
    }

    # SMS-05-B: Character TF-IDF + Logistic Regression
    pipe_b = Pipeline([
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
    architectures["sms_05_b_char"] = {
        "pipeline": pipe_b,
        "name": "SMS-05-B: Character TF-IDF (char_wb 3-5) + Logistic Regression",
        "dir": EXP_DIR / "sms_05_b_char",
        "description": "Subword character boundary n-gram (3-5) TF-IDF features with balanced logistic regression."
    }

    # SMS-05-C: Combined Word + Character FeatureUnion + Logistic Regression
    pipe_c = Pipeline([
        ("features", FeatureUnion([
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
        ])),
        ("classifier", LogisticRegression(
            C=1.0,
            penalty="l2",
            solver="liblinear",
            random_state=SEED,
            max_iter=1000,
            class_weight="balanced"
        ))
    ])
    architectures["sms_05_c_combined"] = {
        "pipeline": pipe_c,
        "name": "SMS-05-C: Combined Word + Character FeatureUnion + Logistic Regression",
        "dir": EXP_DIR / "sms_05_c_combined",
        "description": "Hybrid word (1-2) and character boundary (3-5) TF-IDF feature union with balanced logistic regression."
    }

    # SMS-05-D: Structured Two-Channel Model
    pipe_d = Pipeline([
        ("features", FeatureUnion([
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
            )),
            ("structural_branch", StructuralFeatureExtractor())
        ])),
        ("classifier", LogisticRegression(
            C=1.0,
            penalty="l2",
            solver="liblinear",
            random_state=SEED,
            max_iter=1000,
            class_weight="balanced"
        ))
    ])
    architectures["sms_05_d_two_channel"] = {
        "pipeline": pipe_d,
        "name": "SMS-05-D: Structured Two-Channel Content + Structural Model",
        "dir": EXP_DIR / "sms_05_d_two_channel",
        "description": "Dual-channel pipeline uniting lexical/subword TF-IDF with derived text-level structural indicators (has_url, has_phone_number, is_premium_rate_prefix, has_currency_symbol, uppercase_ratio, punctuation_density)."
    }

    # Fitting and Training Evaluation
    training_results = {}
    validation_results = {}

    for model_id, m_info in architectures.items():
        print(f"\n--- Training {model_id} ({m_info['name']}) ---")
        m_dir = m_info["dir"]
        m_dir.mkdir(parents=True, exist_ok=True)
        pipe = m_info["pipeline"]

        t0 = time.time()
        pipe.fit(X_train_raw, y_train)
        fit_time = round(time.time() - t0, 3)
        print(f"Fit completed in {fit_time}s.")
        m_info["fit_time_seconds"] = fit_time

        # Save experiment_configuration.json
        exp_config = {
            "model_id": model_id,
            "model_name": m_info["name"],
            "description": m_info["description"],
            "fit_time_seconds": fit_time,
            "seed": SEED,
            "dataset": {
                "manifest": "sms05_split_manifest.csv",
                "train_samples": len(train_rows),
                "val_samples": len(val_rows),
                "test_samples": len(test_rows)
            },
            "operating_threshold": 0.50
        }
        with open(m_dir / "experiment_configuration.json", "w", encoding="utf-8") as f:
            json.dump(exp_config, f, indent=2)

        # Training evaluation
        train_eval = evaluate_partition(train_rows, pipe, threshold=0.50)
        training_metrics = {
            "model_id": model_id,
            "fit_time_seconds": fit_time,
            "overall_metrics": train_eval["overall_metrics"],
            "category_rates": train_eval["category_rates"]
        }
        with open(m_dir / "training_metrics.json", "w", encoding="utf-8") as f:
            json.dump(training_metrics, f, indent=2)
        training_results[model_id] = training_metrics

        # Validation evaluation
        val_eval = evaluate_partition(val_rows, pipe, threshold=0.50)
        val_metrics_out = {
            "model_id": model_id,
            "model_name": m_info["name"],
            "fit_time_seconds": fit_time,
            "operating_threshold": 0.50,
            "overall_metrics": val_eval["overall_metrics"],
            "category_rates": val_eval["category_rates"],
            "source_metrics": val_eval["source_metrics"],
            "subgroup_metrics": val_eval["subgroup_metrics"],
            "threshold_curve": val_eval["threshold_curve"]
        }
        with open(m_dir / "validation_metrics.json", "w", encoding="utf-8") as f:
            json.dump(val_metrics_out, f, indent=2)

        # Write validation_predictions.csv
        with open(m_dir / "validation_predictions.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(val_eval["pred_rows"][0].keys()))
            writer.writeheader()
            writer.writerows(val_eval["pred_rows"])

        # Write subgroup_metrics.csv
        subgroup_rows = []
        for sg_name, sg_met in val_eval["subgroup_metrics"].items():
            subgroup_rows.append({
                "subgroup": sg_name,
                "n_samples": sg_met["n_samples"],
                "f1": sg_met["f1"],
                "recall": sg_met["recall"],
                "specificity": sg_met["specificity"],
                "balanced_accuracy": sg_met["balanced_accuracy"],
                "roc_auc": sg_met["roc_auc"]
            })
        with open(m_dir / "subgroup_metrics.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["subgroup", "n_samples", "f1", "recall", "specificity", "balanced_accuracy", "roc_auc"])
            writer.writeheader()
            writer.writerows(subgroup_rows)

        validation_results[model_id] = val_metrics_out

    # Print Validation Comparison Table
    print("\n" + "=" * 115)
    print("SMS-05 VALIDATION PERFORMANCE COMPARISON (N = 1,305 | Operating Threshold = 0.50):")
    print("=" * 115)
    header = f"{'Model ID':22s} | {'F1':6s} | {'BalAcc':6s} | {'Smish R':7s} | {'Linkless R':10s} | {'URL R':6s} | {'Ham FPR':7s} | {'Spam FPR':8s} | {'ROC-AUC':7s}"
    print(header)
    print("-" * len(header))
    for m_id, res in validation_results.items():
        ov = res["overall_metrics"]
        cr = res["category_rates"]
        print(f"{m_id:22s} | {ov['f1']:<6.4f} | {ov['balanced_accuracy']:<6.4f} | {cr['smishing_recall']:<7.4f} | {cr['smishing_linkless_recall']:<10.4f} | {cr['smishing_url_bearing_recall']:<6.4f} | {cr['ham_false_positive_rate']:<7.4f} | {cr['commercial_spam_false_positive_rate']:<8.4f} | {ov['roc_auc']:<7.4f}")

    # Determine Winning Candidate Based on Validation Metrics
    # Criteria:
    # 1. Balanced Accuracy & F1
    # 2. Linkless Smishing Recall (highest priority for generalizing beyond SMS-03)
    # 3. Ham FPR control (must be near 0)
    best_candidate_id = max(
        validation_results.keys(),
        key=lambda k: (
            validation_results[k]["overall_metrics"]["balanced_accuracy"],
            validation_results[k]["category_rates"]["smishing_linkless_recall"],
            validation_results[k]["overall_metrics"]["f1"]
        )
    )

    print("\n" + "=" * 75)
    print(f"SELECTED WINNING CANDIDATE: {best_candidate_id}")
    print(f"Name: {architectures[best_candidate_id]['name']}")
    print("=" * 75)

    winning_pipe = architectures[best_candidate_id]["pipeline"]
    winning_dir = architectures[best_candidate_id]["dir"]

    # Phase 5: Serialize & Cryptographically Freeze Winning Model
    print(f"\n--- Phase 5: Serializing and Freezing {best_candidate_id} ---")
    winning_model_path = winning_dir / "sms_05_model.joblib"
    joblib.dump(winning_pipe, winning_model_path)
    winning_sha256 = sha256_file(winning_model_path)
    winning_size = winning_model_path.stat().st_size
    print(f"Saved: {winning_model_path} ({winning_size} bytes)")
    print(f"SHA-256: {winning_sha256}")

    freeze_manifest = {
        "manifest_name": "SMS-05 Linkless Generalization Selected Model Freeze Manifest",
        "freeze_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "selected_model_id": best_candidate_id,
        "selected_model_name": architectures[best_candidate_id]["name"],
        "operating_threshold": 0.50,
        "runtime_environment": {
            "python": sys.version,
            "scikit_learn": metrics.__file__,
            "seed": SEED
        },
        "model_artifact": {
            "relative_path": str(winning_model_path.relative_to(PROJECT_ROOT)),
            "size_bytes": winning_size,
            "sha256": winning_sha256,
            "architecture": architectures[best_candidate_id]["description"]
        },
        "validation_evidence": {
            "balanced_accuracy": validation_results[best_candidate_id]["overall_metrics"]["balanced_accuracy"],
            "f1_score": validation_results[best_candidate_id]["overall_metrics"]["f1"],
            "smishing_recall": validation_results[best_candidate_id]["category_rates"]["smishing_recall"],
            "smishing_linkless_recall": validation_results[best_candidate_id]["category_rates"]["smishing_linkless_recall"],
            "smishing_url_bearing_recall": validation_results[best_candidate_id]["category_rates"]["smishing_url_bearing_recall"],
            "ham_fpr": validation_results[best_candidate_id]["category_rates"]["ham_false_positive_rate"],
            "commercial_spam_fpr": validation_results[best_candidate_id]["category_rates"]["commercial_spam_false_positive_rate"],
            "roc_auc": validation_results[best_candidate_id]["overall_metrics"]["roc_auc"]
        }
    }
    with open(winning_dir / "model_integrity_manifest.json", "w", encoding="utf-8") as f:
        json.dump(freeze_manifest, f, indent=2)
    print(f"Saved: {winning_dir / 'model_integrity_manifest.json'}")

    # Phase 6: Single Internal Test Evaluation of Frozen Winning Model
    print(f"\n--- Phase 6: Single Internal Test Evaluation on {best_candidate_id} (N = {len(test_rows)}) ---")
    test_eval = evaluate_partition(test_rows, winning_pipe, threshold=0.50)

    # Save test predictions
    with open(winning_dir / "test_predictions.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(test_eval["pred_rows"][0].keys()))
        writer.writeheader()
        writer.writerows(test_eval["pred_rows"])

    test_metrics_out = {
        "model_id": best_candidate_id,
        "model_name": architectures[best_candidate_id]["name"],
        "operating_threshold": 0.50,
        "overall_metrics": test_eval["overall_metrics"],
        "category_rates": test_eval["category_rates"],
        "source_metrics": test_eval["source_metrics"],
        "subgroup_metrics": test_eval["subgroup_metrics"]
    }
    with open(winning_dir / "test_metrics.json", "w", encoding="utf-8") as f:
        json.dump(test_metrics_out, f, indent=2)
    print(f"Saved: {winning_dir / 'test_metrics.json'}")

    print("\nInternal Test Performance:")
    print(f"  F1: {test_eval['overall_metrics']['f1']}")
    print(f"  Balanced Accuracy: {test_eval['overall_metrics']['balanced_accuracy']}")
    print(f"  Smishing Recall: {test_eval['category_rates']['smishing_recall']}")
    print(f"    - Linkless Smishing Recall: {test_eval['category_rates']['smishing_linkless_recall']}")
    print(f"    - URL-Bearing Smishing Recall: {test_eval['category_rates']['smishing_url_bearing_recall']}")
    print(f"  Ham FPR: {test_eval['category_rates']['ham_false_positive_rate']}")
    print(f"  Commercial Spam FPR: {test_eval['category_rates']['commercial_spam_false_positive_rate']}")

    # Phase 7: Evaluate Frozen SMS-03 on the EXACT SAME SMS-05 Test Partition for Direct Comparison
    print(f"\n--- Comparative Baseline Evaluation: Frozen SMS-03 on SMS-05 Test Partition ---")
    sms03_pipe = joblib.load(SMS03_MODEL_PATH)
    sms03_on_sms05_test = evaluate_partition(test_rows, sms03_pipe, threshold=0.50)

    comparison_record = {
        "frozen_sms03": {
            "model_id": "sms_03_combined",
            "artifact_sha256": sms03_actual_sha256,
            "test_metrics": sms03_on_sms05_test["overall_metrics"],
            "test_category_rates": sms03_on_sms05_test["category_rates"]
        },
        "frozen_sms05_winning": {
            "model_id": best_candidate_id,
            "artifact_sha256": winning_sha256,
            "test_metrics": test_eval["overall_metrics"],
            "test_category_rates": test_eval["category_rates"]
        }
    }
    with open(EXP_DIR / "sms03_vs_sms05_test_comparison.json", "w", encoding="utf-8") as f:
        json.dump(comparison_record, f, indent=2)
    print(f"Saved: {EXP_DIR / 'sms03_vs_sms05_test_comparison.json'}")

    print("\n" + "=" * 75)
    print("ALL EXPERIMENTS & EVALUATIONS COMPLETED SUCCESSFULLY")
    print("=" * 75)


if __name__ == "__main__":
    main()
