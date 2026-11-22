"""Loading and inference helpers for the prepared Android feature model."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import sys
import warnings
from pathlib import Path
from typing import Any, Mapping

ANDROID_MODEL_ID = "android-random-forest-grouped-sklearn-1.8.0-v1"
ANDROID_MODEL_SKLEARN_VERSION = "1.8.0"
ANDROID_FEATURE_COUNT = 226
ANDROID_THRESHOLD = 0.5
ANDROID_POSITIVE_CLASS = 1
ANDROID_MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "models"
    / "android"
    / "android_random_forest_grouped_sklearn_1_8_0.joblib"
)
ANDROID_CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "reports"
    / "ml"
    / "android_malware_sklearn_1_8_0"
    / "experiment_config.json"
)
ANDROID_DISCLAIMER = (
    "This result is based on Android permission and feature indicators and "
    "provisional dataset labels. It is an uncalibrated model score, not proof "
    "that an application is malicious or safe. This endpoint analyzes prepared "
    "feature values and does not scan APK files."
)


class AndroidModelLoadError(RuntimeError):
    """Raised when the Android model or its feature schema is unavailable."""


@dataclass(frozen=True)
class LoadedAndroidModel:
    """Model and its authoritative ordered feature schema."""

    pipeline: Any
    feature_columns: tuple[str, ...]
    threshold: float = ANDROID_THRESHOLD
    model_id: str = ANDROID_MODEL_ID


def validate_android_bundle(model: Any, config: Mapping[str, Any]) -> LoadedAndroidModel:
    """Validate model dimensions/classes against the saved configuration."""

    feature_columns = config.get("feature_columns")
    feature_count = config.get("feature_count")
    if not isinstance(feature_columns, list) or len(feature_columns) != ANDROID_FEATURE_COUNT:
        raise AndroidModelLoadError(
            f"Android feature schema must contain exactly {ANDROID_FEATURE_COUNT} names."
        )
    if any(not isinstance(name, str) or not name for name in feature_columns):
        raise AndroidModelLoadError("Android feature schema contains an invalid name.")
    if len(set(feature_columns)) != ANDROID_FEATURE_COUNT:
        raise AndroidModelLoadError("Android feature schema contains duplicate names.")
    if type(feature_count) is not int or feature_count != len(feature_columns):
        raise AndroidModelLoadError(
            "Android feature_count does not match the saved feature_columns list."
        )

    threshold = config.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise AndroidModelLoadError("Android model threshold is missing or invalid.")
    if float(threshold) != ANDROID_THRESHOLD:
        raise AndroidModelLoadError(
            f"Android model configuration must use threshold {ANDROID_THRESHOLD}."
        )

    steps = getattr(model, "named_steps", None)
    if not isinstance(steps, Mapping) or set(steps) != {"classifier"}:
        raise AndroidModelLoadError(
            "Android artifact must be a pipeline with one step named 'classifier'."
        )
    classifier = steps["classifier"]
    model_feature_count = getattr(classifier, "n_features_in_", None)
    if model_feature_count != len(feature_columns):
        raise AndroidModelLoadError(
            "Android model feature dimension does not match the saved schema "
            f"({model_feature_count!r} != {len(feature_columns)})."
        )
    pipeline_feature_count = getattr(model, "n_features_in_", model_feature_count)
    if pipeline_feature_count != len(feature_columns):
        raise AndroidModelLoadError(
            "Android pipeline feature dimension does not match the saved schema "
            f"({pipeline_feature_count!r} != {len(feature_columns)})."
        )

    classes = getattr(model, "classes_", getattr(classifier, "classes_", None))
    if classes is None or ANDROID_POSITIVE_CLASS not in classes:
        raise AndroidModelLoadError(
            f"Android model must contain positive class {ANDROID_POSITIVE_CLASS}."
        )
    if 0 not in classes:
        raise AndroidModelLoadError("Android model must contain class 0 as well as class 1.")

    return LoadedAndroidModel(
        pipeline=model,
        feature_columns=tuple(feature_columns),
        threshold=float(threshold),
    )


def load_android_model(
    model_path: Path = ANDROID_MODEL_PATH,
    config_path: Path = ANDROID_CONFIG_PATH,
) -> LoadedAndroidModel:
    """Load and validate the persisted model once during application startup."""

    if not model_path.is_file():
        raise AndroidModelLoadError(f"Android model artifact is missing: {model_path}")
    if not config_path.is_file():
        raise AndroidModelLoadError(f"Android experiment configuration is missing: {config_path}")

    try:
        import joblib
        import sklearn
        from sklearn.exceptions import InconsistentVersionWarning
    except Exception as exc:
        raise AndroidModelLoadError(
            "Android model dependencies are unavailable in the active environment."
        ) from exc

    if sklearn.__version__ != ANDROID_MODEL_SKLEARN_VERSION:
        raise AndroidModelLoadError(
            "Android model requires scikit-learn "
            f"{ANDROID_MODEL_SKLEARN_VERSION}; the active environment has "
            f"{sklearn.__version__}."
        )

    # Perform cryptographic artifact verification if using the canonical model path
    if model_path == ANDROID_MODEL_PATH:
        from app.model_integrity import verify_model_artifact_integrity
        try:
            verify_model_artifact_integrity(model_path, model_key="android")
        except RuntimeError as exc:
            raise AndroidModelLoadError(str(exc)) from exc

    repository_root = Path(__file__).resolve().parents[2]
    if str(repository_root) not in sys.path:
        sys.path.insert(0, str(repository_root))

    try:
        with config_path.open(encoding="utf-8") as stream:
            config = json.load(stream)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", InconsistentVersionWarning)
            model = joblib.load(model_path)
        incompatible = [
            warning for warning in caught
            if issubclass(warning.category, InconsistentVersionWarning)
        ]
        if incompatible:
            raise AndroidModelLoadError(
                "scikit-learn reported an incompatible Android estimator: "
                + str(incompatible[0].message)
            )
        return validate_android_bundle(model, config)
    except AndroidModelLoadError:
        raise
    except Exception as exc:
        raise AndroidModelLoadError(
            "Could not load Android model/configuration: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def classify_android_features(
    features: Mapping[str, int], loaded: LoadedAndroidModel
) -> dict[str, Any]:
    """Order a validated feature mapping and score class 1 without training."""

    expected = set(loaded.feature_columns)
    supplied = set(features)
    if supplied != expected:
        raise ValueError("Android feature names do not match the loaded model schema.")
    for name, value in features.items():
        if type(value) is not int or value not in (0, 1):
            raise ValueError(f"Android feature {name!r} must be integer 0 or 1.")

    try:
        import numpy as np

        row = np.asarray(
            [[features[name] for name in loaded.feature_columns]], dtype=np.uint8
        )
        classes = list(loaded.pipeline.classes_)
        probabilities = loaded.pipeline.predict_proba(row)
        score = float(probabilities[0][classes.index(ANDROID_POSITIVE_CLASS)])
    except Exception as exc:
        raise RuntimeError("Android model could not score the supplied features.") from exc

    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise RuntimeError("Android model returned an invalid class score.")

    return {
        "classification": "malicious" if score >= loaded.threshold else "non_malicious",
        "malware_score": score,
        "score_kind": "uncalibrated_model_score",
        "threshold": loaded.threshold,
        "model_id": loaded.model_id,
        "disclaimer": ANDROID_DISCLAIMER,
    }
