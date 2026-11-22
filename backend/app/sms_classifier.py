"""Local inference helpers for the separately trained SMS phishing model (SMS-05-C)."""

from __future__ import annotations

import math
import sys
import warnings
from pathlib import Path
from typing import Any

MODEL_ID = "sms-05-c-combined-v1"
MODEL_THRESHOLD = 0.50
MODEL_SKLEARN_VERSION = "1.8.0"
MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "models"
    / "sms"
    / "sms_05_model.joblib"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DISCLAIMER = (
    "This result is an uncalibrated experimental model score, not proof that a message "
    "is malicious or safe. Review the message and its context."
)


class SMSModelLoadError(RuntimeError):
    """Raised when the persisted SMS inference model is unavailable or incompatible."""


def load_sms_model(path: Path = MODEL_PATH) -> Any:
    """Load and validate the persisted SMS pipeline once during app startup."""

    if not path.is_file():
        raise SMSModelLoadError(f"SMS model artifact is missing: {path}")

    try:
        import joblib
        import sklearn
        from sklearn.exceptions import InconsistentVersionWarning
    except Exception as exc:
        raise SMSModelLoadError(
            "SMS model dependencies are unavailable; install the backend "
            "ML dependencies in the active environment."
        ) from exc

    if sklearn.__version__ != MODEL_SKLEARN_VERSION:
        raise SMSModelLoadError(
            "SMS model requires scikit-learn "
            f"{MODEL_SKLEARN_VERSION}; the active environment has "
            f"{sklearn.__version__}."
        )

    # Perform cryptographic artifact verification if using the canonical model path
    if path == MODEL_PATH:
        from app.model_integrity import verify_model_artifact_integrity
        try:
            verify_model_artifact_integrity(path, model_key="sms")
        except RuntimeError as exc:
            raise SMSModelLoadError(str(exc)) from exc

    try:
        if str(REPOSITORY_ROOT) not in sys.path:
            sys.path.insert(0, str(REPOSITORY_ROOT))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", InconsistentVersionWarning)
            model = joblib.load(path)
        version_warnings = [
            warning for warning in caught
            if issubclass(warning.category, InconsistentVersionWarning)
        ]
        if version_warnings:
            raise SMSModelLoadError(
                "scikit-learn reported an incompatible serialized estimator: "
                + str(version_warnings[0].message)
            )
    except SMSModelLoadError:
        raise
    except Exception as exc:
        raise SMSModelLoadError(
            f"Could not load SMS model artifact {path}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    classes = getattr(model, "classes_", None)
    if not callable(getattr(model, "predict_proba", None)) or classes is None:
        raise SMSModelLoadError(
            "SMS model must expose classes_ and predict_proba()."
        )
    if 1 not in classes or 0 not in classes:
        raise SMSModelLoadError(
            "SMS model must contain both target classes 0 and 1."
        )
    return model


def classify_sms_message(message: str, model: Any) -> dict[str, Any]:
    """Score one SMS message using the saved SMS-05-C pipeline."""

    try:
        scores = model.predict_proba([message])
        classes = list(model.classes_)
        smishing_score = float(scores[0][classes.index(1)])
    except Exception as exc:
        raise RuntimeError("SMS model could not score this message.") from exc

    if not math.isfinite(smishing_score) or not 0.0 <= smishing_score <= 1.0:
        raise RuntimeError("SMS model returned an invalid class score.")

    return {
        "classification": "smishing" if smishing_score >= MODEL_THRESHOLD else "not_smishing",
        "smishing_score": smishing_score,
        "score_kind": "uncalibrated_model_score",
        "threshold": MODEL_THRESHOLD,
        "model_id": MODEL_ID,
        "disclaimer": DISCLAIMER,
    }
