"""Local inference helpers for the separately trained phishing text model."""

from __future__ import annotations

import math
import sys
import warnings
from pathlib import Path
from typing import Any

MODEL_ID = "phishing-tfidf-logreg-domain-grouped-v1"
MODEL_THRESHOLD = 0.5
# The executed training notebook recorded scikit-learn 1.8.0. Keep inference
# aligned with that artifact; update this alongside any future model artifact.
MODEL_SKLEARN_VERSION = "1.8.0"
MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "models"
    / "text"
    / "phishing_tfidf_logreg_domain_grouped.joblib"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DISCLAIMER = (
    "This result is an uncalibrated model score, not proof that a message or "
    "website is malicious or safe. Review the message and its context."
)


class ModelLoadError(RuntimeError):
    """Raised when the persisted inference model is unavailable or incompatible."""


def load_phishing_model(path: Path = MODEL_PATH) -> Any:
    """Load and validate the persisted pipeline once during app startup."""

    if not path.is_file():
        raise ModelLoadError(f"Phishing model artifact is missing: {path}")

    try:
        import joblib
        import sklearn
        from sklearn.exceptions import InconsistentVersionWarning
    except Exception as exc:
        raise ModelLoadError(
            "Phishing model dependencies are unavailable; install the backend "
            "ML dependencies in the active environment."
        ) from exc

    if sklearn.__version__ != MODEL_SKLEARN_VERSION:
        raise ModelLoadError(
            "Phishing model requires scikit-learn "
            f"{MODEL_SKLEARN_VERSION}; the active environment has "
            f"{sklearn.__version__}."
        )

    try:
        # The serialized TF-IDF preprocessor references backend.ml.*. Ensure
        # that package is importable when Uvicorn is launched from backend/.
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
            raise ModelLoadError(
                "scikit-learn reported an incompatible serialized estimator: "
                + str(version_warnings[0].message)
            )
    except ModelLoadError:
        raise
    except Exception as exc:
        raise ModelLoadError(
            f"Could not load phishing model artifact {path}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    classes = getattr(model, "classes_", None)
    if not callable(getattr(model, "predict_proba", None)) or classes is None:
        raise ModelLoadError(
            "Phishing model must expose classes_ and predict_proba()."
        )
    if 1 not in classes or 0 not in classes:
        raise ModelLoadError(
            "Phishing model must contain both source classes 0 and 1."
        )
    return model


def classify_message(message: str, model: Any) -> dict[str, Any]:
    """Score one message using the saved pipeline's own preprocessing."""

    try:
        scores = model.predict_proba([message])
        classes = list(model.classes_)
        phishing_score = float(scores[0][classes.index(1)])
    except Exception as exc:
        raise RuntimeError("Phishing model could not score this message.") from exc

    if not math.isfinite(phishing_score) or not 0.0 <= phishing_score <= 1.0:
        raise RuntimeError("Phishing model returned an invalid class score.")

    return {
        "classification": "phishing" if phishing_score >= MODEL_THRESHOLD else "benign",
        "phishing_score": phishing_score,
        "score_kind": "uncalibrated_model_score",
        "threshold": MODEL_THRESHOLD,
        "model_id": MODEL_ID,
        "disclaimer": DISCLAIMER,
    }
