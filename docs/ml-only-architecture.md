# ML-only application architecture

The active application exposes two local inference endpoints:

- `POST /api/ml/analyze` classifies submitted message text with the saved
  TF-IDF and Logistic Regression pipeline.
- `POST /api/ml/analyze-android` classifies a prepared map of exactly 226
  configured binary Android features with the saved Random Forest pipeline.

Both models load during FastAPI startup and are used as-is for inference.
Requests do not train models or make network calls. Each score is an
uncalibrated model score and is not proof that an input is malicious or safe.

The Android endpoint accepts prepared feature values only. APK upload and
automatic Android feature extraction are not implemented.

The former deterministic rule-analysis endpoint (`POST /api/analyze`) is no
longer part of the application. `docs/v1-analysis-contract.md` and
`detection_rules.md` remain as historical development documentation; their
rule definitions are not active runtime behavior.

The service does not claim real-world detection accuracy based on the
synthetic development data used to build and evaluate the models.
