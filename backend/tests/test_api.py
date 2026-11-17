"""FastAPI ML endpoint tests."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
import numpy as np
import pytest

from app.main import app
from app.android_classifier import (
    ANDROID_FEATURE_COUNT,
    AndroidModelLoadError,
    LoadedAndroidModel,
    classify_android_features,
    load_android_model,
    validate_android_bundle,
)
from app.ml_classifier import ModelLoadError, load_phishing_model


client = TestClient(app)


def test_health_endpoint_returns_success() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_cors_allows_configured_vite_origins() -> None:
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        response = client.options(
            "/api/ml/analyze",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
        assert "POST" in response.headers["access-control-allow-methods"]


def test_cors_rejects_unconfigured_origin() -> None:
    response = client.options(
        "/api/ml/analyze",
        headers={
            "Origin": "http://localhost:5174",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_cors_origins_configurable_via_env(monkeypatch) -> None:
    from app.main import get_configured_cors_origins

    monkeypatch.setenv("SIGNALCHECK_CORS_ORIGINS", "https://demo.example.com, http://127.0.0.1:4173")
    origins = get_configured_cors_origins()
    assert origins == ["https://demo.example.com", "http://127.0.0.1:4173"]

    # Rejection of wildcard and malformed entries
    monkeypatch.setenv("SIGNALCHECK_CORS_ORIGINS", "*, invalid-no-scheme, https://valid.com:8443")
    origins_sanitized = get_configured_cors_origins()
    assert origins_sanitized == ["https://valid.com:8443"]

    # Rejection of URL paths (other than optional root), query strings, fragments, and credentials
    monkeypatch.setenv(
        "SIGNALCHECK_CORS_ORIGINS",
        "https://evil.com/path, http://bad.com?token=123, http://frag.com#anchor, http://user:pass@steal.com, https://clean.example.org/"
    )
    strict_origins = get_configured_cors_origins()
    assert strict_origins == ["https://clean.example.org"]


def test_model_integrity_verification_scenarios(tmp_path) -> None:
    import hashlib
    from app.model_integrity import verify_model_artifact_integrity

    valid_content = b"valid serialized model test payload"
    valid_hash = hashlib.sha256(valid_content).hexdigest()
    valid_file = tmp_path / "valid_model.joblib"
    valid_file.write_bytes(valid_content)

    # 1. Matching valid digest
    verify_model_artifact_integrity(valid_file, expected_hash=valid_hash)

    # 2. Tampered / modified artifact
    tampered_file = tmp_path / "tampered_model.joblib"
    tampered_file.write_bytes(b"tampered content")
    with pytest.raises(RuntimeError, match="integrity verification failed"):
        verify_model_artifact_integrity(tampered_file, expected_hash=valid_hash)

    # 3. Missing model file
    missing_file = tmp_path / "non_existent.joblib"
    with pytest.raises(FileNotFoundError, match="not found"):
        verify_model_artifact_integrity(missing_file, expected_hash=valid_hash)

    # 4. Missing manifest key
    with pytest.raises(ValueError, match="No trusted integrity hash"):
        verify_model_artifact_integrity(valid_file, model_key="unregistered_model")

    # 5. Invalid digest format (not 64-char hex)
    with pytest.raises(ValueError, match="Invalid SHA-256 digest format"):
        verify_model_artifact_integrity(valid_file, expected_hash="too-short")

    with pytest.raises(ValueError, match="Invalid SHA-256 digest format"):
        verify_model_artifact_integrity(valid_file, expected_hash="g" * 64)


def test_http_security_headers_present() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in headers["permissions-policy"]
    assert "default-src 'self'" in headers["content-security-policy"]
    # HSTS should not be enabled on plain HTTP requests
    assert "strict-transport-security" not in headers


def test_rate_limiting_enforced_on_analysis_endpoint(monkeypatch) -> None:
    from app.main import limiter
    # Reset limiter storage state for clean test
    limiter.reset()

    # Set rate limit to 2 per minute for testing
    monkeypatch.setenv("SIGNALCHECK_RATE_LIMIT_ANALYZE", "2/minute")
    fake_model = FakePhishingModel()
    monkeypatch.setattr("app.main.load_phishing_model", lambda: fake_model)

    with TestClient(app) as test_client:
        # Request 1: OK
        r1 = test_client.post("/api/ml/analyze", json={"content": "Check message 1"})
        assert r1.status_code == 200

        # Request 2: OK
        r2 = test_client.post("/api/ml/analyze", json={"content": "Check message 2"})
        assert r2.status_code == 200

        # Request 3: Exceeded limit -> HTTP 429
        r3 = test_client.post("/api/ml/analyze", json={"content": "Check message 3"})
        assert r3.status_code == 429
        data = r3.json()
        assert data["error"] == "rate_limit_exceeded"
        assert "Retry-After" in r3.headers


def test_trusted_proxy_and_forwarded_for_handling(monkeypatch) -> None:
    from starlette.requests import Request
    from app.security import get_client_ip

    # 1. Untrusted peer connection: X-Forwarded-For must NOT be trusted
    monkeypatch.delenv("SIGNALCHECK_TRUSTED_PROXIES", raising=False)
    untrusted_scope = {
        "type": "http",
        "client": ("192.168.1.100", 45678),
        "headers": [(b"x-forwarded-for", b"203.0.113.195")],
    }
    untrusted_req = Request(untrusted_scope)
    assert get_client_ip(untrusted_req) == "192.168.1.100"

    # 2. Configured trusted proxy (e.g., local NGINX at 10.0.0.1):
    # Valid X-Forwarded-For header should be parsed and trusted
    monkeypatch.setenv("SIGNALCHECK_TRUSTED_PROXIES", "10.0.0.1, 127.0.0.1")
    trusted_scope = {
        "type": "http",
        "client": ("10.0.0.1", 50000),
        "headers": [(b"x-forwarded-for", b"203.0.113.195, 10.0.0.1")],
    }
    trusted_req = Request(trusted_scope)
    assert get_client_ip(trusted_req) == "203.0.113.195"

    # 3. Trusted proxy connection with invalid/malformed IP candidate in X-Forwarded-For:
    # Falls back to direct peer IP
    malformed_scope = {
        "type": "http",
        "client": ("10.0.0.1", 50000),
        "headers": [(b"x-forwarded-for", b"invalid-ip-string")],
    }
    malformed_req = Request(malformed_scope)
    assert get_client_ip(malformed_req) == "10.0.0.1"


class FakePhishingModel:
    classes_ = [0, 1]

    def __init__(self) -> None:
        self.messages = []
        self.fit_calls = 0

    def predict_proba(self, messages):
        self.messages.extend(messages)
        return [[0.2, 0.8] for _ in messages]

    def fit(self, *_args, **_kwargs):
        self.fit_calls += 1
        raise AssertionError("The API must never train the model.")


def test_ml_endpoint_returns_prediction_schema_and_uses_loaded_model(monkeypatch) -> None:
    model = FakePhishingModel()
    loads = []

    def load_once():
        loads.append(True)
        return model

    monkeypatch.setattr("app.main.load_phishing_model", load_once)
    monkeypatch.setattr(
        "app.main.load_android_model", lambda: make_android_loaded_model()
    )
    with TestClient(app) as ml_client:
        response = ml_client.post(
            "/api/ml/analyze", json={"content": "  Review this message  "}
        )
        repeated = ml_client.post("/api/ml/analyze", json={"content": "Second message"})

    assert response.status_code == 200
    data = response.json()
    assert set(data) == {
        "classification", "phishing_score", "score_kind", "threshold",
        "model_id", "disclaimer",
    }
    assert data["classification"] == "phishing"
    assert data["phishing_score"] == 0.8
    assert data["score_kind"] == "uncalibrated_model_score"
    assert data["threshold"] == 0.5
    assert data["model_id"] == "phishing-tfidf-logreg-domain-grouped-v1"
    assert data["disclaimer"]
    assert repeated.status_code == 200
    assert model.messages == ["Review this message", "Second message"]
    assert model.fit_calls == 0
    assert len(loads) == 1


@pytest.mark.parametrize(
    ("payload", "status_code", "error"),
    [
        ({"content": ""}, 422, "empty_input"),
        ({"content": " \t\n "}, 422, "empty_input"),
        ({"content": 42}, 422, "validation_error"),
        ({"content": "x" * 10_001}, 413, "input_too_long"),
    ],
)
def test_ml_endpoint_rejects_invalid_content(payload, status_code, error, monkeypatch) -> None:
    monkeypatch.setattr("app.main.load_phishing_model", FakePhishingModel)
    monkeypatch.setattr(
        "app.main.load_android_model", lambda: make_android_loaded_model()
    )
    with TestClient(app) as ml_client:
        response = ml_client.post("/api/ml/analyze", json=payload)
    assert response.status_code == status_code
    assert response.json()["error"] == error


def test_ml_model_loading_failure_is_reported_clearly(monkeypatch) -> None:
    def fail_load():
        raise ModelLoadError("Phishing model artifact is missing.")

    monkeypatch.setattr("app.main.load_phishing_model", fail_load)
    with pytest.raises(RuntimeError, match="Phishing ML model startup failed"):
        with TestClient(app):
            pass


def test_model_loader_reports_missing_artifact(tmp_path) -> None:
    with pytest.raises(ModelLoadError, match="artifact is missing"):
        load_phishing_model(tmp_path / "missing.joblib")


def test_model_loader_rejects_incompatible_scikit_learn_version(tmp_path, monkeypatch) -> None:
    import sklearn

    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"placeholder")
    monkeypatch.setattr(sklearn, "__version__", "0.0-test")
    with pytest.raises(ModelLoadError, match="requires scikit-learn 1.8.0"):
        load_phishing_model(artifact)


ANDROID_TEST_FEATURES = tuple(
    f"FEATURE_{index:03d}" for index in range(ANDROID_FEATURE_COUNT)
)


class FakeAndroidStep:
    def __init__(self, feature_count: int = ANDROID_FEATURE_COUNT) -> None:
        self.n_features_in_ = feature_count
        self.fit_calls = 0

    def fit(self, *_args, **_kwargs):
        self.fit_calls += 1
        raise AssertionError("The API must never train the Android model.")


class FakeAndroidPipeline:
    def __init__(self, scores=(0.7, 0.3), classes=(1, 0), feature_count=ANDROID_FEATURE_COUNT):
        self.classes_ = list(classes)
        self.named_steps = {"classifier": FakeAndroidStep(feature_count)}
        self.scores = list(scores)
        self.received = []

    def predict_proba(self, features):
        self.received.append(np.asarray(features).copy())
        return [self.scores]


def make_android_loaded_model(
    scores=(0.7, 0.3), classes=(1, 0), feature_count=ANDROID_FEATURE_COUNT
) -> LoadedAndroidModel:
    return LoadedAndroidModel(
        pipeline=FakeAndroidPipeline(scores, classes, feature_count),
        feature_columns=ANDROID_TEST_FEATURES,
        threshold=0.5,
    )


def android_feature_payload(values=None):
    if values is None:
        values = {name: index % 2 for index, name in enumerate(ANDROID_TEST_FEATURES)}
    return {"features": values}


def test_android_endpoint_uses_saved_feature_order_and_response_schema(monkeypatch) -> None:
    phishing_model = FakePhishingModel()
    android_model = make_android_loaded_model(scores=(0.73, 0.27), classes=(1, 0))
    loads = []

    def load_android_once():
        loads.append(True)
        return android_model

    monkeypatch.setattr("app.main.load_phishing_model", lambda: phishing_model)
    monkeypatch.setattr("app.main.load_android_model", load_android_once)

    # Deliberately reverse JSON insertion order; inference must follow config order.
    values = {
        name: index % 2
        for index, name in reversed(list(enumerate(ANDROID_TEST_FEATURES)))
    }
    with TestClient(app) as android_client:
        response = android_client.post(
            "/api/ml/analyze-android", json=android_feature_payload(values)
        )
        repeated = android_client.post(
            "/api/ml/analyze-android", json=android_feature_payload(values)
        )

    assert response.status_code == 200
    data = response.json()
    assert set(data) == {
        "classification", "malware_score", "score_kind", "threshold",
        "model_id", "disclaimer",
    }
    assert data["classification"] == "malicious"
    assert data["malware_score"] == 0.73
    assert data["score_kind"] == "uncalibrated_model_score"
    assert data["threshold"] == 0.5
    assert data["model_id"] == "android-random-forest-grouped-sklearn-1.8.0-v1"
    assert "provisional dataset labels" in data["disclaimer"]
    assert "does not scan APK files" in data["disclaimer"]
    assert repeated.status_code == 200
    expected_row = np.asarray(
        [[values[name] for name in ANDROID_TEST_FEATURES]], dtype=np.uint8
    )
    assert all(np.array_equal(batch, expected_row) for batch in android_model.pipeline.received)
    assert android_model.pipeline.named_steps["classifier"].fit_calls == 0
    assert len(loads) == 1


@pytest.mark.parametrize(
    ("positive_score", "expected_classification"),
    [(0.5, "malicious"), (0.49, "non_malicious")],
)
def test_android_endpoint_uses_threshold_for_classification(
    positive_score, expected_classification, monkeypatch
) -> None:
    monkeypatch.setattr("app.main.load_phishing_model", FakePhishingModel)
    monkeypatch.setattr(
        "app.main.load_android_model",
        lambda: make_android_loaded_model(
            scores=(positive_score, 1.0 - positive_score), classes=(1, 0)
        ),
    )
    with TestClient(app) as android_client:
        response = android_client.post(
            "/api/ml/analyze-android", json=android_feature_payload()
        )
    assert response.status_code == 200
    assert response.json()["malware_score"] == positive_score
    assert response.json()["classification"] == expected_classification


def test_android_endpoint_rejects_missing_and_unexpected_feature_names(monkeypatch) -> None:
    monkeypatch.setattr("app.main.load_phishing_model", FakePhishingModel)
    monkeypatch.setattr(
        "app.main.load_android_model", lambda: make_android_loaded_model()
    )
    missing = dict(android_feature_payload()["features"])
    missing.pop(ANDROID_TEST_FEATURES[-1])
    unexpected = dict(android_feature_payload()["features"])
    unexpected.pop(ANDROID_TEST_FEATURES[-1])
    unexpected["NOT_A_MODEL_FEATURE"] = 0

    with TestClient(app) as android_client:
        missing_response = android_client.post(
            "/api/ml/analyze-android", json=android_feature_payload(missing)
        )
        unexpected_response = android_client.post(
            "/api/ml/analyze-android", json=android_feature_payload(unexpected)
        )

    assert missing_response.status_code == 422
    assert missing_response.json()["error"] == "invalid_android_features"
    assert unexpected_response.status_code == 422
    detail = unexpected_response.json()["detail"]
    assert "NOT_A_MODEL_FEATURE" in detail["unexpected_features"]
    assert ANDROID_TEST_FEATURES[-1] in detail["missing_features"]


@pytest.mark.parametrize("invalid_value", [True, False, "1", "0", None, 0.0, 1.0, 2, -1])
def test_android_endpoint_rejects_non_binary_or_non_integer_values(
    invalid_value, monkeypatch
) -> None:
    monkeypatch.setattr("app.main.load_phishing_model", FakePhishingModel)
    monkeypatch.setattr(
        "app.main.load_android_model", lambda: make_android_loaded_model()
    )
    values = dict(android_feature_payload()["features"])
    values[ANDROID_TEST_FEATURES[0]] = invalid_value
    with TestClient(app) as android_client:
        response = android_client.post(
            "/api/ml/analyze-android", json=android_feature_payload(values)
        )
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_android_features"


def test_android_model_loader_reports_missing_artifact(tmp_path) -> None:
    with pytest.raises(AndroidModelLoadError, match="Android model artifact is missing"):
        load_android_model(tmp_path / "missing.joblib", tmp_path / "config.json")


def test_android_model_loader_rejects_feature_schema_dimension_mismatch() -> None:
    config = {
        "feature_columns": list(ANDROID_TEST_FEATURES),
        "feature_count": ANDROID_FEATURE_COUNT,
        "threshold": 0.5,
    }
    model = FakeAndroidPipeline(feature_count=ANDROID_FEATURE_COUNT - 1)
    with pytest.raises(AndroidModelLoadError, match="feature dimension"):
        validate_android_bundle(model, config)


def test_android_model_loader_rejects_duplicate_schema_names() -> None:
    config = {
        "feature_columns": list(ANDROID_TEST_FEATURES[:-1]) + [ANDROID_TEST_FEATURES[0]],
        "feature_count": ANDROID_FEATURE_COUNT,
        "threshold": 0.5,
    }
    with pytest.raises(AndroidModelLoadError, match="duplicate names"):
        validate_android_bundle(FakeAndroidPipeline(), config)


def test_android_model_loader_requires_positive_class_one() -> None:
    config = {
        "feature_columns": list(ANDROID_TEST_FEATURES),
        "feature_count": ANDROID_FEATURE_COUNT,
        "threshold": 0.5,
    }
    model = FakeAndroidPipeline(classes=(0, 2))
    with pytest.raises(AndroidModelLoadError, match="positive class 1"):
        validate_android_bundle(model, config)


def test_android_model_failure_does_not_disable_phishing_endpoint(monkeypatch) -> None:
    def fail_android_load():
        raise AndroidModelLoadError("Android model artifact is missing.")

    monkeypatch.setattr("app.main.load_phishing_model", FakePhishingModel)
    monkeypatch.setattr("app.main.load_android_model", fail_android_load)
    with TestClient(app) as service_client:
        removed_endpoint_response = service_client.post(
            "/api/analyze", json={"content": "The service is available."}
        )
        phishing_response = service_client.post(
            "/api/ml/analyze", json={"content": "A routine message."}
        )
        android_response = service_client.post(
            "/api/ml/analyze-android", json=android_feature_payload()
        )

    assert removed_endpoint_response.status_code == 404
    assert phishing_response.status_code == 200
    assert android_response.status_code == 503
    assert "Android malware classification model is not available" in str(
        android_response.json()["detail"]
    )


def test_real_android_model_loads_and_verifies_integrity() -> None:
    """The production Android model artifact must load and verify against manifest integrity."""
    loaded = load_android_model()
    assert isinstance(loaded, LoadedAndroidModel)
    assert loaded.model_id == "android-random-forest-grouped-sklearn-1.8.0-v1"
    assert len(loaded.feature_columns) == ANDROID_FEATURE_COUNT == 226
    assert loaded.threshold == 0.5


def test_real_android_model_predicts_on_known_sample_vector() -> None:
    """The production Android model must score the verified 226-feature sample vector."""
    sample_path = (
        Path(__file__).resolve().parents[2]
        / "frontend"
        / "src"
        / "components"
        / "sample_android_features.json"
    )
    with sample_path.open(encoding="utf-8") as stream:
        sample_data = json.load(stream)

    features = sample_data["features"]
    assert len(features) == 226

    loaded = load_android_model()
    result = classify_android_features(features, loaded)
    assert result["classification"] == "non_malicious"
    assert 0.14 <= result["malware_score"] <= 0.15
    assert round(result["malware_score"], 4) == 0.1420
    assert result["threshold"] == 0.5
    assert result["model_id"] == "android-random-forest-grouped-sklearn-1.8.0-v1"
    assert result["score_kind"] == "uncalibrated_model_score"

    # Also test through the live FastAPI endpoint without mocking
    with TestClient(app) as client:
        response = client.post("/api/ml/analyze-android", json={"features": features})
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "non_malicious"
        assert round(data["malware_score"], 4) == 0.1420

