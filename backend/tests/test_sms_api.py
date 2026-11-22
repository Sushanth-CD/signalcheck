"""Tests for the dedicated SMS phishing endpoint (/api/ml/analyze-sms)."""

from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.sms_classifier import SMSModelLoadError, load_sms_model, classify_sms_message


client = TestClient(app)


class FakeSMSModel:
    """Mock SMS model exposing classes_ and predict_proba for unit testing."""
    classes_ = [0, 1]

    def __init__(self, score: float = 0.85) -> None:
        self.score = score
        self.messages: list[str] = []
        self.fit_calls = 0

    def predict_proba(self, messages):
        self.messages.extend(messages)
        return [[1.0 - self.score, self.score] for _ in messages]

    def fit(self, *_args, **_kwargs):
        self.fit_calls += 1
        raise AssertionError("The API must never train the SMS model.")


def test_sms_endpoint_valid_smishing_prediction(monkeypatch) -> None:
    fake_model = FakeSMSModel(score=0.92)
    monkeypatch.setattr("app.main.load_sms_model", lambda: fake_model)

    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/ml/analyze-sms",
            json={"content": "URGENT: Your account has been locked. Call 0800123456 immediately."},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "smishing"
    assert data["smishing_score"] == 0.92
    assert data["threshold"] == 0.50
    assert data["score_kind"] == "uncalibrated_model_score"
    assert data["model_id"] == "sms-05-c-combined-v1"
    assert "disclaimer" in data
    assert fake_model.messages == ["URGENT: Your account has been locked. Call 0800123456 immediately."]
    assert fake_model.fit_calls == 0


def test_sms_endpoint_valid_legitimate_prediction(monkeypatch) -> None:
    fake_model = FakeSMSModel(score=0.15)
    monkeypatch.setattr("app.main.load_sms_model", lambda: fake_model)

    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/ml/analyze-sms",
            json={"content": "Hey, let's meet for lunch at 12:30 tomorrow."},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "not_smishing"
    assert data["smishing_score"] == 0.15
    assert data["threshold"] == 0.50
    assert data["model_id"] == "sms-05-c-combined-v1"
    assert fake_model.messages == ["Hey, let's meet for lunch at 12:30 tomorrow."]


def test_sms_endpoint_rejects_empty_input() -> None:
    response = client.post("/api/ml/analyze-sms", json={"content": ""})
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "empty_input"
    assert "Provide an SMS message to analyze." in data["message"]


def test_sms_endpoint_rejects_whitespace_only_input() -> None:
    response = client.post("/api/ml/analyze-sms", json={"content": "    \n\t  "})
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "empty_input"
    assert "Provide an SMS message to analyze." in data["message"]


def test_sms_endpoint_rejects_excessively_long_input() -> None:
    response = client.post(
        "/api/ml/analyze-sms",
        json={"content": "A" * 2001},
    )
    assert response.status_code == 413
    data = response.json()
    assert data["error"] == "input_too_long"
    assert "2000 characters" in data["message"]


def test_sms_endpoint_service_unavailable_when_model_missing(monkeypatch) -> None:
    with TestClient(app) as test_client:
        test_client.app.state.sms_model = None
        response = test_client.post(
            "/api/ml/analyze-sms",
            json={"content": "Sample message text."},
        )
    assert response.status_code == 503
    assert "not available" in response.json()["detail"]


def test_sms_endpoint_positive_class_probability_extraction(monkeypatch) -> None:
    class InvertedOrderModel:
        classes_ = [1, 0]  # Positive class is at index 0

        def predict_proba(self, messages):
            return [[0.88, 0.12] for _ in messages]

    monkeypatch.setattr("app.main.load_sms_model", lambda: InvertedOrderModel())

    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/ml/analyze-sms",
            json={"content": "Test inverted class ordering."},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["smishing_score"] == 0.88
    assert data["classification"] == "smishing"


def test_sms_endpoint_threshold_edge_cases(monkeypatch) -> None:
    # Exactly 0.50 should classify as smishing
    model_50 = FakeSMSModel(score=0.50)
    monkeypatch.setattr("app.main.load_sms_model", lambda: model_50)
    with TestClient(app) as test_client:
        resp = test_client.post("/api/ml/analyze-sms", json={"content": "Threshold edge 0.50"})
        assert resp.json()["classification"] == "smishing"

    # 0.4999 should classify as not_smishing
    model_4999 = FakeSMSModel(score=0.4999)
    monkeypatch.setattr("app.main.load_sms_model", lambda: model_4999)
    with TestClient(app) as test_client:
        resp = test_client.post("/api/ml/analyze-sms", json={"content": "Threshold edge 0.4999"})
        assert resp.json()["classification"] == "not_smishing"


def test_sms_endpoint_uses_real_frozen_artifact_at_startup() -> None:
    # Full end-to-end inference against the loaded real artifact
    with TestClient(app) as test_client:
        # 1. Smishing lure (premium callback lure)
        smish_resp = test_client.post(
            "/api/ml/analyze-sms",
            json={"content": "URGENT: Your debit card has been blocked. Call 08712404000 immediately to unlock."},
        )
        assert smish_resp.status_code == 200
        smish_data = smish_resp.json()
        assert smish_data["classification"] == "smishing"
        assert smish_data["smishing_score"] >= 0.50
        assert smish_data["model_id"] == "sms-05-c-combined-v1"

        # 2. Legitimate benign text
        benign_resp = test_client.post(
            "/api/ml/analyze-sms",
            json={"content": "Hey Mum, I will be home around 6pm for dinner. See you soon!"},
        )
        assert benign_resp.status_code == 200
        benign_data = benign_resp.json()
        assert benign_data["classification"] == "not_smishing"
        assert benign_data["smishing_score"] < 0.50
