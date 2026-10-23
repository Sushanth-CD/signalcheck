"""FastAPI analysis endpoint tests."""

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _analyze(content: str):
    return client.post("/api/analyze", json={"content": content})


def _assert_band(score: int, level: str) -> None:
    expected = "low" if score <= 19 else "medium" if score <= 49 else "high"
    assert level == expected


def test_health_endpoint_returns_success() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_cors_allows_configured_vite_origins() -> None:
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        response = client.options(
            "/api/analyze",
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
        "/api/analyze",
        headers={
            "Origin": "http://localhost:5174",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_valid_suspicious_message_returns_structured_analysis() -> None:
    response = _analyze("Please send your OTP to this number immediately.")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 25
    assert data["risk_level"] == "medium"
    assert {
        "risk_score",
        "risk_level",
        "summary",
        "detected_indicators",
        "recommendations",
        "disclaimer",
    } <= set(data)
    assert data["detected_indicators"][0]["rule_id"] == "PH001"
    assert data["detected_indicators"][0]["explanation"]
    assert data["disclaimer"]
    _assert_band(data["risk_score"], data["risk_level"])


def test_supplied_kyc_account_blocking_message_returns_explainable_finding() -> None:
    content = (
        "URGENT: Your Bank Account Will Be Blocked!\n\nDear Customer, your bank account will be blocked today "
        "due to incomplete KYC verification. Update your details immediately by clicking the link below.\n\n"
        "http://bank-kyc-verify.example.com\n\nFailure to update your KYC may result in permanent account suspension."
    )
    response = _analyze(content)
    assert response.status_code == 200
    data = response.json()
    ids = {item["rule_id"] for item in data["detected_indicators"]}
    assert "PH011" in ids
    ph011 = next(item for item in data["detected_indicators"] if item["rule_id"] == "PH011")
    assert ph011["title"] == "Urgent KYC or account-blocking link"
    assert ph011["score_contribution"] == 25
    assert ph011["explanation"]
    assert data["risk_score"] == min(
        100, sum(item["score_contribution"] for item in data["detected_indicators"])
    )
    _assert_band(data["risk_score"], data["risk_level"])


def test_benign_message_returns_low_score_without_claiming_safety() -> None:
    response = _analyze("The weather is pleasant today.")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 0
    assert data["risk_level"] == "low"
    assert not data["detected_indicators"]
    assert "does not prove" in data["summary"]
    _assert_band(data["risk_score"], data["risk_level"])


def test_suspicious_url_returns_matching_url_indicator() -> None:
    response = _analyze("Review this link: https://bit.ly/abc")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 10
    assert data["risk_level"] == "low"
    assert [item["rule_id"] for item in data["detected_indicators"]] == ["URL001"]


def test_multiple_rules_are_summed_and_explained() -> None:
    response = _analyze(
        "We are from the cybercrime police. Send your OTP now. "
        "You are under digital arrest."
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 75
    assert data["risk_level"] == "high"
    assert {item["rule_id"] for item in data["detected_indicators"]} == {
        "PH001",
        "DA001",
        "DA002",
    }
    assert all(item["explanation"] for item in data["detected_indicators"])
    assert data["risk_score"] == min(
        100, sum(item["score_contribution"] for item in data["detected_indicators"])
    )
    _assert_band(data["risk_score"], data["risk_level"])


def test_analysis_score_is_bounded() -> None:
    response = _analyze("We are from the cybercrime police. Send your OTP now.")

    assert 0 <= response.json()["risk_score"] <= 100


def test_empty_content_is_rejected() -> None:
    response = client.post("/api/analyze", json={"content": ""})

    assert response.status_code == 422
    assert response.json()["error"] == "empty_input"


def test_whitespace_only_content_is_rejected() -> None:
    response = client.post("/api/analyze", json={"content": " \t\n "})

    assert response.status_code == 422
    assert response.json()["error"] == "empty_input"


def test_content_over_10000_characters_is_rejected() -> None:
    response = client.post("/api/analyze", json={"content": "x" * 10_001})

    assert response.status_code == 413
    assert response.json()["error"] == "input_too_long"


def test_exactly_10000_characters_passes_validation() -> None:
    response = client.post("/api/analyze", json={"content": "x" * 10_000})

    assert response.status_code == 200


def test_leading_and_trailing_whitespace_is_trimmed_before_analysis() -> None:
    response = client.post("/api/analyze", json={"content": "  message  "})

    assert response.status_code == 200


def test_unexpected_request_fields_are_rejected() -> None:
    response = client.post(
        "/api/analyze",
        json={"content": "Suspicious message", "extra": "not accepted"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_non_string_content_is_rejected() -> None:
    response = client.post("/api/analyze", json={"content": 42})

    assert response.status_code == 422


def test_validation_failures_never_return_internal_server_error() -> None:
    invalid_payloads = [
        {},
        {"content": ""},
        {"content": " "},
        {"content": "x" * 10_001},
        {"content": []},
        {"content": "text", "unexpected": True},
    ]

    for payload in invalid_payloads:
        response = client.post("/api/analyze", json=payload)
        assert response.status_code != 500


def test_malformed_url_does_not_prevent_text_analysis() -> None:
    response = _analyze("Send your OTP immediately. http://[broken")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 25
    assert [item["rule_id"] for item in data["detected_indicators"]] == ["PH001"]
    assert "could not be parsed" in data["summary"]


def test_malformed_url_does_not_prevent_other_valid_url_analysis() -> None:
    response = _analyze("Links: http://[broken and https://192.0.2.20/login")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 15
    assert [item["rule_id"] for item in data["detected_indicators"]] == ["URL002"]
    assert "could not be parsed" in data["summary"]


def test_duplicate_rule_matches_do_not_inflate_score() -> None:
    response = _analyze("Please send your OTP. Then send your password.")

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 25
    assert [item["rule_id"] for item in data["detected_indicators"]] == ["PH001"]
