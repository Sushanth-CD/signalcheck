"""Test suite for dual_channel transformers and V3 pipelines."""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from ml.dual_channel import (
    ContentChannelExtractor,
    URLChannelExtractor,
    build_content_only_feature_pipeline,
    build_dual_channel_feature_pipeline,
    build_url_only_feature_pipeline,
    extract_single_content,
    extract_single_urls,
)


def test_html_extraction() -> None:
    raw_html = (
        "<html><head><title>Account Security Alert</title>"
        "<script>console.log('malicious script');</script>"
        "<style>body { color: red; }</style></head>"
        "<body><h1>Urgent action required</h1>"
        "<p>Your card has been locked.</p>"
        "<a href='https://bank.example.com/login'>Click Here To Unlock</a>"
        "</body></html>"
    )
    content = extract_single_content(raw_html)
    assert "account security alert" in content
    assert "urgent action required" in content
    assert "click here to unlock" in content
    assert "malicious script" not in content
    assert "color: red" not in content


def test_plain_text_url_removal() -> None:
    raw_text = "Important notice: Please visit https://secure.update-account.com/auth now to verify."
    content = extract_single_content(raw_text)
    assert "important notice: please visit now to verify." in content
    assert "secure.update-account.com" not in content


def test_url_feature_extraction() -> None:
    raw_text = (
        "Check this out: <a href='https://secure.chase-login.com/accounts/verify.php?token=secret123&action=reset'>"
        "Verify</a>"
    )
    url_features = extract_single_urls(raw_text)
    assert "host_secure.chase-login.com" in url_features
    assert "chase" in url_features
    assert "login" in url_features
    assert "accounts" in url_features
    assert "verify" in url_features
    assert "php" in url_features
    assert "param_token" in url_features
    assert "param_action" in url_features
    # Verify raw parameter values are NOT present
    assert "secret123" not in url_features


def test_empty_channels() -> None:
    empty_content = extract_single_content("")
    empty_url = extract_single_urls("")
    assert empty_content == ""
    assert empty_url == ""

    # Message with no URLs
    no_url_text = "Hello this is a plain message without any link whatsoever."
    assert extract_single_urls(no_url_text) == ""

    # Ambiguous bare domain mention should not be accepted as confirmed URL
    bare_domain = "You can read more at wikipedia.org someday."
    # V2 parser marks wikipedia.org as ambiguous_bare_domain_mention (medium conf), not high conf normalized_hostname
    assert extract_single_urls(bare_domain) == ""


def test_multiple_urls() -> None:
    raw = (
        "Links: <a href='https://alpha.example.com/one?id=1'>One</a> "
        "and <a href='https://beta.example.org/two?key=abc'>Two</a>"
    )
    url_features = extract_single_urls(raw)
    assert "host_alpha.example.com" in url_features
    assert "host_beta.example.org" in url_features
    assert "param_id" in url_features
    assert "param_key" in url_features


def test_malformed_html_handling() -> None:
    malformed = "<div class='unclosed'><title>Broken<p>Some text<script>run();"
    content = extract_single_content(malformed)
    assert isinstance(content, str)
    assert "some text" in content or "broken" in content


def test_model_serialization_and_reproducibility(tmp_path: Path) -> None:
    texts = [
        "<html><head><title>Bank Alert</title></head><body><a href='https://evil.com/login?token=abc'>Sign in</a></body></html>",
        "Hello team, the meeting is postponed until tomorrow afternoon.",
        "Your PayPal transaction was rejected: https://paypal-verify.com/login?u=test",
        "Weekly newsletter with standard company updates and team photos.",
    ]
    labels = [1, 0, 1, 0]

    pipeline = Pipeline(
        [
            ("features", build_dual_channel_feature_pipeline()),
            ("clf", LogisticRegression(random_state=42)),
        ]
    )
    pipeline.fit(texts, labels)
    preds_orig = pipeline.predict_proba(texts)

    model_file = tmp_path / "dual_channel_test.joblib"
    joblib.dump(pipeline, model_file)

    loaded_pipe = joblib.load(model_file)
    preds_loaded = loaded_pipe.predict_proba(texts)

    import numpy as np
    np.testing.assert_allclose(preds_orig, preds_loaded, rtol=1e-5, atol=1e-5)


if __name__ == "__main__":
    pytest.main(["-v", str(__file__)])
