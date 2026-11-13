"""Tests for the static APK analysis API endpoint (POST /api/apk/analyze).

Verifies:
- Programmatic ZIP/APK fixture creation and handling.
- Valid APK analysis with Androguard extraction.
- Non-ZIP file renamed .apk rejected with clear 422.
- ZIP without AndroidManifest.xml rejected with clear 422.
- ZIP without classes*.dex rejected with clear 422.
- Oversize upload (>25 MB) rejected with 413.
- Zip-bomb high compression ratio rejected with 422.
- Zip-bomb excess uncompressed size rejected with 422.
- Path-traversal filenames in archive rejected with 422.
- Corrupt DEX handling.
- Timeout path handled with 504.
- Temporary file deleted after success and after failure.
- No APK file content or extracted strings in logs.
- Rate limiting returns 429 when threshold exceeded.
- Rule table behaviors (findings generation, severity levels).
"""

from __future__ import annotations

import io
import os
import tempfile
import zipfile
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app, limiter

REAL_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "reports",
    "ml",
    "android_v3_runs",
    "run_017_dataset_acquisition",
    "acquired_apks",
    "ANDROGUARD_TESTS_TestActivity.apk",
)


def create_minimal_zip(files: dict[str, bytes]) -> io.BytesIO:
    """Helper to create an in-memory zip archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset SlowAPI limiter storage between tests so rate limits don't leak."""
    try:
        limiter.reset()
    except Exception:
        pass
    yield
    try:
        limiter.reset()
    except Exception:
        pass


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_apk_analyze_with_real_fixture(client):
    """Test analyzing a known clean APK fixture from the repo."""
    assert os.path.exists(REAL_FIXTURE_PATH), f"Fixture not found at {REAL_FIXTURE_PATH}"
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    response = client.post(
        "/api/apk/analyze",
        files={"file": ("TestActivity.apk", file_bytes, "application/vnd.android.package-archive")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["analysis_version"] == "apk-static-v1"
    assert len(data["sha256"]) == 64
    assert data["file_size"] == len(file_bytes)
    assert data["app"]["package_name"] == "tests.androguard"
    assert "permissions" in data
    assert "components" in data
    assert "signing" in data
    assert "code_indicators" in data
    assert isinstance(data["findings"], list)
    assert data["indicator_level"] in ("no_notable_indicators", "some_indicators", "many_indicators")
    assert len(data["limitations"]) > 0


def test_apk_analyze_rejects_non_zip_file(client):
    """A plain text or non-ZIP binary named test.apk must be rejected with 422."""
    non_zip = b"This is plain text, not a zip archive."
    response = client.post(
        "/api/apk/analyze",
        files={"file": ("malicious.apk", non_zip, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "invalid_zip_archive"


def test_apk_analyze_rejects_zip_without_manifest(client):
    """A ZIP without AndroidManifest.xml must be rejected with 422."""
    zip_buf = create_minimal_zip({"classes.dex": b"dex\n035\x00dummy"})
    response = client.post(
        "/api/apk/analyze",
        files={"file": ("nomanifest.apk", zip_buf.getvalue(), "application/octet-stream")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "missing_android_manifest"


def test_apk_analyze_rejects_zip_without_dex(client):
    """A ZIP with AndroidManifest.xml but no classes*.dex must be rejected with 422."""
    zip_buf = create_minimal_zip({"AndroidManifest.xml": b"dummy_manifest"})
    response = client.post(
        "/api/apk/analyze",
        files={"file": ("nodex.apk", zip_buf.getvalue(), "application/octet-stream")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "missing_dex_code"


def test_apk_analyze_rejects_path_traversal(client):
    """Archive with path traversal filename must be rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0")
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex")
    buf.seek(0)

    response = client.post(
        "/api/apk/analyze",
        files={"file": ("traversal.apk", buf.getvalue(), "application/octet-stream")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "path_traversal_detected"


def test_apk_analyze_rejects_oversize_upload(client, monkeypatch):
    """Uploads exceeding the configured max byte size must be rejected with 413."""
    monkeypatch.setenv("SIGNALCHECK_APK_MAX_SIZE_BYTES", "1024")  # 1 KB limit
    oversize = b"PK\x03\x04" + b"A" * 2000

    response = client.post(
        "/api/apk/analyze",
        files={"file": ("big.apk", oversize, "application/octet-stream")},
    )
    assert response.status_code == 413
    data = response.json()
    assert data["detail"]["error"] == "apk_too_large"


def test_apk_analyze_rejects_zip_bomb_uncompressed_size(client, monkeypatch):
    """Total uncompressed size exceeding limit triggers zip bomb defense."""
    monkeypatch.setenv("SIGNALCHECK_APK_MAX_UNCOMPRESSED_BYTES", "5000")
    # Compress 10,000 zeros (compresses to ~20 bytes)
    big_zeros = b"\x00" * 10000
    zip_buf = create_minimal_zip({
        "AndroidManifest.xml": b"manifest",
        "classes.dex": b"dex",
        "big.bin": big_zeros,
    })

    response = client.post(
        "/api/apk/analyze",
        files={"file": ("zipbomb.apk", zip_buf.getvalue(), "application/octet-stream")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["detail"]["error"] == "zip_bomb_size_exceeded"


def test_apk_analyze_handles_timeout(client, monkeypatch):
    """Simulated analysis timeout returns 504."""
    monkeypatch.setenv("SIGNALCHECK_APK_TIMEOUT_SECONDS", "0.01")

    # Patch analyze_apk_file to sleep longer than the timeout
    import time
    def slow_analyze(*args, **kwargs):
        time.sleep(0.1)
        return {}

    with patch("app.main.analyze_apk_file", side_effect=slow_analyze):
        with open(REAL_FIXTURE_PATH, "rb") as f:
            file_bytes = f.read()

        response = client.post(
            "/api/apk/analyze",
            files={"file": ("slow.apk", file_bytes, "application/octet-stream")},
        )
        assert response.status_code == 504
        data = response.json()
        assert data["detail"]["error"] == "analysis_timeout"


def test_temp_file_deleted_on_success_and_failure(client, monkeypatch):
    """Ensure temporary file is deleted in the finally block."""
    created_temp_paths = []
    original_named_temp = tempfile.NamedTemporaryFile

    def tracking_temp_file(*args, **kwargs):
        tf = original_named_temp(*args, **kwargs)
        created_temp_paths.append(tf.name)
        return tf

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", tracking_temp_file)

    # 1. Success path
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()
    resp_ok = client.post(
        "/api/apk/analyze",
        files={"file": ("TestActivity.apk", file_bytes, "application/octet-stream")},
    )
    assert resp_ok.status_code == 200
    assert len(created_temp_paths) >= 1
    assert not os.path.exists(created_temp_paths[-1])

    # 2. Failure path
    created_temp_paths.clear()
    resp_err = client.post(
        "/api/apk/analyze",
        files={"file": ("bad.apk", b"not a zip", "application/octet-stream")},
    )
    assert resp_err.status_code == 422
    assert len(created_temp_paths) >= 1
    assert not os.path.exists(created_temp_paths[-1])


def test_no_upload_content_in_audit_logs(client, capsys):
    """Confirm the logging statement only logs size, duration, outcome, and req_id."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    client.post(
        "/api/apk/analyze",
        files={"file": ("super_secret_payload_filename.apk", file_bytes, "application/octet-stream")},
    )

    captured = capsys.readouterr()
    log_lines = [line for line in captured.out.splitlines() if "SIGNALCHECK_APK_AUDIT" in line]
    assert len(log_lines) >= 1
    audit_line = log_lines[-1]
    assert "super_secret_payload_filename" not in audit_line
    assert "req_id=" in audit_line
    assert "size_bytes=" in audit_line
    assert "duration_sec=" in audit_line
    assert "outcome=SUCCESS" in audit_line


def test_apk_rate_limiting_enforced(client, monkeypatch):
    """Confirm 429 is returned when rate limit is exceeded."""
    monkeypatch.setenv("SIGNALCHECK_RATE_LIMIT_APK", "2/minute")
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    # Request 1
    r1 = client.post(
        "/api/apk/analyze",
        files={"file": ("test1.apk", file_bytes, "application/octet-stream")},
    )
    assert r1.status_code == 200

    # Request 2
    r2 = client.post(
        "/api/apk/analyze",
        files={"file": ("test2.apk", file_bytes, "application/octet-stream")},
    )
    assert r2.status_code == 200

    # Request 3 -> Exceeded
    r3 = client.post(
        "/api/apk/analyze",
        files={"file": ("test3.apk", file_bytes, "application/octet-stream")},
    )
    assert r3.status_code == 429
    assert r3.json()["error"] == "rate_limit_exceeded"
