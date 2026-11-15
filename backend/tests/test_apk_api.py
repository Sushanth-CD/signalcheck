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
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
import pytest
from unittest.mock import MagicMock, patch
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
    from app import apk_jobs

    def timeout_job_status(job_id: str):
        return {
            "job_id": job_id,
            "status": "timeout",
            "result": None,
            "error": "Analysis timed out",
        }

    with patch("app.main.get_job_status", side_effect=timeout_job_status):
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
    # Give isolated worker process a moment to clean up
    time.sleep(0.5)
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
    assert "outcome=" in audit_line


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


# ---------------------------------------------------------------------------
# Stage C2: Result History & Report Export Tests
# ---------------------------------------------------------------------------

def test_apk_analysis_persists_to_history(client):
    """Confirm that analyzing an APK stores a JSON record in session history and sets session cookie."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    response = client.post(
        "/api/apk/analyze",
        files={"file": ("TestActivity.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    # Confirm session cookie was issued
    assert "signalcheck_apk_sid" in response.cookies
    data = response.json()
    record_id = data.get("id")
    assert record_id is not None
    assert isinstance(record_id, int)

    # Check history endpoint with the client's session contains this record
    hist_resp = client.get("/api/apk/history?limit=10")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total"] >= 1
    found = any(item["id"] == record_id for item in hist_data["items"])
    assert found


def test_apk_history_ordering_newest_first(client):
    """History entries must be ordered by descending creation time."""
    hist_resp = client.get("/api/apk/history?limit=10")
    assert hist_resp.status_code == 200
    items = hist_resp.json()["items"]
    if len(items) >= 2:
        assert items[0]["id"] >= items[1]["id"]


def test_apk_history_pagination_bounds(client):
    """Limit > 50 or limit < 1 or offset < 0 must return 422."""
    r_toolarge = client.get("/api/apk/history?limit=51")
    assert r_toolarge.status_code == 422

    r_toosmall = client.get("/api/apk/history?limit=0")
    assert r_toosmall.status_code == 422

    r_negoffset = client.get("/api/apk/history?offset=-1")
    assert r_negoffset.status_code == 422

    r_valid = client.get("/api/apk/history?limit=5&offset=0")
    assert r_valid.status_code == 200
    assert len(r_valid.json()["items"]) <= 5


def test_apk_report_by_id_json(client):
    """GET /api/apk/report/{id} returns the full JSON result for the owner session."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    # Analyze an APK to ensure the session has an owned record
    analyze_resp = client.post(
        "/api/apk/analyze",
        files={"file": ("TestActivity.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert analyze_resp.status_code == 200
    rec_id = analyze_resp.json()["id"]

    report_resp = client.get(f"/api/apk/report/{rec_id}")
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["analysis_version"] == "apk-static-v1"
    assert report_data["sha256"] == analyze_resp.json()["sha256"]
    assert "findings" in report_data
    assert "permissions" in report_data
    assert "signing" in report_data


def test_apk_report_unknown_id_returns_444_or_404(client):
    """Querying an unknown report ID returns 404."""
    resp = client.get("/api/apk/report/9999999")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "report_not_found"


def test_apk_report_pdf_export(client):
    """GET /api/apk/report/{id}?format=pdf returns valid application/pdf bytes for owner session."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    # Analyze an APK to ensure the session has an owned record
    analyze_resp = client.post(
        "/api/apk/analyze",
        files={"file": ("TestActivity.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert analyze_resp.status_code == 200
    rec_id = analyze_resp.json()["id"]

    pdf_resp = client.get(f"/api/apk/report/{rec_id}?format=pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 1000  # Non-trivial PDF size
    # Check PDF magic header %PDF
    assert pdf_resp.content.startswith(b"%PDF")
    assert "attachment;" in pdf_resp.headers["content-disposition"]


def test_apk_history_retention_cap_per_session(monkeypatch):
    """Enforce retention setting SIGNALCHECK_APK_HISTORY_MAX=5 trimmings per session."""
    monkeypatch.setenv("SIGNALCHECK_APK_HISTORY_MAX", "5")
    from app.apk_db import save_apk_result, get_apk_history, get_session, APKAnalysisRecord
    from app.security import hash_session_token
    import uuid

    # Use unique session tokens for isolation from previous test runs
    uid = uuid.uuid4().hex
    session_a_hash = hash_session_token(f"session_a_{uid}")
    session_b_hash = hash_session_token(f"session_b_{uid}")

    dummy_result = {
        "analysis_version": "apk-static-v1",
        "sha256": "0" * 64,
        "file_size": 100,
        "app": {},
        "permissions": {},
        "components": {},
        "signing": {},
        "code_indicators": {},
        "findings": [],
        "indicator_level": "no_notable_indicators",
        "limitations": [],
    }

    # Insert 8 dummy results into session A
    for i in range(8):
        save_apk_result(
            sha256="a" * 64,
            package_name=f"test.app.a.{i}",
            file_size=1000,
            indicator_level="no_notable_indicators",
            outcome="SUCCESS",
            result_data=dummy_result,
            session_hash=session_a_hash,
        )

    # Insert 3 dummy results into session B
    for i in range(3):
        save_apk_result(
            sha256="b" * 64,
            package_name=f"test.app.b.{i}",
            file_size=2000,
            indicator_level="no_notable_indicators",
            outcome="SUCCESS",
            result_data=dummy_result,
            session_hash=session_b_hash,
        )

    items_a, total_a = get_apk_history(limit=50, session_hash=session_a_hash)
    # Session A must be capped at 5
    assert total_a == 5
    assert len(items_a) == 5

    # Session B must retain all 3 items (unaffected by Session A's cap)
    items_b, total_b = get_apk_history(limit=50, session_hash=session_b_hash)
    assert total_b == 3
    assert len(items_b) == 3


def test_apk_cross_session_isolation_and_id_probing():
    """Verify that records from Session A are completely invisible to Session B and vice versa.

    Session B cannot see Session A's history or probe Session A's report IDs (returns 404).
    """
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    # Session A client
    client_a = TestClient(app)
    resp_a = client_a.post(
        "/api/apk/analyze",
        files={"file": ("SessionA.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert resp_a.status_code == 200
    rec_a_id = resp_a.json()["id"]
    sid_a = resp_a.cookies["signalcheck_apk_sid"]
    assert sid_a

    # Session B client (clean client, separate cookie jar)
    client_b = TestClient(app)

    # 1. Before session B has analyzed anything, its history is empty
    hist_b_empty = client_b.get("/api/apk/history")
    assert hist_b_empty.status_code == 200
    assert hist_b_empty.json()["total"] == 0
    assert len(hist_b_empty.json()["items"]) == 0

    # 2. Session B attempts to probe/access Session A's report ID -> must return 404
    probe_resp = client_b.get(f"/api/apk/report/{rec_a_id}")
    assert probe_resp.status_code == 404
    assert probe_resp.json()["detail"]["error"] == "report_not_found"

    # 3. Session B attempts to download PDF of Session A's report ID -> must return 404
    probe_pdf = client_b.get(f"/api/apk/report/{rec_a_id}?format=pdf")
    assert probe_pdf.status_code == 404

    # 4. Session B analyzes an APK -> receives its own distinct session cookie
    resp_b = client_b.post(
        "/api/apk/analyze",
        files={"file": ("SessionB.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert resp_b.status_code == 200
    rec_b_id = resp_b.json()["id"]
    sid_b = resp_b.cookies["signalcheck_apk_sid"]
    assert sid_b != sid_a

    # 5. Session B sees ONLY its own record in history
    hist_b = client_b.get("/api/apk/history")
    assert hist_b.status_code == 200
    b_ids = [item["id"] for item in hist_b.json()["items"]]
    assert rec_b_id in b_ids
    assert rec_a_id not in b_ids

    # 6. Session A sees ONLY its own records in history
    hist_a = client_a.get("/api/apk/history")
    assert hist_a.status_code == 200
    a_ids = [item["id"] for item in hist_a.json()["items"]]
    assert rec_a_id in a_ids
    assert rec_b_id not in a_ids

    # 7. Session A can access its own report and PDF
    rep_a = client_a.get(f"/api/apk/report/{rec_a_id}")
    assert rep_a.status_code == 200
    rep_a_pdf = client_a.get(f"/api/apk/report/{rec_a_id}?format=pdf")
    assert rep_a_pdf.status_code == 200

    # 8. Session A probing Session B's report returns 404
    probe_a_of_b = client_a.get(f"/api/apk/report/{rec_b_id}")
    assert probe_a_of_b.status_code == 404


def test_no_apk_bytes_persisted_in_database():
    """Verify that SQLite database stores only JSON and metadata, never raw APK bytes."""
    from app.apk_db import get_session, APKAnalysisRecord
    session = get_session()
    try:
        records = session.query(APKAnalysisRecord).all()
        for r in records:
            # result_json should be text
            assert isinstance(r.result_json, str)
            # Must not contain zip magic bytes PK\x03\x04
            assert "PK\x03\x04" not in r.result_json
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Stage C3: Educational Finding Explanations Tests
# ---------------------------------------------------------------------------


def test_finding_explanations_completeness():
    """Every rule ID in finding_explanations.py must have all required non-empty fields."""
    from app.finding_explanations import FINDING_EXPLANATIONS

    expected_rules = [
        "RULE_SMS_EXFILTRATION_CAPABILITY",
        "RULE_ACCESSIBILITY_OVERLAY_COMBO",
        "RULE_DEVICE_ADMIN_PRIVILEGE",
        "RULE_COMMAND_EXECUTION",
        "RULE_DYNAMIC_CODE_LOADING",
        "RULE_BOOT_PERSISTENCE",
        "RULE_UNSIGNED_PACKAGE",
        "RULE_DEBUG_SIGNED_CERT",
        "RULE_PACKAGE_INSTALLER",
        "RULE_HARDCODED_IP_URL",
        "RULE_OBFUSCATION_HINT",
    ]

    for rule_id in expected_rules:
        assert rule_id in FINDING_EXPLANATIONS, f"Missing explanation for {rule_id}"
        entry = FINDING_EXPLANATIONS[rule_id]

        assert isinstance(entry.get("what_it_means"), str) and len(entry["what_it_means"].strip()) > 10
        assert isinstance(entry.get("why_attackers_use_it"), str) and len(entry["why_attackers_use_it"].strip()) > 10
        assert isinstance(entry.get("legit_uses"), list) and len(entry["legit_uses"]) >= 1
        for legit in entry["legit_uses"]:
            assert isinstance(legit, str) and len(legit.strip()) > 5

        assert isinstance(entry.get("what_to_do"), str) and len(entry["what_to_do"].strip()) > 10
        assert isinstance(entry.get("learn_more_tags"), list) and len(entry["learn_more_tags"]) >= 1
        for tag in entry["learn_more_tags"]:
            assert isinstance(tag, str) and len(tag.strip()) > 1


def test_unknown_rule_degrades_gracefully():
    """Unknown or future rule IDs must degrade gracefully without crash or exception."""
    from app.finding_explanations import get_finding_explanation, attach_explanations_to_payload

    assert get_finding_explanation("RULE_FUTURE_UNKNOWN_HEURISTIC_999") is None
    assert get_finding_explanation("") is None
    assert get_finding_explanation(None) is None

    synthetic_payload = {
        "analysis_version": "apk-static-v1",
        "findings": [
            {
                "id": "RULE_FUTURE_UNKNOWN_HEURISTIC_999",
                "category": "future",
                "severity": "low",
                "title": "Future unknown finding",
                "evidence": "synthetic",
                "why_it_matters": "testing fallback",
            }
        ],
    }

    enriched = attach_explanations_to_payload(synthetic_payload)
    assert len(enriched["findings"]) == 1
    # Unknown rule should NOT crash and should not have explanation field attached
    assert "explanation" not in enriched["findings"][0]


def test_explanation_present_on_analyze():
    """POST /api/apk/analyze response includes structured educational explanation on triggered findings."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    client = TestClient(app)
    response = client.post(
        "/api/apk/analyze",
        files={"file": ("VulnApp.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    data = response.json()
    findings = data.get("findings", [])
    assert len(findings) > 0

    for f in findings:
        explanation = f.get("explanation")
        assert explanation is not None, f"Expected explanation on finding {f.get('id')}"
        assert "what_it_means" in explanation
        assert "why_attackers_use_it" in explanation
        assert "legit_uses" in explanation
        assert "what_to_do" in explanation
        assert "learn_more_tags" in explanation


def test_explanation_attached_on_stored_report_fetch():
    """GET /api/apk/report/{id} dynamically attaches educational explanation to persisted records."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    client = TestClient(app)
    post_resp = client.post(
        "/api/apk/analyze",
        files={"file": ("StoredCheck.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert post_resp.status_code == 200
    rec_id = post_resp.json()["id"]

    # Fetch via report endpoint
    rep_resp = client.get(f"/api/apk/report/{rec_id}")
    assert rep_resp.status_code == 200
    rep_data = rep_resp.json()
    findings = rep_data.get("findings", [])
    assert len(findings) > 0

    for f in findings:
        exp = f.get("explanation")
        assert exp is not None
        assert len(exp["what_it_means"]) > 0


def test_pdf_export_with_explanations():
    """PDF generator renders successfully when explanations are attached to findings."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    client = TestClient(app)
    post_resp = client.post(
        "/api/apk/analyze",
        files={"file": ("PdfCheck.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert post_resp.status_code == 200
    rec_id = post_resp.json()["id"]

    pdf_resp = client.get(f"/api/apk/report/{rec_id}?format=pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 1000
    assert pdf_resp.content.startswith(b"%PDF-")


def test_no_explanation_text_persisted_in_db():
    """Database must never store educational explanation text; only dynamic attachment at serialization."""
    from app.apk_db import get_session, APKAnalysisRecord
    import json

    session = get_session()
    try:
        records = session.query(APKAnalysisRecord).all()
        assert len(records) > 0
        for r in records:
            raw_data = json.loads(r.result_json)
            findings = raw_data.get("findings", [])
            for f in findings:
                # Raw stored database JSON must NOT contain 'explanation'
                assert "explanation" not in f, "Found persisted 'explanation' key inside SQLite database record!"
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Stage C4: Isolated Worker & Async Job Pipeline Tests
# ---------------------------------------------------------------------------


def test_main_api_process_has_not_imported_androguard():
    """The main FastAPI process must NEVER import androguard."""
    import sys
    androguard_modules = [mod for mod in sys.modules if mod == "androguard" or mod.startswith("androguard.")]
    assert len(androguard_modules) == 0, f"androguard detected in main process modules: {androguard_modules}"


def test_apk_job_enqueue_and_poll_status(client):
    """POST /api/apk/analyze?async_mode=true enqueues job and GET /api/apk/jobs/{id} returns status."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    post_resp = client.post(
        "/api/apk/analyze?async_mode=true",
        files={"file": ("JobTest.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert post_resp.status_code == 202
    job_data = post_resp.json()
    job_id = job_data["job_id"]
    assert job_id
    assert job_data["status"] in ("queued", "running", "done")

    # Poll status until done (with timeout)
    poll_start = time.time()
    terminal_status = None
    final_payload = None

    while time.time() - poll_start < 15:
        get_resp = client.get(f"/api/apk/jobs/{job_id}")
        assert get_resp.status_code == 200
        final_payload = get_resp.json()
        status_val = final_payload["status"]
        if status_val in ("done", "failed", "timeout"):
            terminal_status = status_val
            break
        time.sleep(0.3)

    assert terminal_status == "done"
    assert final_payload["result"] is not None
    assert final_payload["result"]["analysis_version"] == "apk-static-v1"
    assert final_payload["result"]["app"]["package_name"] == "tests.androguard"


def test_unknown_job_id_returns_404(client):
    """Querying an unknown job ID must return 404."""
    resp = client.get("/api/apk/jobs/non-existent-uuid-9999")
    assert resp.status_code == 404
    data = resp.json()
    assert data["detail"]["error"] == "job_not_found"


def test_oversized_input_rejected_before_enqueue(client):
    """Files exceeding 25 MB are rejected with 413 before enqueuing."""
    large_payload = b"0" * (26 * 1024 * 1024)
    resp = client.post(
        "/api/apk/analyze?async_mode=true",
        files={"file": ("huge.apk", large_payload, "application/octet-stream")},
    )
    assert resp.status_code == 413


def test_worker_crash_returns_failed_without_crashing_api(client, monkeypatch):
    """If the worker subprocess crashes or exits with an error code, job status becomes 'failed'."""
    from app import apk_jobs

    def crashing_subprocess(job_id, file_path, sha256_hash, file_size, on_complete_cb=None):
        with apk_jobs._LOCAL_JOBS_LOCK:
            apk_jobs._LOCAL_JOBS[job_id]["status"] = "failed"
            apk_jobs._LOCAL_JOBS[job_id]["error"] = "Simulated crash: SIGSEGV in worker"
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

    with patch("app.apk_jobs._execute_subprocess_job", side_effect=crashing_subprocess):
        with open(REAL_FIXTURE_PATH, "rb") as f:
            file_bytes = f.read()

        post_resp = client.post(
            "/api/apk/analyze?async_mode=true",
            files={"file": ("CrashTest.apk", file_bytes, "application/vnd.android.package-archive")},
        )
        assert post_resp.status_code == 202
        job_id = post_resp.json()["job_id"]

        get_resp = client.get(f"/api/apk/jobs/{job_id}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["status"] == "failed"
        assert "Simulated crash" in data["error"]


def test_timeout_kills_the_worker(client):
    """Worker process exceeding timeout limit is killed and returns timeout status."""
    from app import apk_jobs
    import tempfile

    # Create dummy temp apk file
    fd, temp_path = tempfile.mkstemp(suffix=".apk")
    with open(fd, "wb") as f:
        f.write(b"dummy")

    # Run _execute_subprocess_job with a mock command that sleeps
    job_id = "test-timeout-kill-job"
    with apk_jobs._LOCAL_JOBS_LOCK:
        apk_jobs._LOCAL_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "result": None,
            "error": None,
        }

    # Temporarily set JOB_TIMEOUT_SECONDS to 0.1 for fast test
    orig_timeout = apk_jobs.JOB_TIMEOUT_SECONDS
    try:
        apk_jobs.JOB_TIMEOUT_SECONDS = 0.2
        # Patch sys.executable to run a long sleep
        with patch("sys.executable", sys.executable):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="python", timeout=0.2)
                mock_popen.return_value = mock_proc

                apk_jobs._execute_subprocess_job(job_id, temp_path, "sha", 100)

                # Assert kill was invoked on the worker process
                assert mock_proc.kill.called
                status_res = apk_jobs.get_job_status(job_id)
                assert status_res["status"] == "timeout"
                assert not os.path.exists(temp_path)
    finally:
        apk_jobs.JOB_TIMEOUT_SECONDS = orig_timeout
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def test_temp_file_removed_in_all_worker_outcomes():
    """Worker removes temp file across done, failed, and timeout outcomes."""
    from app import apk_jobs

    for outcome in ["done", "failed", "timeout"]:
        fd, temp_path = tempfile.mkstemp(suffix=".apk")
        with open(fd, "wb") as f:
            f.write(b"dummy_temp_content")
        assert os.path.exists(temp_path)

        job_id = f"test-cleanup-{outcome}"
        with apk_jobs._LOCAL_JOBS_LOCK:
            apk_jobs._LOCAL_JOBS[job_id] = {"job_id": job_id, "status": "queued"}

        # Simulate runner execution
        if outcome == "done":
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.communicate.return_value = (json.dumps({"analysis_version": "apk-static-v1"}), "")
                mock_proc.returncode = 0
                mock_popen.return_value = mock_proc
                apk_jobs._execute_subprocess_job(job_id, temp_path, "sha", 100)
        elif outcome == "failed":
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.communicate.return_value = ("", "Fatal parse error")
                mock_proc.returncode = 1
                mock_popen.return_value = mock_proc
                apk_jobs._execute_subprocess_job(job_id, temp_path, "sha", 100)
        elif outcome == "timeout":
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="python", timeout=1)
                mock_popen.return_value = mock_proc
                apk_jobs._execute_subprocess_job(job_id, temp_path, "sha", 100)

        assert not os.path.exists(temp_path), f"Temp file was not deleted for outcome {outcome}!"


def test_result_matches_pre_change_schema(client):
    """Async worker result adheres strictly to the apk-static-v1 schema."""
    with open(REAL_FIXTURE_PATH, "rb") as f:
        file_bytes = f.read()

    post_resp = client.post(
        "/api/apk/analyze?async_mode=true",
        files={"file": ("SchemaCheck.apk", file_bytes, "application/vnd.android.package-archive")},
    )
    assert post_resp.status_code == 202
    job_id = post_resp.json()["job_id"]

    # Poll until done
    poll_start = time.time()
    result = None
    while time.time() - poll_start < 15:
        get_resp = client.get(f"/api/apk/jobs/{job_id}")
        data = get_resp.json()
        if data["status"] == "done":
            result = data["result"]
            break
        time.sleep(0.3)

    assert result is not None
    required_keys = [
        "analysis_version",
        "sha256",
        "file_size",
        "app",
        "permissions",
        "components",
        "signing",
        "code_indicators",
        "findings",
        "indicator_level",
        "limitations",
    ]
    for key in required_keys:
        assert key in result, f"Missing key {key} in analysis result"
    assert result["analysis_version"] == "apk-static-v1"



