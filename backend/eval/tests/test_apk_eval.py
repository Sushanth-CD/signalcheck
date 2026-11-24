"""test_apk_eval.py - Unit tests for the APK Heuristic Rule Evaluation Harness (Stage C5).

Verifies:
1. wilson_score_interval helper returns correct known values and handles edge cases.
2. The eval harness runs cleanly on test APK fixtures via isolated worker subprocess without importing androguard.
3. Corrupt/invalid files are safely recorded as failures/rejections and skipped without halting evaluation.
4. Empty directory or pending state produces clear notification messages without crashing.
5. Generated CSV contains no filenames or file paths (strict privacy / SHA-256 only).
6. Subprocess timeout is recorded as failure without stopping the evaluation of subsequent samples.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from eval.run_eval import (
    CSV_HEADERS,
    RULE_IDS,
    evaluate_directory,
    generate_summary_markdown,
    pre_validate_apk_file,
    wilson_score_interval,
    analyze_sample_subprocess,
)

FIXTURE_APK = Path("backend/tests/fixtures/ANDROGUARD_TESTS_TestActivity.apk")


def test_wilson_score_interval_known_values():
    """Verify Wilson score confidence interval calculation on standard reference cases."""
    # Empty / zero cases
    low, high = wilson_score_interval(0, 0)
    assert low == 0.0
    assert high == 0.0

    # 0 successes out of 10 trials (standard 95% Wilson bound: ~0.0 to 0.2775)
    low, high = wilson_score_interval(0, 10, confidence=0.95)
    assert low == 0.0
    assert 0.25 < high < 0.30

    # 10 successes out of 10 trials
    low, high = wilson_score_interval(10, 10, confidence=0.95)
    assert 0.70 < low < 0.75
    assert pytest.approx(high, abs=1e-5) == 1.0

    # 50 out of 100 trials (~0.50 center, bounds ~0.40 to 0.60)
    low, high = wilson_score_interval(50, 100, confidence=0.95)
    assert 0.40 < low < 0.45
    assert 0.55 < high < 0.60
    assert low < 0.5 < high


@pytest.mark.slow
def test_eval_harness_runs_on_fixture(tmp_path: Path):
    """Verify that evaluate_directory runs cleanly on an APK fixture without error."""
    assert FIXTURE_APK.exists(), f"Fixture APK not found at {FIXTURE_APK}"

    benign_dir = tmp_path / "benign"
    benign_dir.mkdir(parents=True)
    target_apk = benign_dir / "sample_test.apk"
    shutil.copyfile(FIXTURE_APK, target_apk)

    records = evaluate_directory(str(benign_dir), "benign")
    assert len(records) == 1
    rec = records[0]

    assert rec["group"] == "benign"
    assert rec["outcome"] == "SUCCESS"
    assert len(rec["sha256"]) == 64  # Valid SHA-256 hex string

    # Ensure all rule columns are present and either 0 or 1
    for r_id in RULE_IDS:
        assert r_id in rec
        assert rec[r_id] in (0, 1)


@pytest.mark.slow
def test_eval_corrupt_file_recorded_and_skipped(tmp_path: Path):
    """Verify that corrupt or non-zip files are recorded as REJECTED and do not crash the harness."""
    suspicious_dir = tmp_path / "suspicious"
    suspicious_dir.mkdir(parents=True)

    # File with invalid zip header
    bad_apk = suspicious_dir / "corrupted.apk"
    bad_apk.write_bytes(b"NOT_A_ZIP_HEADER_DATA_123456789")

    # Also place a valid fixture so we verify subsequent files still process
    valid_apk = suspicious_dir / "valid_followup.apk"
    shutil.copyfile(FIXTURE_APK, valid_apk)

    records = evaluate_directory(str(suspicious_dir), "suspicious")
    assert len(records) == 2

    # First record should be rejected
    r1 = records[0]
    assert r1["group"] == "suspicious"
    assert r1["outcome"].startswith("REJECTED")

    # Second record should succeed
    r2 = records[1]
    assert r2["group"] == "suspicious"
    assert r2["outcome"] == "SUCCESS"


def test_eval_empty_folder_gives_clear_message(tmp_path: Path):
    """Verify that empty directories are handled gracefully with a clear pending/warning message."""
    empty_benign = tmp_path / "benign"
    empty_suspicious = tmp_path / "suspicious"
    empty_benign.mkdir()
    empty_suspicious.mkdir()

    benign_records = evaluate_directory(str(empty_benign), "benign")
    suspicious_records = evaluate_directory(str(empty_suspicious), "suspicious")

    assert len(benign_records) == 0
    assert len(suspicious_records) == 0

    summary_file = tmp_path / "summary.md"
    md_content = generate_summary_markdown(benign_records, suspicious_records, str(summary_file))

    assert "Pending Samples" in md_content
    assert "Evaluation data directories" in md_content
    assert summary_file.exists()


@pytest.mark.slow
def test_eval_csv_contains_no_filenames_or_paths(tmp_path: Path):
    """Verify that results.csv output contains strictly privacy-preserving columns (SHA-256 only, no paths)."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    apk_file = data_dir / "secret_personal_test_app_v1.apk"
    shutil.copyfile(FIXTURE_APK, apk_file)

    records = evaluate_directory(str(data_dir), "benign")
    assert len(records) == 1

    csv_path = tmp_path / "results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = CSV_HEADERS
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    with open(csv_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Must contain sha256 header and hex
    assert "sha256" in content
    assert records[0]["sha256"] in content

    # Must NOT contain the original file name or any directory path
    assert "secret_personal_test_app_v1.apk" not in content
    assert str(apk_file) not in content
    assert "secret_personal" not in content


def test_eval_timeout_recorded_as_failure_without_stopping_run(tmp_path: Path):
    """Verify that a worker subprocess timeout is caught, recorded as TIMEOUT, and next sample proceeds."""
    test_dir = tmp_path / "samples"
    test_dir.mkdir()
    apk1 = test_dir / "sample1.apk"
    apk2 = test_dir / "sample2.apk"
    shutil.copyfile(FIXTURE_APK, apk1)
    shutil.copyfile(FIXTURE_APK, apk2)

    # Mock Popen.communicate to simulate a timeout on the first sample, then success on the second
    call_count = 0

    real_popen = subprocess.Popen

    def mock_popen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        proc = real_popen(*args, **kwargs)
        if call_count == 1:
            # First sample simulates timeout
            orig_communicate = proc.communicate

            def timeout_communicate(*c_args, **c_kwargs):
                raise subprocess.TimeoutExpired(cmd=args[0], timeout=30)

            proc.communicate = timeout_communicate
        return proc

    with patch("subprocess.Popen", side_effect=mock_popen):
        records = evaluate_directory(str(test_dir), "benign")

    assert len(records) == 2
    assert records[0]["outcome"] == "TIMEOUT"
    assert records[1]["outcome"] == "SUCCESS"
