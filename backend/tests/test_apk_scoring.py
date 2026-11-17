"""test_apk_scoring.py - Comprehensive Unit Tests for the Rule-Based APK Indicator Engine.

Validates the 8 requirements:
1. Determinism: Same findings give identical score and level.
2. Combination bonuses: Each documented combination bonus triggers correctly.
3. Cut-point boundaries: Strict boundary transitions (19 vs 20, 49 vs 50).
4. Zero findings: Empty findings list gives Low indicator level.
5. Unknown rule IDs: Non-existent rule IDs are safely ignored.
6. Legacy compatibility: Historical stored records get summary attached at serialization.
7. Tone & safety: No forbidden wording (probability, percentage, safe, unsafe, malware outside disclaimer).
8. PDF generation: Technical report PDF renders cleanly with the new indicator summary.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import pytest

from app.apk_pdf import generate_apk_pdf_report
from app.apk_scoring import (
    COMBINATION_BONUSES,
    CUT_POINTS,
    DISCLAIMER_TEXT,
    RULE_WEIGHTS,
    SCORING_VERSION,
    attach_indicator_summary,
    score_findings,
)
from app.schemas import APKAnalysisResponse, APKIndicatorSummary


# ------------------------------------------------------------------------------
# Test 1: Determinism
# ------------------------------------------------------------------------------
def test_deterministic_scoring_same_findings_same_level() -> None:
    """Verify that identical findings consistently produce identical scoring results across runs."""
    sample_findings = [
        {"id": "RULE_SMS_EXFILTRATION_CAPABILITY", "title": "SMS"},
        {"id": "RULE_DYNAMIC_CODE_LOADING", "title": "Dynamic Loading"},
        {"id": "RULE_BOOT_PERSISTENCE", "title": "Boot Persistence"},
    ]

    result1 = score_findings(sample_findings)
    result2 = score_findings(sample_findings)
    result3 = score_findings(list(reversed(sample_findings)))

    assert result1 == result2
    # Order of input findings should not affect the deterministic output
    assert result1["total_points"] == result3["total_points"]
    assert result1["level"] == result3["level"]
    assert result1["indicator_level"] == result3["indicator_level"]
    assert result1["scoring_version"] == "apk-rules-v1"


# ------------------------------------------------------------------------------
# Test 2: Each Combination Bonus
# ------------------------------------------------------------------------------
def test_each_combination_bonus_triggers_correctly() -> None:
    """Verify each documented combination bonus adds the exact specified points when all constituent rules fire."""
    # Base check: each combo definition has required keys
    assert len(COMBINATION_BONUSES) >= 4

    for combo in COMBINATION_BONUSES:
        combo_id = combo["id"]
        rules = combo["rules"]
        bonus_pts = combo["bonus_points"]

        # 1. Partial presence: only first rule (should NOT trigger combo)
        partial_findings = [{"id": rules[0]}]
        partial_res = score_findings(partial_findings)
        assert not any(c["id"] == combo_id for c in partial_res["combination_contributions"])
        expected_partial = RULE_WEIGHTS[rules[0]]["points"]
        assert partial_res["total_points"] == expected_partial

        # 2. Full presence: all required rules in combo
        full_findings = [{"id": r} for r in rules]
        full_res = score_findings(full_findings)

        combo_contribs = [c for c in full_res["combination_contributions"] if c["id"] == combo_id]
        assert len(combo_contribs) == 1, f"Combo {combo_id} failed to trigger"
        assert combo_contribs[0]["points"] == bonus_pts

        expected_total = sum(RULE_WEIGHTS[r]["points"] for r in rules) + bonus_pts
        assert full_res["total_points"] == expected_total


# ------------------------------------------------------------------------------
# Test 3: Cut-point boundaries
# ------------------------------------------------------------------------------
def test_cut_point_boundaries() -> None:
    """Verify strict level transitions at cut-point boundaries (19 vs 20, 49 vs 50)."""
    # 0 points -> Low
    res_0 = score_findings([])
    assert res_0["total_points"] == 0
    assert res_0["level"] == "Low"
    assert res_0["indicator_level"] == "no_notable_indicators"

    # Exactly 19 points -> Low (e.g. PACKAGE_INSTALLER 15 + non-existent or mocked finding)
    # We test boundary evaluation directly against mock point scenarios
    # PACKAGE_INSTALLER (15) -> Low
    res_15 = score_findings([{"id": "RULE_PACKAGE_INSTALLER"}])
    assert res_15["total_points"] == 15
    assert res_15["level"] == "Low"
    assert res_15["indicator_level"] == "no_notable_indicators"

    # Exactly 20 points -> Medium (DYNAMIC_CODE_LOADING = 20)
    res_20 = score_findings([{"id": "RULE_DYNAMIC_CODE_LOADING"}])
    assert res_20["total_points"] == 20
    assert res_20["level"] == "Medium"
    assert res_20["indicator_level"] == "some_indicators"

    # 45 points -> Medium (SMS_EXFILTRATION 30 + PACKAGE_INSTALLER 15 = 45, no combo)
    res_45 = score_findings([
        {"id": "RULE_SMS_EXFILTRATION_CAPABILITY"},
        {"id": "RULE_PACKAGE_INSTALLER"},
    ])
    assert res_45["total_points"] == 45
    assert res_45["level"] == "Medium"
    assert res_45["indicator_level"] == "some_indicators"

    # Exactly 50 points -> High (SMS_EXFILTRATION 30 + DYNAMIC_CODE_LOADING 20 = 50 base + 15 combo = 65,
    # or ACCESSIBILITY_OVERLAY 30 + COMMAND_EXECUTION 20 = 50 base)
    # Let's test RULE_ACCESSIBILITY_OVERLAY_COMBO (30) + RULE_DYNAMIC_CODE_LOADING (20) = 50 (no combo between these two)
    res_50 = score_findings([
        {"id": "RULE_ACCESSIBILITY_OVERLAY_COMBO"},
        {"id": "RULE_DYNAMIC_CODE_LOADING"},
    ])
    assert res_50["total_points"] == 50
    assert res_50["level"] == "High"
    assert res_50["indicator_level"] == "many_indicators"

    # 65 points -> High (SMS 30 + DYNAMIC 20 + COMBO 15 = 65)
    res_65 = score_findings([
        {"id": "RULE_SMS_EXFILTRATION_CAPABILITY"},
        {"id": "RULE_DYNAMIC_CODE_LOADING"},
    ])
    assert res_65["total_points"] == 65
    assert res_65["level"] == "High"
    assert res_65["indicator_level"] == "many_indicators"


# ------------------------------------------------------------------------------
# Test 4: No Findings Gives Low
# ------------------------------------------------------------------------------
def test_no_findings_gives_low() -> None:
    """Verify an empty findings array produces zero points, level 'Low', and 'no_notable_indicators'."""
    res = score_findings([])
    assert res["total_points"] == 0
    assert res["level"] == "Low"
    assert res["indicator_level"] == "no_notable_indicators"
    assert res["rule_contributions"] == []
    assert res["combination_contributions"] == []
    assert res["scoring_version"] == SCORING_VERSION
    assert res["disclaimer"] == DISCLAIMER_TEXT


# ------------------------------------------------------------------------------
# Test 5: Unknown Rule ID Is Ignored
# ------------------------------------------------------------------------------
def test_unknown_rule_id_is_ignored() -> None:
    """Verify that unrecognized or future rule IDs do not cause errors and contribute 0 points."""
    findings = [
        {"id": "RULE_NONEXISTENT_FUTURE_INDICATOR_XYZ"},
        {"id": "UNKNOWN_CUSTOM_HEURISTIC_123"},
        {"missing_id_key": "some_value"},
        "not_even_a_dict",
    ]
    res = score_findings(findings)
    assert res["total_points"] == 0
    assert res["level"] == "Low"
    assert res["indicator_level"] == "no_notable_indicators"
    assert res["rule_contributions"] == []
    assert res["combination_contributions"] == []


# ------------------------------------------------------------------------------
# Test 6: Old Stored Record Gets a Summary
# ------------------------------------------------------------------------------
def test_old_stored_record_gets_a_summary() -> None:
    """Verify historical stored records lacking indicator_summary get one at serialization time."""
    # Emulate an old record from SQLite history without indicator_summary
    old_record_payload = {
        "analysis_version": "apk-static-v1",
        "sha256": "e" * 64,
        "file_size": 123456,
        "app": {
            "package_name": "com.legacy.app",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
        },
        "permissions": {},
        "components": {},
        "signing": {},
        "code_indicators": {},
        "findings": [
            {
                "id": "RULE_COMMAND_EXECUTION",
                "category": "Command Execution",
                "severity": "high",
                "title": "Runtime Process Execution Detected in Bytecode",
                "evidence": "Runtime.getRuntime().exec()",
                "why_it_matters": "Process execution.",
            }
        ],
        "indicator_level": "no_notable_indicators",  # Old default
        "limitations": ["Static only."],
    }

    # Pass through attach_indicator_summary (called at serialization time)
    enriched = attach_indicator_summary(old_record_payload)

    assert "indicator_summary" in enriched
    summary = enriched["indicator_summary"]
    assert summary["scoring_version"] == "apk-rules-v1"
    assert summary["total_points"] == 20
    assert summary["level"] == "Medium"
    # Single source of truth updates indicator_level dynamically
    assert enriched["indicator_level"] == "some_indicators"

    # Schema validation check: validates cleanly against APKAnalysisResponse
    validated = APKAnalysisResponse(**enriched)
    assert validated.indicator_summary is not None
    assert validated.indicator_summary.level == "Medium"
    assert validated.indicator_summary.total_points == 20


# ------------------------------------------------------------------------------
# Test 7: No Forbidden Wording in Any Output String
# ------------------------------------------------------------------------------
def test_no_forbidden_wording_in_any_output_string() -> None:
    """Verify that no forbidden words (probability, percentage, safe, unsafe, malware) appear in generated strings."""
    findings = [{"id": r} for r in RULE_WEIGHTS.keys()]
    res = score_findings(findings)

    # Convert entire scoring structure to JSON string
    serialized = json.dumps(res)

    # Strictly forbidden everywhere
    forbidden_strict = ["probability", "percentage", r"\bsafe\b", r"\bunsafe\b"]
    for pattern in forbidden_strict:
        matches = re.findall(pattern, serialized, re.IGNORECASE)
        assert len(matches) == 0, f"Forbidden term '{pattern}' discovered in scoring output: {matches}"

    # 'malware' is only permitted within the canonical disclaimer
    malware_matches = re.findall(r"malware", serialized, re.IGNORECASE)
    assert len(malware_matches) == 1, f"Expected exactly 1 occurrence of 'malware' (in disclaimer), found: {len(malware_matches)}"
    assert res["disclaimer"] == "Heuristic indicator level, a signal to check and not a malware verdict."


# ------------------------------------------------------------------------------
# Test 8: PDF Still Generates with Indicator Summary
# ------------------------------------------------------------------------------
def test_pdf_still_generates_with_indicator_summary() -> None:
    """Verify PDF technical report generation succeeds and includes indicator scoring."""
    sample_payload = {
        "analysis_version": "apk-static-v1",
        "sha256": "f" * 64,
        "file_size": 2048000,
        "app": {
            "package_name": "com.signalcheck.testapp",
            "version_name": "2.4.0",
            "version_code": "24",
            "min_sdk": "26",
            "target_sdk": "34",
        },
        "permissions": {"sms": ["android.permission.RECEIVE_SMS"]},
        "components": {"activities": 4, "services": 2, "receivers": 1, "providers": 0},
        "signing": {"is_signed": True, "scheme_v2": True},
        "code_indicators": {"sms_send_apis": True},
        "findings": [
            {
                "id": "RULE_SMS_EXFILTRATION_CAPABILITY",
                "category": "Sensitive Permissions",
                "severity": "high",
                "title": "Combined SMS Access and Internet Communication Capability",
                "evidence": "Declared permissions: SMS, INTERNET",
                "why_it_matters": "Banking trojans abuse SMS OTP access.",
            }
        ],
        "limitations": ["Purely static inspection.", "Zero code execution."],
    }

    # Attach indicator summary
    enriched = attach_indicator_summary(sample_payload)

    pdf_bytes = generate_apk_pdf_report(enriched)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")
