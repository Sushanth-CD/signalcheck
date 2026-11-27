"""test_apk_scoring.py - Comprehensive Unit Tests for the Rule-Based APK Indicator Engine (Offline Evaluation).

Validates the offline evaluation rule scoring requirements:
1. Determinism: Same findings give identical score and level.
2. Combination bonuses: Each documented combination bonus triggers correctly.
3. Cut-point boundaries: Strict boundary transitions (19 vs 20, 49 vs 50).
4. Zero findings: Empty findings list gives Low indicator level.
5. Unknown rule IDs: Non-existent rule IDs are safely ignored.
6. Record enrichment: Historical records get summary attached at serialization.
7. Tone & safety: No forbidden wording (probability, percentage, safe, unsafe, malware outside disclaimer).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import pytest

from eval.apk_scoring import (
    COMBINATION_BONUSES,
    CUT_POINTS,
    DISCLAIMER_TEXT,
    RULE_WEIGHTS,
    SCORING_VERSION,
    attach_indicator_summary,
    score_findings,
)


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
    assert result1 == result3
    assert result1["scoring_version"] == "apk-rules-v1"
    assert result1["level"] in ("Low", "Medium", "High")
    assert isinstance(result1["total_points"], int)


# ------------------------------------------------------------------------------
# Test 2: Combination Bonuses
# ------------------------------------------------------------------------------
def test_each_combination_bonus_triggers_correctly() -> None:
    """Verify that each of the 4 defined combination bonuses triggers when its prerequisite rules are present."""
    expected_combos = {
        "COMBO_SMS_DYNAMIC": {
            "rules": ["RULE_SMS_EXFILTRATION_CAPABILITY", "RULE_DYNAMIC_CODE_LOADING"],
            "bonus": 15,
        },
        "COMBO_OVERLAY_COMMAND": {
            "rules": ["RULE_ACCESSIBILITY_OVERLAY_COMBO", "RULE_COMMAND_EXECUTION"],
            "bonus": 15,
        },
        "COMBO_INSTALLER_DYNAMIC": {
            "rules": ["RULE_PACKAGE_INSTALLER", "RULE_DYNAMIC_CODE_LOADING"],
            "bonus": 15,
        },
        "COMBO_ADMIN_PERSISTENCE": {
            "rules": ["RULE_DEVICE_ADMIN_PRIVILEGE", "RULE_BOOT_PERSISTENCE"],
            "bonus": 10,
        },
    }

    assert len(COMBINATION_BONUSES) == 4

    for combo_id, spec in expected_combos.items():
        prereqs = spec["rules"]
        bonus = spec["bonus"]

        # Base score of individual rules alone
        base_points = sum(RULE_WEIGHTS[r]["points"] for r in prereqs)

        # 1. Test presence of all prerequisites -> bonus MUST trigger
        findings_with_all = [{"id": r} for r in prereqs]
        res_full = score_findings(findings_with_all)
        combo_matches = [c for c in res_full["combination_contributions"] if c["id"] == combo_id]

        assert len(combo_matches) == 1, f"Expected combo {combo_id} to fire when {prereqs} are present"
        assert combo_matches[0]["points"] == bonus
        assert res_full["total_points"] == base_points + bonus

        # 2. Test omission of one prerequisite -> bonus MUST NOT trigger
        if len(prereqs) > 1:
            findings_partial = [{"id": prereqs[0]}]
            res_partial = score_findings(findings_partial)
            partial_matches = [c for c in res_partial["combination_contributions"] if c["id"] == combo_id]
            assert len(partial_matches) == 0, f"Combo {combo_id} triggered with only partial prereqs!"


# ------------------------------------------------------------------------------
# Test 3: Cut Point Boundaries
# ------------------------------------------------------------------------------
def test_cut_point_boundaries() -> None:
    """Verify cut point boundaries:

    - 0 to 19: Low
    - 20 to 49: Medium
    - 50+: High
    """
    assert CUT_POINTS["LOW_MAX"] == 19
    assert CUT_POINTS["MEDIUM_MIN"] == 20
    assert CUT_POINTS["MEDIUM_MAX"] == 49
    assert CUT_POINTS["HIGH_MIN"] == 50

    # Exactly 0 points -> Low
    res_0 = score_findings([])
    assert res_0["total_points"] == 0
    assert res_0["level"] == "Low"
    assert res_0["indicator_level"] == "no_notable_indicators"

    # Exactly 10 points -> Low (RULE_BOOT_PERSISTENCE = 10)
    res_10 = score_findings([{"id": "RULE_BOOT_PERSISTENCE"}])
    assert res_10["total_points"] == 10
    assert res_10["level"] == "Low"
    assert res_10["indicator_level"] == "no_notable_indicators"

    # Exactly 15 points -> Low (RULE_PACKAGE_INSTALLER = 15)
    res_15 = score_findings([{"id": "RULE_PACKAGE_INSTALLER"}])
    assert res_15["total_points"] == 15
    assert res_15["level"] == "Low"
    assert res_15["indicator_level"] == "no_notable_indicators"

    # Exactly 20 points -> Medium (RULE_COMMAND_EXECUTION = 20)
    res_20 = score_findings([{"id": "RULE_COMMAND_EXECUTION"}])
    assert res_20["total_points"] == 20
    assert res_20["level"] == "Medium"
    assert res_20["indicator_level"] == "some_indicators"

    # Exactly 45 points -> Medium (RULE_SMS_EXFILTRATION_CAPABILITY [30] + RULE_PACKAGE_INSTALLER [15] = 45, no combo)
    res_45 = score_findings([
        {"id": "RULE_SMS_EXFILTRATION_CAPABILITY"},
        {"id": "RULE_PACKAGE_INSTALLER"},
    ])
    assert res_45["total_points"] == 45
    assert res_45["level"] == "Medium"
    assert res_45["indicator_level"] == "some_indicators"

    # Exactly 50 points -> High (RULE_SMS_EXFILTRATION_CAPABILITY [30] + RULE_DYNAMIC_CODE_LOADING [20] = 50 + combo [15] = 65)
    # Let's create an exact 50: RULE_ACCESSIBILITY_OVERLAY_COMBO (30) + RULE_COMMAND_EXECUTION (20) -> triggers COMBO_OVERLAY_COMMAND (+15) = 65.
    # To get >= 50 without combo:
    # RULE_ACCESSIBILITY_OVERLAY_COMBO (30) + RULE_DYNAMIC_CODE_LOADING (20) = 50 points (no combo)
    res_50 = score_findings([
        {"id": "RULE_ACCESSIBILITY_OVERLAY_COMBO"},
        {"id": "RULE_DYNAMIC_CODE_LOADING"},
    ])
    assert res_50["total_points"] == 50
    assert res_50["level"] == "High"
    assert res_50["indicator_level"] == "many_indicators"

    # Above 50 -> High
    res_high = score_findings([
        {"id": "RULE_SMS_EXFILTRATION_CAPABILITY"},
        {"id": "RULE_ACCESSIBILITY_OVERLAY_COMBO"},
    ])
    assert res_high["total_points"] == 60
    assert res_high["level"] == "High"
    assert res_high["indicator_level"] == "many_indicators"


# ------------------------------------------------------------------------------
# Test 4: Zero Findings
# ------------------------------------------------------------------------------
def test_no_findings_gives_low() -> None:
    """Verify that an APK with no triggered findings receives 0 points and 'Low' level."""
    res = score_findings([])
    assert res["total_points"] == 0
    assert res["level"] == "Low"
    assert res["indicator_level"] == "no_notable_indicators"
    assert len(res["rule_contributions"]) == 0
    assert len(res["combination_contributions"]) == 0
    assert res["scoring_version"] == "apk-rules-v1"
    assert res["disclaimer"] == DISCLAIMER_TEXT


# ------------------------------------------------------------------------------
# Test 5: Unknown Rule IDs Safely Ignored
# ------------------------------------------------------------------------------
def test_unknown_rule_id_is_ignored() -> None:
    """Verify that unrecognized or future rule IDs do not cause key errors or incorrect point totals."""
    findings = [
        {"id": "RULE_NON_EXISTENT_FUTURE_RULE_999"},
        {"id": "MALWARE_TRIGGER_FAKE"},
        {"id": ""},
        {"not_even_id_key": "val"},
        {"id": "RULE_BOOT_PERSISTENCE"},  # Valid rule (10 pts)
    ]
    res = score_findings(findings)
    assert res["total_points"] == 10
    assert res["level"] == "Low"
    assert len(res["rule_contributions"]) == 1
    assert res["rule_contributions"][0]["rule_id"] == "RULE_BOOT_PERSISTENCE"


# ------------------------------------------------------------------------------
# Test 6: Old Stored Record Gets a Summary
# ------------------------------------------------------------------------------
def test_old_stored_record_gets_a_summary() -> None:
    """Verify historical stored records lacking indicator_summary get one at serialization time."""
    old_record_payload = {
        "analysis_version": "apk-static-v1",
        "sha256": "e" * 64,
        "file_size": 123456,
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

    enriched = attach_indicator_summary(old_record_payload)

    assert "indicator_summary" in enriched
    summary = enriched["indicator_summary"]
    assert summary["scoring_version"] == "apk-rules-v1"
    assert summary["total_points"] == 20
    assert summary["level"] == "Medium"
    assert enriched["indicator_level"] == "some_indicators"


# ------------------------------------------------------------------------------
# Test 7: No Forbidden Wording in Any Output String
# ------------------------------------------------------------------------------
def test_no_forbidden_wording_in_any_output_string() -> None:
    """Verify that no forbidden words (probability, percentage, safe, unsafe, malware) appear in generated strings."""
    findings = [{"id": r} for r in RULE_WEIGHTS.keys()]
    res = score_findings(findings)

    serialized = json.dumps(res)

    forbidden_strict = ["probability", "percentage", r"\bsafe\b", r"\bunsafe\b"]
    for pattern in forbidden_strict:
        matches = re.findall(pattern, serialized, re.IGNORECASE)
        assert len(matches) == 0, f"Forbidden term '{pattern}' discovered in scoring output: {matches}"

    # 'malware' is only permitted within the canonical disclaimer
    malware_matches = re.findall(r"malware", serialized, re.IGNORECASE)
    assert len(malware_matches) == 1, f"Expected exactly 1 occurrence of 'malware' (in disclaimer), found: {len(malware_matches)}"
    assert res["disclaimer"] == "Heuristic indicator level, a signal to check and not a malware verdict."
