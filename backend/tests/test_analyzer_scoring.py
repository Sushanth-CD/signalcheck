"""Tests for score aggregation and contract risk bands."""

import pytest

from app.analyzer import analyze_content
from app.analyzer.scoring import risk_level_for_score, score_findings
from app.schemas import DetectedIndicator, RiskLevel


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, RiskLevel.LOW),
        (19, RiskLevel.LOW),
        (20, RiskLevel.MEDIUM),
        (49, RiskLevel.MEDIUM),
        (50, RiskLevel.HIGH),
        (100, RiskLevel.HIGH),
    ],
)
def test_risk_band_boundaries(score: int, level: RiskLevel) -> None:
    assert risk_level_for_score(score) == level


@pytest.mark.parametrize("score", [-1, 101])
def test_risk_band_rejects_scores_outside_allowed_range(score: int) -> None:
    with pytest.raises(ValueError):
        risk_level_for_score(score)


def test_duplicate_rule_findings_contribute_only_once() -> None:
    finding = DetectedIndicator(
        rule_id="PH001",
        category="phishing",
        title="Requests a secret",
        score_contribution=25,
        explanation="A secret is requested.",
    )

    result = score_findings([finding, finding])

    assert result.risk_score == 25
    assert len(result.detected_indicators) == 1


def test_total_score_is_capped_and_consistent_with_unique_findings() -> None:
    ids_and_scores = [
        ("PH001", 25),
        ("DA001", 25),
        ("DA002", 25),
        ("URL001", 10),
        ("URL002", 15),
        ("APP001", 15),
        ("APP002", 15),
    ]
    findings = [
        DetectedIndicator(
            rule_id=rule_id,
            category="phishing",
            title=rule_id,
            score_contribution=contribution,
            explanation="A rule condition matched.",
        )
        for rule_id, contribution in ids_and_scores
    ]

    result = score_findings(findings)

    assert sum(f.score_contribution for f in result.detected_indicators) == 130
    assert result.risk_score == min(100, 130)
    assert result.risk_score <= 100
    assert result.risk_level == RiskLevel.HIGH


def test_complete_result_has_schema_fields_and_nonempty_explanations() -> None:
    result = analyze_content("We are from cybercrime police. Send your OTP now.")

    assert result.risk_score == 50
    assert result.risk_level == RiskLevel.HIGH
    assert result.summary
    assert result.disclaimer
    assert result.recommendations
    for finding in result.detected_indicators:
        assert finding.rule_id and finding.category and finding.title
        assert finding.score_contribution > 0
        assert finding.explanation


def test_da001_alone_contributes_25_and_maps_to_medium() -> None:
    result = analyze_content("We are from the cybercrime police. Transfer money now.")

    assert [(finding.rule_id, finding.score_contribution) for finding in result.detected_indicators] == [
        ("DA001", 25)
    ]
    assert result.risk_score == 25
    assert result.risk_level == RiskLevel.MEDIUM


def test_ph011_alone_contributes_25_and_maps_to_medium() -> None:
    result = analyze_content(
        "Your account may be terminated. Complete account verification using the link below."
    )
    assert [(item.rule_id, item.score_contribution) for item in result.detected_indicators] == [("PH011", 25)]
    assert result.risk_score == 25
    assert result.risk_level == RiskLevel.MEDIUM


def test_da001_and_da002_sum_to_50_and_map_to_high() -> None:
    result = analyze_content(
        "We are from the cybercrime police. Transfer money now. You are under digital arrest."
    )

    assert {finding.rule_id for finding in result.detected_indicators} == {"DA001", "DA002"}
    assert result.risk_score == 50
    assert result.risk_level == RiskLevel.HIGH


def test_duplicate_da001_findings_do_not_increase_its_contribution() -> None:
    finding = DetectedIndicator(
        rule_id="DA001",
        category="digital_arrest",
        title="Claims authority",
        score_contribution=25,
        explanation="Authority is claimed with coercive pressure.",
    )

    result = score_findings([finding, finding])

    assert result.risk_score == 25
    assert result.risk_level == RiskLevel.MEDIUM
    assert len(result.detected_indicators) == 1


def test_empty_content_returns_non_assertive_zero_score() -> None:
    result = analyze_content(" \n ")

    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.LOW
    assert not result.detected_indicators
    assert "does not prove" in result.summary
