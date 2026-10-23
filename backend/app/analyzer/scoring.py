"""Risk aggregation for findings produced by the enabled rule modules."""

from collections.abc import Iterable

from app.schemas import AnalysisResponse, DetectedIndicator, RiskLevel


def risk_level_for_score(score: int) -> RiskLevel:
    """Map a capped heuristic score to the contract's provisional band."""

    if not 0 <= score <= 100:
        raise ValueError("risk score must be between 0 and 100")
    if score < 20:
        return RiskLevel.LOW
    if score < 50:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def score_findings(findings: Iterable[DetectedIndicator]) -> AnalysisResponse:
    """Deduplicate by canonical rule ID, sum contributions, and cap at 100."""

    unique: list[DetectedIndicator] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            unique.append(finding)

    score = min(100, sum(finding.score_contribution for finding in unique))
    level = risk_level_for_score(score)

    if unique:
        categories = {finding.category for finding in unique}
        if categories == {"digital_arrest"}:
            summary = "The text contains warning signs associated with a digital-arrest scam. Verify any claim independently."
        elif categories == {"malicious_application"}:
            summary = "The text describes potentially sensitive app permissions. Verify the app and whether those permissions are necessary."
        else:
            summary = "The text contains one or more warning signs that merit careful verification."
    else:
        summary = "No enabled warning indicators were identified in the submitted text. This does not prove that it is safe."

    recommendations = _recommendations(unique)
    return AnalysisResponse(
        risk_score=score,
        risk_level=level,
        summary=summary,
        detected_indicators=unique,
        recommendations=recommendations,
        disclaimer=(
            "This is a heuristic text assessment, not a fraud probability or definitive verdict. "
            "A low score does not prove that the content is safe."
        ),
    )


def _recommendations(findings: list[DetectedIndicator]) -> list[str]:
    categories = {finding.category for finding in findings}
    recommendations: list[str] = []
    if "phishing" in categories:
        recommendations.append(
            "Do not click an unexpected link or share passwords, OTPs, CVVs, or UPI PINs."
        )
    if "digital_arrest" in categories:
        recommendations.append(
            "Do not transfer money or disclose credentials; verify the claim through independently sourced official contacts."
        )
    if "malicious_application" in categories:
        recommendations.append(
            "Check whether the app needs these permissions and verify its developer before granting access."
        )
    if not recommendations:
        recommendations.append(
            "Remain cautious and verify unexpected requests using a separate trusted channel."
        )
    return recommendations
