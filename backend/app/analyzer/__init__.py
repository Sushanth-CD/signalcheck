"""Deterministic Version 1 analysis modules."""

from app.analyzer.rules import detect_text_indicators
from app.analyzer.scoring import score_findings
from app.analyzer.urls import analyze_url_candidates, analyze_urls, extract_url_candidates
from app.schemas import AnalysisResponse


def analyze_content(content: str) -> AnalysisResponse:
    """Run the enabled local text and URL rules and aggregate their findings."""

    candidates = extract_url_candidates(content)
    findings = [*detect_text_indicators(content), *analyze_url_candidates(candidates)]
    result = score_findings(findings)
    if any(not candidate.is_valid for candidate in candidates):
        result = result.model_copy(
            update={
                "summary": (
                    f"{result.summary} One or more URL-like strings could not be parsed "
                    "and received no URL-specific points."
                )
            }
        )
    return result


__all__ = [
    "analyze_content",
    "analyze_url_candidates",
    "analyze_urls",
    "detect_text_indicators",
    "extract_url_candidates",
    "score_findings",
]
