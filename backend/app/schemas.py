"""Typed API schemas for the analysis service."""

from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(StrEnum):
    """Risk bands defined by the Version 1 analysis contract."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnalysisRequest(BaseModel):
    """Text submitted for analysis."""

    model_config = ConfigDict(extra="forbid")

    content: Annotated[str, Field(min_length=1, max_length=10_000)]

    @field_validator("content", mode="before")
    @classmethod
    def validate_and_trim_content(cls, value: Any) -> Any:
        if isinstance(value, str):
            if len(value) > 10_000:
                raise ValueError("content_too_long")
            value = value.strip()
            if not value:
                raise ValueError("content_empty")
        return value


class DetectedIndicator(BaseModel):
    """One explainable rule match in a completed analysis."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    title: str = Field(min_length=1)
    score_contribution: int = Field(ge=0, le=100)
    explanation: str = Field(min_length=1)


class AnalysisResponse(BaseModel):
    """Structured analysis result reserved for the implemented engine."""

    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    summary: str = Field(min_length=1)
    detected_indicators: list[DetectedIndicator]
    recommendations: list[str]
    disclaimer: str = Field(min_length=1)


class HealthResponse(BaseModel):
    """Health-check payload."""

    status: str = "ok"
