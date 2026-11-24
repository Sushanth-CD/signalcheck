"""Typed API schemas for the analysis service."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator


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


class MLAnalysisResponse(BaseModel):
    """Result from the separate text-classification model endpoint."""

    model_config = ConfigDict(extra="forbid")

    classification: Literal["phishing", "benign"]
    phishing_score: float = Field(ge=0.0, le=1.0)
    score_kind: Literal["uncalibrated_model_score"] = "uncalibrated_model_score"
    threshold: float = Field(ge=0.0, le=1.0)
    model_id: str = Field(min_length=1)
    disclaimer: str = Field(min_length=1)


class AndroidMLAnalysisRequest(BaseModel):
    """Prepared named Android feature values; this is not an APK upload."""

    model_config = ConfigDict(extra="forbid")

    features: dict[str, Annotated[StrictInt, Field(ge=0, le=1)]] = Field(
        min_length=226,
        max_length=226,
    )


class AndroidMLAnalysisResponse(BaseModel):
    """Result from the separate Android permission-feature classifier."""

    model_config = ConfigDict(extra="forbid")

    classification: Literal["malicious", "non_malicious"]
    malware_score: float = Field(ge=0.0, le=1.0)
    score_kind: Literal["uncalibrated_model_score"] = "uncalibrated_model_score"
    threshold: float = Field(ge=0.0, le=1.0)
    model_id: str = Field(min_length=1)
    disclaimer: str = Field(min_length=1)


class HealthResponse(BaseModel):
    """Health-check payload."""

    status: str = "ok"


class SMSAnalysisRequest(BaseModel):
    """SMS message submitted for phishing analysis."""

    model_config = ConfigDict(extra="forbid")

    content: Annotated[str, Field(min_length=1, max_length=2_000)]

    @field_validator("content", mode="before")
    @classmethod
    def validate_and_trim_content(cls, value: Any) -> Any:
        if isinstance(value, str):
            if len(value) > 2_000:
                raise ValueError("sms_content_too_long")
            value = value.strip()
            if not value:
                raise ValueError("sms_content_empty")
        return value


class SMSAnalysisResponse(BaseModel):
    """Result from the dedicated SMS phishing classification endpoint."""

    model_config = ConfigDict(extra="forbid")

    classification: Literal["smishing", "not_smishing"]
    smishing_score: float = Field(ge=0.0, le=1.0)
    score_kind: Literal["uncalibrated_model_score"] = "uncalibrated_model_score"
    threshold: float = Field(ge=0.0, le=1.0)
    model_id: str = Field(min_length=1)
    disclaimer: str = Field(min_length=1)
