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


# ---------------------------------------------------------------------------
# APK Static Analysis (apk-static-v1) Schemas
# ---------------------------------------------------------------------------

class APKAppInfo(BaseModel):
    """Metadata regarding the Android application package."""

    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(default="")
    version_name: str = Field(default="")
    version_code: str = Field(default="")
    min_sdk: str = Field(default="")
    target_sdk: str = Field(default="")


class APKPermissionGroup(BaseModel):
    """Grouped declared Android permissions."""

    model_config = ConfigDict(extra="forbid")

    sms: list[str] = Field(default_factory=list)
    call_phone: list[str] = Field(default_factory=list)
    contacts: list[str] = Field(default_factory=list)
    accessibility: list[str] = Field(default_factory=list)
    device_admin: list[str] = Field(default_factory=list)
    overlay: list[str] = Field(default_factory=list)
    install_packages: list[str] = Field(default_factory=list)
    read_notifications: list[str] = Field(default_factory=list)
    location: list[str] = Field(default_factory=list)
    camera_mic: list[str] = Field(default_factory=list)
    internet: list[str] = Field(default_factory=list)
    boot_completed: list[str] = Field(default_factory=list)
    other: list[str] = Field(default_factory=list)
    all_declared: list[str] = Field(default_factory=list)


class APKComponentsInfo(BaseModel):
    """Declared component counts and sensitive flags."""

    model_config = ConfigDict(extra="forbid")

    activities_count: int = 0
    services_count: int = 0
    receivers_count: int = 0
    providers_count: int = 0
    exported_count: int = 0
    notable_intent_filters: list[str] = Field(default_factory=list)


class APKCertificateInfo(BaseModel):
    """Parsed certificate details."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(default="")
    issuer: str = Field(default="")
    valid_from: str = Field(default="")
    valid_to: str = Field(default="")
    sha256_fingerprint: str = Field(default="")


class APKSigningInfo(BaseModel):
    """Cryptographic signing verification and details."""

    model_config = ConfigDict(extra="forbid")

    is_signed: bool = False
    signature_schemes: list[str] = Field(default_factory=list)
    is_debug_signed: bool = False
    is_self_signed: bool = False
    certificates: list[APKCertificateInfo] = Field(default_factory=list)


class APKCodeIndicators(BaseModel):
    """Static indicators discovered in Dalvik bytecode."""

    model_config = ConfigDict(extra="forbid")

    dynamic_code_loading: bool = False
    reflection_use: bool = False
    runtime_exec: bool = False
    sms_send_apis: bool = False
    accessibility_event_handling: bool = False
    native_library_presence: bool = False
    base64_obfuscation_hints: bool = False
    obfuscation_name_ratio_hint: float = Field(default=0.0, ge=0.0, le=1.0)
    discovered_urls: list[str] = Field(default_factory=list)


class APKFinding(BaseModel):
    """Single security heuristic finding."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: Literal["info", "low", "medium", "high"]
    title: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    why_it_matters: str = Field(min_length=1)


class APKAnalysisResponse(BaseModel):
    """Versioned output response for static APK analysis (apk-static-v1)."""

    model_config = ConfigDict(extra="forbid")

    id: int | None = Field(default=None)
    analysis_version: Literal["apk-static-v1"] = "apk-static-v1"
    sha256: str = Field(min_length=64, max_length=64)
    file_size: int = Field(ge=0)
    app: APKAppInfo
    permissions: APKPermissionGroup
    components: APKComponentsInfo
    signing: APKSigningInfo
    code_indicators: APKCodeIndicators
    findings: list[APKFinding] = Field(default_factory=list)
    indicator_level: Literal["no_notable_indicators", "some_indicators", "many_indicators"]
    limitations: list[str] = Field(default_factory=list)


class APKHistoryItem(BaseModel):
    """Summary item in paginated APK history list."""

    model_config = ConfigDict(extra="forbid")

    id: int
    sha256: str
    package_name: str
    file_size: int
    indicator_level: str
    outcome: str
    created_at: str


class APKHistoryResponse(BaseModel):
    """Paginated list of historical APK analyses."""

    model_config = ConfigDict(extra="forbid")

    items: list[APKHistoryItem]
    total: int
    limit: int
    offset: int


