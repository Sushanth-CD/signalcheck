"""FastAPI application entry point."""

import os
import re
from urllib.parse import urlparse
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from app.security import (
    get_allowed_hosts,
    get_client_ip,
    get_rate_limit,
    get_rate_limit_storage_uri,
)

from app.android_classifier import (
    LoadedAndroidModel,
    classify_android_features,
    load_android_model,
)
from app.ml_classifier import ModelLoadError, classify_message, load_phishing_model
from app.sms_classifier import (
    SMSModelLoadError,
    classify_sms_message,
    load_sms_model,
)
from app.schemas import (
    AnalysisRequest,
    AndroidMLAnalysisRequest,
    AndroidMLAnalysisResponse,
    HealthResponse,
    MLAnalysisResponse,
    SMSAnalysisRequest,
    SMSAnalysisResponse,
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Load the persisted ML pipeline once when the API starts."""

    try:
        application.state.phishing_model = load_phishing_model()
    except ModelLoadError as exc:
        raise RuntimeError(f"Phishing ML model startup failed: {exc}") from exc
    try:
        application.state.android_model = load_android_model()
        application.state.android_model_load_error = None
    except Exception as exc:
        # Android is independent; preserve phishing service availability if
        # this artifact cannot be loaded.
        application.state.android_model = None
        application.state.android_model_load_error = exc
    try:
        application.state.sms_model = load_sms_model()
        application.state.sms_model_load_error = None
    except Exception as exc:
        # SMS model is independent; preserve other service availability if
        # this experimental artifact cannot be loaded.
        application.state.sms_model = None
        application.state.sms_model_load_error = exc
    try:
        yield
    finally:
        application.state.phishing_model = None
        application.state.android_model = None
        application.state.android_model_load_error = None
        application.state.sms_model = None
        application.state.sms_model_load_error = None

def get_configured_cors_origins() -> list[str]:
    """Parse and strictly validate allowed CORS origins from SIGNALCHECK_CORS_ORIGINS.

    Enforces:
    - Only http and https schemes.
    - No wildcards (*).
    - No paths (other than optional root '/').
    - No query strings or URL fragments.
    - No embedded username/password credentials.
    - Consistent whitespace trimming.
    - Explicit default: http://localhost:5173, http://127.0.0.1:5173.
    """
    default_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
    raw_env = os.getenv("SIGNALCHECK_CORS_ORIGINS", "").strip()
    if not raw_env:
        return default_origins

    parsed_origins: list[str] = []
    for candidate in raw_env.split(","):
        origin = candidate.strip()
        if not origin:
            continue
        # Reject wildcards
        if "*" in origin:
            continue

        parsed = urlparse(origin)
        # Scheme must be strictly http or https
        if parsed.scheme not in ("http", "https"):
            continue
        # Must have a netloc (hostname + optional port)
        if not parsed.netloc:
            continue
        # Reject embedded credentials (user:pass@host)
        if parsed.username or parsed.password:
            continue
        # Reject query parameters and fragments
        if parsed.query or parsed.fragment:
            continue
        # Path must be empty or strictly root '/'
        if parsed.path not in ("", "/"):
            continue

        # Reconstruct canonical origin: scheme://hostname[:port]
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        if normalized not in parsed_origins:
            parsed_origins.append(normalized)

    return parsed_origins if parsed_origins else default_origins


limiter = Limiter(
    key_func=get_client_ip,
    storage_uri=get_rate_limit_storage_uri(),
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject standard HTTP defense-in-depth security headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        # Prevent MIME-sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking / iframe embedding
        response.headers["X-Frame-Options"] = "DENY"
        # Restrict referrer leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Disable browser feature APIs not required by SignalCheck
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Content-Security-Policy tailored to avoid breaking Swagger UI (/docs) and Vite
        # Allows self, OpenAPI Swagger CDN assets, and inline script hashes/nonces required by Swagger UI
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "connect-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "font-src 'self' data:; "
            "frame-ancestors 'none';"
        )

        # HSTS only when HTTPS is actually in use
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


app = FastAPI(
    title="Cyber Security Awareness Platform API",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter

# Middleware execution order in Starlette/FastAPI is reverse of addition order.
# Order: SecurityHeaders -> TrustedHost -> RateLimit (Limiter) -> CORS -> Endpoints
app.add_middleware(SecurityHeadersMiddleware)

allowed_hosts = get_allowed_hosts()
if "*" not in allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_configured_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return structured HTTP 429 response matching SignalCheck schema conventions."""
    retry_after = getattr(exc, "detail", "Rate limit exceeded. Please retry later.")
    response = JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "rate_limit_exceeded",
            "message": "Too many requests. Please slow down and try again later.",
            "details": {"limit": str(exc)},
        },
    )
    response.headers["Retry-After"] = "60"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return safe validation messages without echoing submitted content."""

    errors = exc.errors()
    first_error = errors[0] if errors else {}
    error_type = first_error.get("type", "")
    message = first_error.get("msg", "")
    location = first_error.get("loc", ())

    if error_type == "json_invalid":
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "invalid_json",
                "message": "Request body must be valid JSON.",
            },
        )

    if "content_too_long" in message or error_type == "string_too_long":
        limit = 2000 if request.url.path == "/api/ml/analyze-sms" else 10000
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "error": "input_too_long",
                "message": f"content must not exceed {limit} characters.",
            },
        )

    if "sms_content_too_long" in message:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "error": "input_too_long",
                "message": "content must not exceed 2000 characters.",
            },
        )

    if "content_empty" in message or "sms_content_empty" in message:
        msg = (
            "Provide an SMS message to analyze."
            if request.url.path == "/api/ml/analyze-sms"
            else "Provide a message, URL, or text to analyze."
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "empty_input",
                "message": msg,
            },
        )

    if "features" in location or request.url.path == "/api/ml/analyze-android":
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "invalid_android_features",
                "message": (
                    "features must contain exactly the 226 expected names, "
                    "each with an integer value of 0 or 1."
                ),
                "details": {"field": "features"},
            },
        )

    field = location[-1] if location and isinstance(location[-1], str) else None
    safe_message = "Request body did not match the required schema."
    if field == "content":
        limit = 2000 if request.url.path == "/api/ml/analyze-sms" else 10000
        safe_message = f"content must be a string containing 1 to {limit} characters."
    elif error_type == "extra_forbidden":
        safe_message = "Only the content field is accepted."

    body = {"error": "validation_error", "message": safe_message}
    if field:
        body["details"] = {"field": field}

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=body,
    )


@app.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Report that the backend process is running."""

    return HealthResponse(status="ok")


@app.post("/api/ml/analyze", response_model=MLAnalysisResponse)
@limiter.limit(lambda: get_rate_limit("analyze", "30/minute"))
def analyze_with_ml(
    request: Request,
    payload: AnalysisRequest,
) -> MLAnalysisResponse:
    """Classify text with the saved local phishing model."""

    model = getattr(request.app.state, "phishing_model", None)
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The phishing classification model is not available.",
        )
    return MLAnalysisResponse(**classify_message(payload.content, model))


@app.post(
    "/api/ml/analyze-android",
    response_model=AndroidMLAnalysisResponse,
)
@limiter.limit(lambda: get_rate_limit("android", "20/minute"))
def analyze_android_with_ml(
    request: Request,
    payload: AndroidMLAnalysisRequest,
) -> AndroidMLAnalysisResponse:
    """Classify prepared Android permission/features independently of text analysis."""

    loaded_model: LoadedAndroidModel | None = getattr(
        request.app.state, "android_model", None
    )
    if loaded_model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The Android malware classification model is not available.",
        )

    expected = set(loaded_model.feature_columns)
    supplied = set(payload.features)
    if supplied != expected:
        missing = sorted(expected - supplied)
        unexpected = sorted(supplied - expected)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_android_features",
                "message": "Feature names must exactly match the loaded Android model schema.",
                "missing_features": missing,
                "unexpected_features": unexpected,
            },
        )

    return AndroidMLAnalysisResponse(
        **classify_android_features(payload.features, loaded_model)
    )


@app.post(
    "/api/ml/analyze-sms",
    response_model=SMSAnalysisResponse,
)
@limiter.limit(lambda: get_rate_limit("sms", "30/minute"))
def analyze_sms_with_ml(
    request: Request,
    payload: SMSAnalysisRequest,
) -> SMSAnalysisResponse:
    """Classify an SMS message using the frozen SMS-05-C model."""

    model = getattr(request.app.state, "sms_model", None)
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The SMS phishing classification model is not available.",
        )
    return SMSAnalysisResponse(**classify_sms_message(payload.content, model))

