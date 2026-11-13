"""FastAPI application entry point."""

import os
import re
import time
import uuid
import tempfile
import hashlib
import asyncio
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from urllib.parse import urlparse
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File, Query, status
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
    APKAnalysisResponse,
    APKHistoryItem,
    APKHistoryResponse,
    HealthResponse,
    MLAnalysisResponse,
    SMSAnalysisRequest,
    SMSAnalysisResponse,
)
from app.apk_analyzer import (
    APKValidationError,
    validate_zip_structure,
    analyze_apk_file,
)
from app.apk_db import (
    init_db,
    save_apk_result,
    get_apk_history,
    get_apk_record_by_id,
)
from app.apk_pdf import generate_apk_pdf_report


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
    # Initialize SQLite database for APK history
    try:
        init_db()
    except Exception as exc:
        print(f"Warning: Failed to initialize APK database: {exc}")
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


@app.post(
    "/api/apk/analyze",
    response_model=APKAnalysisResponse,
)
@limiter.limit(lambda: get_rate_limit("apk", "5/minute"))
async def analyze_apk(
    request: Request,
    file: UploadFile = File(...),
) -> APKAnalysisResponse:
    """Perform static security analysis on an uploaded Android APK file.

    HARD SAFETY CONSTRAINTS:
    - Never install, execute, emulate or dynamic-load the APK.
    - Upload streaming with strict size cap (SIGNALCHECK_APK_MAX_SIZE_BYTES).
    - Zip-bomb and path-traversal validation before parsing.
    - Parsing runs under strict timeout (SIGNALCHECK_APK_TIMEOUT_SECONDS).
    - File deleted in finally block under all circumstances.
    - Zero sensitive string or filename logging (logs only: req_id, size, duration, outcome).
    """
    request_id = str(uuid.uuid4())
    start_time = time.monotonic()
    outcome_code = "UNKNOWN"

    max_bytes = int(os.getenv("SIGNALCHECK_APK_MAX_SIZE_BYTES", 25 * 1024 * 1024))
    timeout_seconds = float(os.getenv("SIGNALCHECK_APK_TIMEOUT_SECONDS", "20.0"))
    max_uncompressed = int(os.getenv("SIGNALCHECK_APK_MAX_UNCOMPRESSED_BYTES", 300 * 1024 * 1024))
    max_entries = int(os.getenv("SIGNALCHECK_APK_MAX_ENTRIES", "10000"))
    max_ratio = float(os.getenv("SIGNALCHECK_APK_MAX_COMPRESSION_RATIO", "20.0"))

    temp_path = None
    bytes_received = 0
    hasher = hashlib.sha256()

    try:
        # Create an ephemeral temp file on disk
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_file:
            temp_path = temp_file.name

            # Stream chunks (64 KB) to avoid loading entire body into memory
            chunk_size = 64 * 1024
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                bytes_received += len(chunk)
                if bytes_received > max_bytes:
                    outcome_code = "PAYLOAD_TOO_LARGE"
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail={
                            "error": "apk_too_large",
                            "message": f"Uploaded file exceeds maximum permitted size of {max_bytes} bytes.",
                        },
                    )
                hasher.update(chunk)
                temp_file.write(chunk)

        if bytes_received == 0:
            outcome_code = "EMPTY_FILE"
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "empty_file",
                    "message": "Uploaded file is empty.",
                },
            )

        sha256_digest = hasher.hexdigest()

        # Step A: Validate ZIP structure and safety boundaries before parsing
        try:
            validate_zip_structure(
                temp_path,
                max_entries=max_entries,
                max_uncompressed_bytes=max_uncompressed,
                max_compression_ratio=max_ratio,
            )
        except APKValidationError as val_err:
            outcome_code = val_err.error_code
            raise HTTPException(
                status_code=val_err.status_code,
                detail={"error": val_err.error_code, "message": val_err.message},
            ) from val_err

        # Step B: Execute static analysis in worker thread under hard timeout
        loop = asyncio.get_running_loop()
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                analysis_dict = await asyncio.wait_for(
                    loop.run_in_executor(
                        executor,
                        analyze_apk_file,
                        temp_path,
                        sha256_digest,
                        bytes_received,
                    ),
                    timeout=timeout_seconds,
                )
        except asyncio.TimeoutError:
            outcome_code = "ANALYSIS_TIMEOUT"
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "error": "analysis_timeout",
                    "message": f"Static analysis timed out after {timeout_seconds} seconds.",
                },
            )
        except APKValidationError as val_err:
            outcome_code = val_err.error_code
            raise HTTPException(
                status_code=val_err.status_code,
                detail={"error": val_err.error_code, "message": val_err.message},
            ) from val_err
        except Exception as exc:
            outcome_code = "ANALYSIS_ERROR"
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "analysis_failed",
                    "message": f"Static extraction encountered an unrecoverable error: {exc}",
                },
            ) from exc

        outcome_code = "SUCCESS"
        # Persist JSON result to SQLite history (never APK file bytes)
        try:
            record_id = save_apk_result(
                sha256=sha256_digest,
                package_name=analysis_dict.get("app", {}).get("package_name", ""),
                file_size=bytes_received,
                indicator_level=analysis_dict.get("indicator_level", "no_notable_indicators"),
                outcome=outcome_code,
                result_data=analysis_dict,
            )
            analysis_dict["id"] = record_id
        except Exception as db_exc:
            print(f"Warning: Failed to persist APK result: {db_exc}")

        return APKAnalysisResponse(**analysis_dict)

    finally:
        # Ephemeral guarantee: file must be unlinked under all conditions
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass

        # Close uploaded file handle
        try:
            await file.close()
        except Exception:
            pass

        duration_sec = round(time.monotonic() - start_time, 4)
        # Log facts only: request_id, size, duration, outcome_code (NO content or strings)
        print(
            f"SIGNALCHECK_APK_AUDIT: req_id={request_id} "
            f"size_bytes={bytes_received} "
            f"duration_sec={duration_sec} "
            f"outcome={outcome_code}"
        )


@app.get(
    "/api/apk/history",
    response_model=APKHistoryResponse,
)
@limiter.limit(lambda: get_rate_limit("apk_history", "30/minute"))
def get_apk_analysis_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
) -> APKHistoryResponse:
    """Retrieve paginated historical APK static analysis summaries."""
    items, total = get_apk_history(limit=limit, offset=offset)
    return APKHistoryResponse(
        items=[APKHistoryItem(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/api/apk/report/{record_id}",
)
@limiter.limit(lambda: get_rate_limit("apk_report", "30/minute"))
def get_apk_analysis_report(
    request: Request,
    record_id: int,
    format: Optional[str] = Query(default=None),
) -> Response:
    """Retrieve full JSON result or generate one-page PDF technical report."""
    record = get_apk_record_by_id(record_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "report_not_found",
                "message": f"No APK analysis record found with ID {record_id}.",
            },
        )

    result_data = record["result"]

    if format == "pdf":
        pdf_bytes = generate_apk_pdf_report(result_data)
        package_clean = result_data.get("app", {}).get("package_name") or "apk"
        filename = f"signalcheck-report-{package_clean}-{record['sha256'][:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )

    # Default: return JSON result
    return JSONResponse(content=result_data)


