"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.android_classifier import (
    LoadedAndroidModel,
    classify_android_features,
    load_android_model,
)
from app.ml_classifier import ModelLoadError, classify_message, load_phishing_model
from app.schemas import (
    AnalysisRequest,
    AndroidMLAnalysisRequest,
    AndroidMLAnalysisResponse,
    HealthResponse,
    MLAnalysisResponse,
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
        yield
    finally:
        application.state.phishing_model = None
        application.state.android_model = None
        application.state.android_model_load_error = None

app = FastAPI(
    title="Cyber Security Awareness Platform API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


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
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "error": "input_too_long",
                "message": "content must not exceed 10000 characters.",
            },
        )

    if "content_empty" in message:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "empty_input",
                "message": "Provide a message, URL, or text to analyze.",
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
        safe_message = "content must be a string containing 1 to 10000 characters."
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
def analyze_with_ml(
    request: AnalysisRequest,
    http_request: Request,
) -> MLAnalysisResponse:
    """Classify text with the saved local phishing model."""

    model = getattr(http_request.app.state, "phishing_model", None)
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The phishing classification model is not available.",
        )
    return MLAnalysisResponse(**classify_message(request.content, model))


@app.post(
    "/api/ml/analyze-android",
    response_model=AndroidMLAnalysisResponse,
)
def analyze_android_with_ml(
    request: AndroidMLAnalysisRequest,
    http_request: Request,
) -> AndroidMLAnalysisResponse:
    """Classify prepared Android permission/features independently of text analysis."""

    loaded_model: LoadedAndroidModel | None = getattr(
        http_request.app.state, "android_model", None
    )
    if loaded_model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The Android malware classification model is not available.",
        )

    expected = set(loaded_model.feature_columns)
    supplied = set(request.features)
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
        **classify_android_features(request.features, loaded_model)
    )
