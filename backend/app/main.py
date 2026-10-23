"""FastAPI application entry point."""

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.analyzer import analyze_content
from app.schemas import AnalysisRequest, AnalysisResponse, HealthResponse

app = FastAPI(
    title="Cyber Security Awareness Platform API",
    version="1.0.0",
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


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(request: AnalysisRequest) -> AnalysisResponse:
    """Analyze submitted text locally and return structured findings."""

    return analyze_content(request.content)
