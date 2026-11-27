# Multi-stage production Dockerfile for SignalCheck Backend
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies in a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY backend/pyproject.toml /app/backend/
RUN pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir \
    "fastapi>=0.115,<1.0" \
    "uvicorn[standard]>=0.30,<1.0" \
    "joblib==1.5.3" \
    "scikit-learn==1.8.0" \
    "slowapi>=0.1.9,<1.0" \
    "redis>=5.0.0,<9.0.0"

# --- Production Runner Stage ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Create unprivileged service user
RUN groupadd -g 10001 signalcheck && \
    useradd -u 10001 -g signalcheck -s /sbin/nologin -d /app signalcheck

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend

# Copy application source and model artifacts
COPY backend/app /app/backend/app
COPY backend/ml /app/backend/ml
COPY backend/models /app/backend/models
COPY backend/reports/ml/android_malware_sklearn_1_8_0/experiment_config.json /app/backend/reports/ml/android_malware_sklearn_1_8_0/experiment_config.json

# Fix ownership
RUN chown -R signalcheck:signalcheck /app

# Switch to non-root user
USER signalcheck

EXPOSE 8000

# Health check probe against local Uvicorn process
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status == 200 else 1)" || exit 1

# Launch Uvicorn with graceful shutdown signal handling
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info"]
