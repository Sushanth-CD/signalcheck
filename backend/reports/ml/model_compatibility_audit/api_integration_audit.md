# FastAPI Integration Audit

**Audit Scope:** Read-Only Runtime & API Surface Audit  
**Target Repository:** `C:\Projects\cyber-security-awareness-platform`  
**Inspected Source Files:**
- `backend/app/main.py`
- `backend/app/schemas.py`
- `backend/app/ml_classifier.py`
- `backend/app/android_classifier.py`
**Date:** November 2026  

---

## 1. Executive Summary

This audit evaluates the active API implementation in `backend/app/` against the operational requirements of the Cyber Security Awareness Platform. Specifically, it reviews the HTTP endpoints exposed by the service, their request and response schemas, input validation and constraints, model loading lifecycles, and the degree of preprocessing consistency between offline model development and runtime production inference.

---

## 2. API Endpoints Surface

```
+---------------------------------------------------------------------------------------------------+
| CURRENT RUNTIME API ENDPOINTS SURFACE                                                             |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [GET]  /health                                                                                   |
|         ---> Returns {"status": "ok"}                                                             |
|                                                                                                   |
|  [POST] /api/ml/analyze                                                                           |
|         ---> Accepts: AnalysisRequest { content: str (1..10000 chars) }                           |
|         ---> Model: V2 Baseline (phishing_tfidf_logreg_domain_grouped.joblib)                     |
|         ---> Returns: MLAnalysisResponse { classification, phishing_score, threshold, ... }       |
|                                                                                                   |
|  [POST] /api/ml/analyze-android                                                                   |
|         ---> Accepts: AndroidMLAnalysisRequest { features: dict[str, int] (exactly 226 items) }   |
|         ---> Model: Android Random Forest (android_random_forest_grouped.joblib)                  |
|         ---> Returns: AndroidMLAnalysisResponse { classification, malware_score, ... }            |
|                                                                                                   |
|  [DEPRECATED / REMOVED]                                                                           |
|  - POST /api/analyze (Rule-based analyzer engine deleted from active code)                        |
|  - No dedicated /api/ml/analyze-url endpoint exists                                               |
|  - No dedicated /api/ml/analyze-html endpoint exists                                              |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

The active application exposes exactly three HTTP endpoints:
1. `GET /health`: Health-check probe.
2. `POST /api/ml/analyze`: Text-based phishing classification endpoint.
3. `POST /api/ml/analyze-android`: Prepared tabular Android feature classification endpoint.

> [!NOTE]
> There are currently **NO dedicated endpoints** for submitting standalone URLs, fetching and parsing live web links, or uploading raw HTML files. All text-like inputs (plain messages, links, or HTML snippets) must pass through `POST /api/ml/analyze`.

---

## 3. Deep Dive: `POST /api/ml/analyze`

### 3.1 Request Schema & Input Validation

The endpoint receives an `AnalysisRequest` defined in `backend/app/schemas.py`:

```python
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
```

#### Validation Characteristics:
- **Single Monolithic Field:** The request payload schema is strictly `{"content": "<string>"}`. Extra JSON keys are rejected with HTTP 422 (`extra_forbidden`).
- **Length Bounds:** Enforces $1 \le \text{len} \le 10,000$ characters. Whitespace is stripped before length evaluation.
- **Payload Truncation / Rejection:** Submissions exceeding 10,000 characters trigger HTTP 413 (`input_too_long`).
- **Modality Agnosticism:** The schema does not distinguish whether `content` is an SMS message, an email body, a standalone URL (e.g., `https://example.com`), or an HTML document snippet.

### 3.2 Model Loading & Lifecycle

- Model loading is managed in `backend/app/main.py` via FastAPI's `lifespan` context manager:
  ```python
  @asynccontextmanager
  async def lifespan(application: FastAPI):
      try:
          application.state.phishing_model = load_phishing_model()
      except ModelLoadError as exc:
          raise RuntimeError(f"Phishing ML model startup failed: {exc}") from exc
      ...
  ```
- **Loaded Model Artifact:**
  - `load_phishing_model()` in `backend/app/ml_classifier.py` loads:
    `backend/models/text/phishing_tfidf_logreg_domain_grouped.joblib`
  - **Crucial Finding:** The active API loads the **V2 Baseline model** (`MODEL_ID = "phishing-tfidf-logreg-domain-grouped-v1"`), **NOT** any of the V3 models (Content-Only, URL-Only, or Dual-Channel V3).
- **Environment & Version Enforcement:**
  - `load_phishing_model()` verifies that `sklearn.__version__ == "1.8.0"`.
  - Checks for `InconsistentVersionWarning` during unpickling to prevent silent corruption.
  - Ensures the loaded model exposes `predict_proba` and `classes_` containing `{0, 1}`.

### 3.3 Preprocessing Consistency Between Training & Inference

- In `backend/app/ml_classifier.py`:
  ```python
  def classify_message(message: str, model: Any) -> dict[str, Any]:
      scores = model.predict_proba([message])
      classes = list(model.classes_)
      phishing_score = float(scores[0][classes.index(1)])
      ...
  ```
- **Consistency Analysis:**
  - Because `model` is a persisted `sklearn.pipeline.Pipeline`, calling `predict_proba([message])` directly invokes the embedded `TfidfVectorizer.preprocessor` (`backend.ml.text_normalization.normalize_for_model`).
  - **Consistency with V2 Training:** 100% identical. The exact normalization function and TF-IDF vocabulary fitted during V2 training are applied to the raw string.
  - **Inconsistency with V3 Models:** Complete mismatch. If a user submits raw HTML or a standalone URL, the V2 pipeline treats it as unstructured natural text, retaining no URL hierarchy and breaking down completely on HTML structures.

### 3.4 Response Format & Error Handling

- **Response Schema (`MLAnalysisResponse`):**
  ```python
  class MLAnalysisResponse(BaseModel):
      model_config = ConfigDict(extra="forbid")

      classification: Literal["phishing", "benign"]
      phishing_score: float = Field(ge=0.0, le=1.0)
      score_kind: Literal["uncalibrated_model_score"] = "uncalibrated_model_score"
      threshold: float = Field(ge=0.0, le=1.0)
      model_id: str = Field(min_length=1)
      disclaimer: str = Field(min_length=1)
  ```
- **Output Characteristics:**
  - Returns a binary decision (`phishing` vs `benign`) based on fixed threshold $\tau = 0.50$.
  - Explicitly flags `score_kind` as `"uncalibrated_model_score"`.
  - Includes a mandatory legal and educational disclaimer:
    > *"This result is an uncalibrated model score, not proof that a message or website is malicious or safe. Review the message and its context."*
- **Error Handling:**
  - Empty or whitespace input $\rightarrow$ HTTP 422 (`empty_input`).
  - String $> 10,000$ characters $\rightarrow$ HTTP 413 (`input_too_long`).
  - Malformed JSON $\rightarrow$ HTTP 400 (`invalid_json`).
  - Missing model on server $\rightarrow$ HTTP 503 (`service_unavailable`).
  - Pipeline scoring failure $\rightarrow$ HTTP 500 runtime exception.

---

## 4. Architectural Gaps & Findings

1. **Active Endpoint Loads Outdated V2 Baseline:**
   The production FastAPI backend still loads the V2 baseline (`phishing_tfidf_logreg_domain_grouped.joblib`). None of the V3 innovations (URL extraction, HTML stripping, Dual-Channel fusion) are active in `main.py`.
2. **HTML Character Limit Constraint:**
   The 10,000-character maximum length (`max_length=10_000`) is sufficient for SMS and typical email bodies, but **severely truncates raw HTML files**. Real-world web pages and phishing landing pages regularly range between 20 KB and 500 KB (the CompPhish V4 average sample size was ~35 KB). Submitting full HTML to `/api/ml/analyze` currently triggers an immediate HTTP 413 Entity Too Large error.
3. **Lack of Modality Dispatch / Routing:**
   The endpoint does not inspect the input to select an appropriate model. A bare URL (`https://suspicious-login.com`), an SMS text (`Your account is locked`), and an HTML file (`<!DOCTYPE html><html>...`) are all forced through the same V2 text model.
