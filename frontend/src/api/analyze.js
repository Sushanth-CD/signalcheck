const rawBaseUrl = import.meta.env.VITE_API_BASE_URL;
const API_BASE_URL = typeof rawBaseUrl === "string" ? rawBaseUrl.replace(/\/$/, "") : "";

function messageFromError(payload, statusCode) {
  if (payload && typeof payload.message === "string") return payload.message;
  if (payload && typeof payload.detail === "string") return payload.detail;
  if (payload && payload.detail && typeof payload.detail.message === "string") {
    return payload.detail.message;
  }
  return `The analysis service returned an error (HTTP ${statusCode}). Please try again.`;
}

function isMLAnalysisResponse(value) {
  return (
    value &&
    ["phishing", "benign"].includes(value.classification) &&
    typeof value.phishing_score === "number" &&
    Number.isFinite(value.phishing_score) &&
    value.phishing_score >= 0 &&
    value.phishing_score <= 1 &&
    value.score_kind === "uncalibrated_model_score" &&
    typeof value.threshold === "number" &&
    Number.isFinite(value.threshold) &&
    value.threshold >= 0 &&
    value.threshold <= 1 &&
    typeof value.model_id === "string" &&
    value.model_id.length > 0 &&
    typeof value.disclaimer === "string" &&
    value.disclaimer.length > 0
  );
}

function isAndroidAnalysisResponse(value) {
  return (
    value &&
    ["malicious", "non_malicious"].includes(value.classification) &&
    typeof value.malware_score === "number" &&
    Number.isFinite(value.malware_score) &&
    value.malware_score >= 0 &&
    value.malware_score <= 1 &&
    value.score_kind === "uncalibrated_model_score" &&
    typeof value.threshold === "number" &&
    Number.isFinite(value.threshold) &&
    value.threshold >= 0 &&
    value.threshold <= 1 &&
    typeof value.model_id === "string" &&
    value.model_id.length > 0 &&
    typeof value.disclaimer === "string" &&
    value.disclaimer.length > 0
  );
}

function isSMSAnalysisResponse(value) {
  return (
    value &&
    ["smishing", "not_smishing"].includes(value.classification) &&
    typeof value.smishing_score === "number" &&
    Number.isFinite(value.smishing_score) &&
    value.smishing_score >= 0 &&
    value.smishing_score <= 1 &&
    value.score_kind === "uncalibrated_model_score" &&
    typeof value.threshold === "number" &&
    Number.isFinite(value.threshold) &&
    value.threshold >= 0 &&
    value.threshold <= 1 &&
    typeof value.model_id === "string" &&
    value.model_id.length > 0 &&
    typeof value.disclaimer === "string" &&
    value.disclaimer.length > 0
  );
}

function isAPKAnalysisResponse(value) {
  return (
    value &&
    value.analysis_version === "apk-static-v1" &&
    typeof value.sha256 === "string" &&
    value.sha256.length === 64 &&
    typeof value.file_size === "number" &&
    value.app &&
    value.permissions &&
    value.components &&
    value.signing &&
    value.code_indicators &&
    Array.isArray(value.findings) &&
    ["no_notable_indicators", "some_indicators", "many_indicators"].includes(value.indicator_level) &&
    Array.isArray(value.limitations)
  );
}

async function postJson(path, body, isValidResponse) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error("Could not reach the analysis service. Check that the backend is running and try again.");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("The analysis service returned an unreadable response. Please try again.");
  }

  if (!response.ok) throw new Error(messageFromError(payload, response.status));
  if (!isValidResponse(payload)) {
    throw new Error("The analysis service returned an unexpected response. Please try again later.");
  }
  return payload;
}

export function analyzeWithML(content) {
  return postJson("/api/ml/analyze", { content }, isMLAnalysisResponse);
}

export function analyzeAndroid(features) {
  return postJson(
    "/api/ml/analyze-android",
    { features },
    isAndroidAnalysisResponse,
  );
}

export function analyzeSMS(content) {
  return postJson("/api/ml/analyze-sms", { content }, isSMSAnalysisResponse);
}

export async function analyzeAPK(file, onProgress, signal) {
  const formData = new FormData();
  formData.append("file", file);

  let response;
  try {
    response = await fetch(`${API_BASE_URL}/api/apk/analyze`, {
      method: "POST",
      headers: { Accept: "application/json" },
      body: formData,
      signal,
    });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Upload was cancelled.");
    }
    throw new Error("Could not reach the analysis service. Check that the backend is running and try again.");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("The analysis service returned an unreadable response. Please try again.");
  }

  if (!response.ok) throw new Error(messageFromError(payload, response.status));
  if (!isAPKAnalysisResponse(payload)) {
    throw new Error("The analysis service returned an unexpected response. Please try again later.");
  }
  return payload;
}

export async function fetchAPKHistory(limit = 20, offset = 0) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}/api/apk/history?limit=${limit}&offset=${offset}`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new Error("Could not load analysis history.");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Failed to parse history response.");
  }

  if (!response.ok) throw new Error(messageFromError(payload, response.status));
  return payload;
}

export async function fetchAPKReportJson(recordId) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}/api/apk/report/${recordId}`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new Error("Could not load analysis report.");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Failed to parse report response.");
  }

  if (!response.ok) throw new Error(messageFromError(payload, response.status));
  return payload;
}

export function getAPKReportPdfUrl(recordId) {
  return `${API_BASE_URL}/api/apk/report/${recordId}?format=pdf`;
}

