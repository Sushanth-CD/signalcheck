const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

function messageFromError(payload, statusCode) {
  if (payload && typeof payload.message === "string") return payload.message;
  if (payload && typeof payload.detail === "string") return payload.detail;
  return `The analysis service returned an error (HTTP ${statusCode}). Please try again.`;
}

function isAnalysisResponse(value) {
  return (
    value &&
    Number.isInteger(value.risk_score) &&
    value.risk_score >= 0 &&
    value.risk_score <= 100 &&
    ["low", "medium", "high"].includes(value.risk_level) &&
    typeof value.summary === "string" &&
    Array.isArray(value.detected_indicators) &&
    Array.isArray(value.recommendations) &&
    typeof value.disclaimer === "string" &&
    value.detected_indicators.every(
      (item) =>
        item &&
        typeof item.rule_id === "string" &&
        typeof item.category === "string" &&
        typeof item.title === "string" &&
        typeof item.explanation === "string" &&
        Number.isInteger(item.score_contribution),
    )
  );
}

export async function analyzeContent(content) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ content }),
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
  if (!isAnalysisResponse(payload)) {
    throw new Error("The analysis service returned an unexpected response. Please try again later.");
  }
  return payload;
}
