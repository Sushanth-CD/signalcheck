import { useMemo, useRef, useState } from "react";
import { analyzeAndroid } from "../api/analyze.js";
import { SAMPLE_ANDROID_FEATURES } from "./androidSampleFeatures.js";
import StatusBanner from "./ui/StatusBanner.jsx";

const REQUIRED_FEATURE_COUNT = 226;

function readFeatureMap(requestText) {
  let payload;
  try {
    payload = JSON.parse(requestText);
  } catch {
    throw new Error("Enter valid JSON before submitting.");
  }

  if (
    !payload ||
    Array.isArray(payload) ||
    typeof payload !== "object" ||
    Object.keys(payload).length !== 1 ||
    !Object.hasOwn(payload, "features")
  ) {
    throw new Error('The JSON must contain a single top-level "features" object.');
  }

  const features = payload.features;
  if (!features || Array.isArray(features) || typeof features !== "object") {
    throw new Error('The "features" value must be a JSON object.');
  }

  const entries = Object.entries(features);
  if (entries.length !== REQUIRED_FEATURE_COUNT) {
    throw new Error(`Provide exactly ${REQUIRED_FEATURE_COUNT} configured features (found ${entries.length}).`);
  }

  for (const [name, value] of entries) {
    if (!name.trim()) {
      throw new Error("Feature names cannot be empty.");
    }
    if (!Number.isInteger(value) || (value !== 0 && value !== 1)) {
      throw new Error("Every feature value must be the integer 0 or 1.");
    }
  }

  return features;
}

function BenchmarkResult({ result }) {
  if (!result) return null;

  return (
    <section className="android-result-panel" aria-labelledby="benchmark-result-title" aria-live="polite">
      <div className="android-result-heading">
        <div>
          <p className="eyebrow">BENCHMARK ANALYSIS RESULT</p>
          <h3 id="benchmark-result-title">Model Evaluation Output</h3>
        </div>
        <span
          className={`android-classification android-classification-${result.classification}`}
          style={{ textTransform: "none" }}
        >
          Model classification: {result.classification}
        </span>
      </div>

      <dl className="android-result-details">
        <div>
          <dt>Raw model score</dt>
          <dd>{Number(result.malware_score).toFixed(4)}</dd>
        </div>
        <div>
          <dt>Classification threshold</dt>
          <dd>{Number(result.threshold).toFixed(2)}</dd>
        </div>
        <div className="android-model-id">
          <dt>Model identifier</dt>
          <dd>{result.model_id}</dd>
        </div>
      </dl>

      <p className="android-score-note">
        This is an uncalibrated model score, not a percentage probability, risk level, or proof that an application is malicious or safe.
        The classifier applies threshold {Number(result.threshold).toFixed(2)}: vectors scoring at or above {Number(result.threshold).toFixed(2)} are classified as &quot;malicious&quot;, while those below are classified as &quot;non_malicious&quot;.
      </p>
      <p className="android-disclaimer">{result.disclaimer}</p>
    </section>
  );
}

export default function AndroidFeatureAnalysis() {
  const [requestText, setRequestText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const requestInFlight = useRef(false);

  // Compute live detection stats
  const detectionStatus = useMemo(() => {
    if (!requestText.trim()) {
      return { count: 0, validJson: false, ready: false };
    }
    try {
      const parsed = JSON.parse(requestText);
      if (parsed && typeof parsed === "object" && parsed.features && typeof parsed.features === "object") {
        const count = Object.keys(parsed.features).length;
        return { count, validJson: true, ready: count === REQUIRED_FEATURE_COUNT };
      }
      return { count: 0, validJson: true, ready: false };
    } catch {
      return { count: 0, validJson: false, ready: false };
    }
  }, [requestText]);

  async function handleSubmit(event) {
    event.preventDefault();
    if (requestInFlight.current || !requestText.trim()) return;

    setError("");
    setResult(null);

    let features;
    try {
      features = readFeatureMap(requestText);
    } catch (validationError) {
      setError(validationError instanceof Error ? validationError.message : "The feature request is invalid.");
      return;
    }

    requestInFlight.current = true;
    setIsLoading(true);
    try {
      setResult(await analyzeAndroid(features));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Android analysis failed. Please try again.");
    } finally {
      requestInFlight.current = false;
      setIsLoading(false);
    }
  }

  function handleClear() {
    setRequestText("");
    setResult(null);
    setError("");
  }

  function handleLoadSample() {
    setRequestText(JSON.stringify(SAMPLE_ANDROID_FEATURES, null, 2));
    setResult(null);
    setError("");
  }

  return (
    <section className="android-analysis-card" aria-labelledby="android-benchmark-title">
      {/* Consolidated Warning Banner */}
      <div style={{ marginBottom: "1.5rem" }}>
        <StatusBanner
          variant="warning"
          title="Offline Research Benchmark"
        >
          Offline Research Benchmark — This tool evaluates precomputed 226-feature vectors. It does not upload, open, execute or inspect APK files. Only 44 of the model&apos;s 226 features are reproducible directly from an APK. Results are research benchmark outputs, not proof of an application&apos;s behaviour or security.
        </StatusBanner>
      </div>

      {/* Header Intro */}
      <div className="android-analysis-intro">
        <div className="android-step-icon" aria-hidden="true">RF</div>
        <div>
          <p className="eyebrow">OFFLINE ML RESEARCH</p>
          <h2 id="android-benchmark-title">Android 226-Feature Benchmark</h2>
          <p>Evaluate precomputed Android permission and feature vectors using the legacy Random Forest benchmark.</p>
        </div>
      </div>

      {/* Input Section */}
      <div className="android-requirements" id="android-feature-help">
        <p>Prepared Android Feature Vector</p>
        <p style={{ marginTop: "0.25rem", fontWeight: "normal", color: "#64748b" }}>
          Provide a JSON object containing the model&apos;s expected 226 binary features.
        </p>
        <ul style={{ marginTop: "0.5rem" }}>
          <li>Feature names must match the saved model configuration exactly.</li>
          <li>Every value must be the integer 0 or 1.</li>
          <li>This accepts prepared feature data, not an APK file.</li>
          <li>Only 44 of 226 features can be reproduced from an APK, so this tool cannot score uploaded APKs.</li>
        </ul>

        <details className="android-example">
          <summary>View JSON structure example</summary>
          <pre>{`{
  "features": {
    "Default : Access DRM content. (S)": 0,
    "Default : Access Email provider data (S)": 0,
    "Default : Access all system downloads (S)": 0,
    "... [226 total binary features]": 0
  }
}`}</pre>
          <p>
            The object must contain all 226 configured feature keys mapped to 0 or 1.
          </p>
        </details>
      </div>

      <form onSubmit={handleSubmit} noValidate>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "9px" }}>
          <label htmlFor="android-feature-request" style={{ margin: 0 }}>
            Prepared Android Feature Vector (JSON)
          </label>
          <span
            style={{
              fontSize: "0.75rem",
              fontWeight: 600,
              padding: "2px 8px",
              borderRadius: "4px",
              background: detectionStatus.ready ? "#e8f5ee" : "#f1f5f9",
              color: detectionStatus.ready ? "#2e7d32" : "#64748b",
            }}
          >
            {detectionStatus.count} / {REQUIRED_FEATURE_COUNT} features detected
            {detectionStatus.ready ? " (Ready)" : ""}
          </span>
        </div>

        <textarea
          id="android-feature-request"
          name="android-feature-request"
          value={requestText}
          onChange={(event) => {
            setRequestText(event.target.value);
            setResult(null);
            setError("");
          }}
          rows={12}
          spellCheck="false"
          aria-describedby="android-feature-help android-input-note"
          placeholder={'Paste the complete JSON object with a "features" map.'}
        />

        <div className="android-input-meta">
          <span id="android-input-note">
            The client validates JSON syntax and 0/1 binary values; the backend validates exact feature keys.
          </span>
          <span>{requestText.length.toLocaleString()} characters</span>
        </div>

        <div className="android-form-actions">
          <button
            className="button button-android"
            type="submit"
            disabled={isLoading || !requestText.trim()}
          >
            {isLoading ? (
              <>
                <span className="spinner spinner-android" aria-hidden="true" />
                Evaluating vector…
              </>
            ) : (
              "Analyse Benchmark"
            )}
          </button>
          <button
            className="button button-quiet"
            type="button"
            onClick={handleLoadSample}
            disabled={isLoading}
            title="Load precomputed 226-feature sample vector"
          >
            Load Sample Vector
          </button>
          <button
            className="button button-quiet"
            type="button"
            onClick={handleClear}
            disabled={isLoading || (!requestText && !result && !error)}
            title="Clear input and results"
          >
            Clear
          </button>
          {isLoading && (
            <span className="android-loading-message" role="status">
              Sending prepared vector to benchmark service…
            </span>
          )}
        </div>
      </form>

      {error && (
        <div className="error-banner android-error-banner" role="alert">
          <span className="error-symbol" aria-hidden="true">!</span>
          <div>
            <strong>Benchmark evaluation could not be completed</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* Results Section */}
      <BenchmarkResult result={result} />

      {/* Research Information & Technical Context */}
      <section className="android-research-info" aria-labelledby="research-info-heading">
        <h3 id="research-info-heading">Research Context &amp; Limitations</h3>
        <div className="android-info-grid">
          <div className="android-info-card">
            <h4>Why 226 Features Are Used</h4>
            <p>
              This benchmark utilizes a legacy academic feature space constructed from Android manifest permissions, intent filters, and suspicious API indicators used in historical malware classification research.
            </p>
          </div>
          <div className="android-info-card">
            <h4>Why Precomputed Vectors Are Required</h4>
            <p>
              The Random Forest model was trained strictly on tabular, pre-extracted vectors. It cannot consume raw APK binaries, DEX bytecode, or runtime traces directly.
            </p>
          </div>
          <div className="android-info-card">
            <h4>Why Only 44 Features Are Reproducible</h4>
            <p>
              Systematic extraction audits demonstrated that only 44 of the 226 features can be reliably extracted statically from an APK container. The remaining 182 reflect deprecated, dynamic, or inaccessible platform markers, making direct APK scoring invalid.
            </p>
          </div>
          <div className="android-info-card">
            <h4>Dataset Limitations &amp; Boundaries</h4>
            <p>
              Trained on historical research datasets with uncalibrated decision thresholds. Benchmark scores are research signals for comparative analysis and must not be used as proof of maliciousness or safety.
            </p>
          </div>
        </div>
      </section>
    </section>
  );
}
