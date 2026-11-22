import { useRef, useState } from "react";
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
    throw new Error(`Provide exactly ${REQUIRED_FEATURE_COUNT} configured features.`);
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

function AndroidResult({ result }) {
  if (!result) return null;

  return (
    <section className="android-result-panel" aria-labelledby="android-result-title" aria-live="polite">
      <div className="android-result-heading">
        <div>
          <p className="eyebrow">ANDROID MODEL RESULT</p>
          <h3 id="android-result-title">Feature analysis result</h3>
        </div>
        <span className={`android-classification android-classification-${result.classification}`}>
          {result.classification === "malicious" ? "Benchmark output: high score" : "Benchmark output: low score"}
        </span>
      </div>

      <dl className="android-result-details">
        <div>
          <dt>Uncalibrated malware score</dt>
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
        This is an uncalibrated model score, not a percentage probability or proof that an application is malicious or safe.
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

  return (
    <section className="android-analysis-card" aria-labelledby="android-analysis-title">
      <div className="android-analysis-intro">
        <div className="android-step-icon" aria-hidden="true">02</div>
        <div>
          <p className="eyebrow">PREPARED FEATURE DATA</p>
          <h2 id="android-analysis-title">Android Application Feature Analysis</h2>
          <p>Submit Android permission and feature values that have already been prepared for this model.</p>
        </div>
      </div>

      <div style={{ marginBottom: "1.25rem" }}>
        <StatusBanner
          variant="warning"
          title="Offline Research Benchmark"
        >
          Offline research benchmark on precomputed vectors. Only 44 of 226 features can be reproduced from an APK, so this tool cannot score uploaded APKs.
        </StatusBanner>
      </div>

      <div className="android-requirements" id="android-feature-help">
        <p>The request must contain exactly 226 features from the model’s saved configuration.</p>
        <ul>
          <li>Feature names must match the saved model configuration exactly.</li>
          <li>Every value must be the integer 0 or 1.</li>
          <li>This accepts prepared feature data, not an APK file.</li>
          <li>Only 44 of 226 features can be reproduced from an APK, so this tool cannot score uploaded APKs.</li>
        </ul>
        <details className="android-example">
          <summary>View JSON structure</summary>
          <pre>{`{
  "features": {}
}`}</pre>
          <p>This is a structure-only example and is incomplete. Add all 226 exact configured feature names and their 0/1 values; an empty map will be rejected.</p>
        </details>
      </div>

      <form onSubmit={handleSubmit} noValidate>
        <label htmlFor="android-feature-request">Prepared Android feature request (JSON)</label>
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
          <span id="android-input-note">The client checks JSON structure and binary values; the backend verifies the configured feature names.</span>
          <span>{requestText.length.toLocaleString()} characters</span>
        </div>
        <div className="android-form-actions">
          <button className="button button-android" type="submit" disabled={isLoading || !requestText.trim()}>
            {isLoading ? <><span className="spinner spinner-android" aria-hidden="true" /> Analyzing features…</> : "Analyze Android features"}
          </button>
          <button
            className="button button-quiet"
            type="button"
            onClick={() => {
              setRequestText(JSON.stringify(SAMPLE_ANDROID_FEATURES, null, 2));
              setResult(null);
              setError("");
            }}
            disabled={isLoading}
            title="Load precomputed 226-feature sample vector"
          >
            Load sample vector
          </button>
          {isLoading && <span className="android-loading-message" role="status">Sending prepared features to the local backend…</span>}
        </div>
      </form>

      {error && (
        <div className="error-banner android-error-banner" role="alert">
          <span className="error-symbol" aria-hidden="true">!</span>
          <div><strong>Android feature analysis could not be completed</strong><p>{error}</p></div>
        </div>
      )}
      <AndroidResult result={result} />
    </section>
  );
}
