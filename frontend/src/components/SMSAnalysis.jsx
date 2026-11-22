import { useState } from "react";
import AnalysisSummaryCard from "./ui/AnalysisSummaryCard.jsx";
import { analyzeSMS } from "../api/analyze.js";

const SMS_MAX_LENGTH = 2_000;
const SMS_TRAINING_MAX_LENGTH = 1_445;

export default function SMSAnalysis() {
  const [content, setContent] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isTruncated, setIsTruncated] = useState(false);

  const trimmed = content.trim();
  const canAnalyze = trimmed.length > 0 && content.length <= SMS_MAX_LENGTH && !isLoading;
  const isExceedingTrainingLength = content.length > SMS_TRAINING_MAX_LENGTH;

  async function handleSubmit(event) {
    event.preventDefault();
    if (!canAnalyze) return;

    setIsLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await analyzeSMS(content);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "SMS analysis failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  }

  function handleClear() {
    setContent("");
    setResult(null);
    setError("");
    setIsTruncated(false);
  }

  function handleContentChange(event) {
    const raw = event.target.value;
    if (raw.length > SMS_MAX_LENGTH) {
      setIsTruncated(true);
      setContent(raw.slice(0, SMS_MAX_LENGTH));
    } else {
      setIsTruncated(false);
      setContent(raw);
    }
    // Prevent stale result from displaying when typing new content
    if (result) setResult(null);
    if (error) setError("");
  }

  function handleKeyDown(event) {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      if (canAnalyze) {
        handleSubmit(event);
      }
    }
  }

  return (
    <section className="analyzer-card sms-analysis-card" aria-labelledby="sms-analyzer-title">
      <div className="analyzer-intro">
        <div className="step-icon sms-step-icon" aria-hidden="true">SMS</div>
        <div>
          <p className="eyebrow">SMS PHISHING (SMISHING) DETECTION</p>
          <h2 id="sms-analyzer-title">Analyze an SMS message</h2>
          <p>
            The dedicated SMS-05-C model analyzes both linkless and URL-bearing text messages for smishing indicators.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <label htmlFor="sms-content">SMS message text</label>
        <textarea
          id="sms-content"
          name="content"
          value={content}
          onChange={handleContentChange}
          onKeyDown={handleKeyDown}
          maxLength={SMS_MAX_LENGTH}
          placeholder="Paste suspicious SMS text, a package notice, or mobile bank alert here…"
          rows={5}
          aria-describedby="sms-input-help sms-character-count sms-privacy-inline"
        />

        <div className="form-meta">
          <span id="sms-input-help">
            Evaluated by the dedicated linkless-aware SMS model (SMS-05-C).
          </span>
          <span
            id="sms-character-count"
            className={content.length >= SMS_MAX_LENGTH ? "count-limit" : ""}
          >
            {content.length.toLocaleString()} / 2,000
          </span>
        </div>

        {isTruncated && (
          <div className="sms-notice-banner sms-truncation-notice" role="status">
            <span className="notice-symbol" aria-hidden="true">ℹ</span>
            <span>Input reached the 2,000-character limit; additional characters were not included.</span>
          </div>
        )}

        {isExceedingTrainingLength && (
          <div className="sms-notice-banner sms-training-length-notice" role="status">
            <span className="notice-symbol" aria-hidden="true">ℹ</span>
            <span>Messages longer than the model’s observed training examples may have less reliable results.</span>
          </div>
        )}

        <div className="form-actions">
          <button className="button button-primary button-sms" type="submit" disabled={!canAnalyze}>
            {isLoading ? (
              <>
                <span className="spinner" aria-hidden="true" /> Analyzing…
              </>
            ) : (
              <>
                Analyze SMS message <span aria-hidden="true">→</span>
              </>
            )}
          </button>
          <button
            className="button button-quiet"
            type="button"
            onClick={handleClear}
            disabled={isLoading || (!content && !result && !error && !isTruncated)}
          >
            Clear
          </button>
          <span className="privacy-inline" id="sms-privacy-inline">
            <span aria-hidden="true">♧</span> Not saved by this app by default
          </span>
        </div>
      </form>

      {isLoading && (
        <p className="loading-message sms-loading-message" role="status">
          Running the dedicated SMS smishing classifier…
        </p>
      )}

      {error && (
        <div className="error-banner sms-error-banner" role="alert">
          <span className="error-symbol" aria-hidden="true">!</span>
          <div>
            <strong>SMS analysis could not be completed</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* Upgraded Phase 3 Unified Result Experience */}
      <AnalysisSummaryCard
        result={result}
        analyzerType="sms"
        id="sms-analysis-result"
      />
    </section>
  );
}
