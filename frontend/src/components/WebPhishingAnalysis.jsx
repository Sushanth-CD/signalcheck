import { useState } from "react";
import AnalysisSummaryCard from "./ui/AnalysisSummaryCard.jsx";
import { analyzeWithML } from "../api/analyze.js";

const MAX_LENGTH = 10_000;

export default function WebPhishingAnalysis() {
  const [content, setContent] = useState("");
  const [mlResult, setMLResult] = useState(null);
  const [mlError, setMLError] = useState("");
  const [isMLLoading, setIsMLLoading] = useState(false);
  const canAnalyze = content.trim().length > 0 && content.length <= MAX_LENGTH && !isMLLoading;

  async function handleSubmit(event) {
    event.preventDefault();
    if (!canAnalyze) return;
    setIsMLLoading(true);
    setMLError("");
    setMLResult(null);
    try {
      const response = await analyzeWithML(content);
      setMLResult(response);
    } catch (requestError) {
      setMLError(
        requestError instanceof Error
          ? requestError.message
          : "ML analysis failed. Please try again."
      );
    } finally {
      setIsMLLoading(false);
    }
  }

  function handleClear() {
    setContent("");
    setMLResult(null);
    setMLError("");
  }

  function handleContentChange(event) {
    setContent(event.target.value.slice(0, MAX_LENGTH));
    // Immediately clear stale result to avoid showing outdated assessment for newly entered text
    if (mlResult) setMLResult(null);
    if (mlError) setMLError("");
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
    <section className="analyzer-card" aria-labelledby="analyzer-title">
      <div className="analyzer-intro">
        <div className="step-icon" aria-hidden="true">01</div>
        <div>
          <p className="eyebrow">PHISHING &amp; SCAM DETECTION</p>
          <h2 id="analyzer-title">Analyze a message with ML</h2>
          <p>
            The saved text-classification model returns an assessment and uncalibrated phishing score.
          </p>
        </div>
      </div>
      <form onSubmit={handleSubmit}>
        <label htmlFor="message-content">Message or URL</label>
        <textarea
          id="message-content"
          name="content"
          value={content}
          onChange={handleContentChange}
          onKeyDown={handleKeyDown}
          maxLength={MAX_LENGTH}
          placeholder="Paste suspicious message text, an email body, or website URL here…"
          rows={7}
          aria-describedby="input-help character-count privacy-inline"
        />
        <div className="form-meta">
          <span id="input-help">Submitted text is scored by the local backend model.</span>
          <span
            id="character-count"
            className={content.length >= MAX_LENGTH ? "count-limit" : ""}
          >
            {content.length.toLocaleString()} / 10,000
          </span>
        </div>
        <div className="form-actions">
          <button className="button button-primary" type="submit" disabled={!canAnalyze}>
            {isMLLoading ? (
              <>
                <span className="spinner" aria-hidden="true" /> Analyzing…
              </>
            ) : (
              <>
                Analyze message <span aria-hidden="true">→</span>
              </>
            )}
          </button>
          <button
            className="button button-quiet"
            type="button"
            onClick={handleClear}
            disabled={isMLLoading || (!content && !mlResult && !mlError)}
          >
            Clear
          </button>
          <span className="privacy-inline" id="privacy-inline">
            <span aria-hidden="true">♧</span> Not saved by this app by default
          </span>
        </div>
      </form>
      {isMLLoading && (
        <p className="loading-message ml-loading-message" role="status">
          Running the local phishing text classifier…
        </p>
      )}
      {mlError && (
        <div className="error-banner ml-error-banner" role="alert">
          <span className="error-symbol" aria-hidden="true">!</span>
          <div>
            <strong>ML analysis could not be completed</strong>
            <p>{mlError}</p>
          </div>
        </div>
      )}

      {/* Upgraded Phase 3 Unified Result Experience */}
      <AnalysisSummaryCard
        result={mlResult}
        analyzerType="web"
        id="web-analysis-result"
      />
    </section>
  );
}
