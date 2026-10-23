import { useState } from "react";
import AnalysisResult from "./components/AnalysisResult.jsx";
import AwarenessSection from "./components/AwarenessSection.jsx";
import { analyzeContent } from "./api/analyze.js";

const MAX_LENGTH = 10_000;

export default function App() {
  const [content, setContent] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const canAnalyze = content.trim().length > 0 && content.length <= MAX_LENGTH && !isLoading;

  async function handleSubmit(event) {
    event.preventDefault();
    if (!canAnalyze) return;
    setIsLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await analyzeContent(content));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Analysis failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  }

  function handleClear() {
    setContent("");
    setResult(null);
    setError("");
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="Signal Check home">
          <span className="brand-mark" aria-hidden="true"><span /></span>
          <span>Signal<span className="brand-light">Check</span></span>
        </a>
        <span className="header-note"><span className="status-dot" /> Awareness tool · Version 1</span>
      </header>

      <main id="top">
        <section className="hero" aria-labelledby="page-title">
          <div className="hero-copy">
            <p className="eyebrow"><span className="eyebrow-line" /> PAUSE. CHECK. PROTECT.</p>
            <h1 id="page-title">A second look can<br /><span>make all the difference.</span></h1>
            <p className="hero-description">Analyze suspicious messages and links to identify potential warning signs and learn how to stay safe.</p>
            <div className="privacy-note"><span className="privacy-icon" aria-hidden="true">⌑</span><span>Your text is sent to the backend for analysis. This application does not save submissions by default.</span></div>
          </div>
          <div className="hero-art" aria-hidden="true">
            <div className="orbit orbit-one" /><div className="orbit orbit-two" />
            <div className="shield"><div className="shield-inner"><span className="shield-check">✓</span></div></div>
            <div className="float-card float-card-one"><span className="float-icon icon-link">↗</span><span><b>Link check</b><small>Look before you tap</small></span></div>
            <div className="float-card float-card-two"><span className="float-icon icon-lock">⌑</span><span><b>Stay in control</b><small>Keep your details private</small></span></div>
            <span className="spark spark-one">✳</span><span className="spark spark-two">✦</span>
          </div>
        </section>

        <section className="analyzer-card" aria-labelledby="analyzer-title">
          <div className="analyzer-intro">
            <div className="step-icon" aria-hidden="true">01</div>
            <div><p className="eyebrow">MESSAGE CHECK</p><h2 id="analyzer-title">What would you like to check?</h2><p>Paste a suspicious message, link, or both. We’ll look for configured warning signs.</p></div>
          </div>
          <form onSubmit={handleSubmit}>
            <label htmlFor="message-content">Message or URL</label>
            <textarea
              id="message-content"
              name="content"
              value={content}
              onChange={(event) => { setContent(event.target.value.slice(0, MAX_LENGTH)); setResult(null); setError(""); }}
              maxLength={MAX_LENGTH}
              placeholder="Paste the message or link here…"
              rows={7}
              aria-describedby="input-help character-count privacy-inline"
            />
            <div className="form-meta"><span id="input-help">Text and URLs are analyzed locally by the backend.</span><span id="character-count" className={content.length >= MAX_LENGTH ? "count-limit" : ""}>{content.length.toLocaleString()} / 10,000</span></div>
            <div className="form-actions">
              <button className="button button-primary" type="submit" disabled={!canAnalyze}>
                {isLoading ? <><span className="spinner" aria-hidden="true" /> Analyzing…</> : <>Analyze message <span aria-hidden="true">→</span></>}
              </button>
              <button className="button button-quiet" type="button" onClick={handleClear} disabled={isLoading || (!content && !result && !error)}>Clear</button>
              <span className="privacy-inline" id="privacy-inline"><span aria-hidden="true">♧</span> Not saved by this app by default</span>
            </div>
          </form>
          {error && <div className="error-banner" role="alert"><span className="error-symbol" aria-hidden="true">!</span><div><strong>We couldn’t complete the analysis</strong><p>{error}</p></div></div>}
          {isLoading && <p className="loading-message" role="status">Checking the submitted text and URL strings…</p>}
          <AnalysisResult result={result} />
        </section>

        <AwarenessSection />

        <section className="reporting-banner" aria-labelledby="report-title">
          <div className="report-icon" aria-hidden="true">↗</div>
          <div><p className="eyebrow">NEED TO TAKE ACTION?</p><h2 id="report-title">Report cybercrime through official channels</h2><p>Signal Check is an awareness tool, not a replacement for official support or reporting.</p></div>
          <a className="report-link" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">Visit National Cyber Crime Portal <span aria-hidden="true">↗</span></a>
        </section>
      </main>

      <footer className="site-footer"><a className="brand footer-brand" href="#top"><span className="brand-mark" aria-hidden="true"><span /></span><span>Signal<span className="brand-light">Check</span></span></a><p>Clearer signals. Safer choices.</p><span>Heuristic guidance · No guarantee of safety</span></footer>
    </div>
  );
}
