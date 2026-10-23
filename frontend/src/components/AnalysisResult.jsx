const RISK_LABELS = { low: "Low", medium: "Medium", high: "High" };

export default function AnalysisResult({ result }) {
  if (!result) return null;

  return (
    <section className="result-panel" aria-labelledby="result-title" aria-live="polite">
      <div className="result-heading">
        <div>
          <p className="eyebrow">Analysis complete</p>
          <h2 id="result-title">Your results</h2>
        </div>
        <span className={`risk-pill risk-${result.risk_level}`}>
          <span className="risk-dot" aria-hidden="true" />
          {RISK_LABELS[result.risk_level]} risk
        </span>
      </div>

      <div className="score-row">
        <div className={`score-number score-${result.risk_level}`} aria-label={`Risk score ${result.risk_score} out of 100`}>
          {result.risk_score}<span>/100</span>
        </div>
        <div className="score-meter" role="img" aria-label={`Heuristic score: ${result.risk_score} out of 100`}>
          <div className={`score-fill fill-${result.risk_level}`} style={{ width: `${result.risk_score}%` }} />
        </div>
      </div>

      <p className="result-summary">{result.summary}</p>

      <div className="result-section">
        <h3>Detected indicators <span className="count-badge">{result.detected_indicators.length}</span></h3>
        {result.detected_indicators.length ? (
          <ul className="indicator-list">
            {result.detected_indicators.map((item) => (
              <li className="indicator-card" key={item.rule_id}>
                <div className="indicator-topline">
                  <div>
                    <span className="rule-tag">{item.rule_id}</span>
                    <span className="category-tag">{item.category.replaceAll("_", " ")}</span>
                  </div>
                  <span className="contribution">+{item.score_contribution} pts</span>
                </div>
                <h4>{item.title}</h4>
                <p>{item.explanation}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="no-findings">No configured warning signs were identified in this submission. This does not prove the content is safe.</p>
        )}
      </div>

      <div className="result-section recommendations">
        <h3>Recommended next steps</h3>
        <ul>{result.recommendations.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>
      </div>
      <p className="disclaimer"><strong>Keep in mind:</strong> {result.disclaimer}</p>
    </section>
  );
}
