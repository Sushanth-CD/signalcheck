export default function MLAnalysisResult({ result }) {
  if (!result) return null;

  const score = Number(result.phishing_score).toFixed(4);
  const threshold = Number(result.threshold).toFixed(4);

  return (
    <section className="ml-result-panel" aria-labelledby="ml-result-title" aria-live="polite">
      <div className="ml-result-heading">
        <div>
          <p className="eyebrow">MODEL CLASSIFICATION</p>
          <h2 id="ml-result-title">ML analysis result</h2>
        </div>
        <span className={`ml-classification ml-classification-${result.classification}`}>
          {result.classification === "phishing" ? "Phishing" : "Benign"}
        </span>
      </div>

      <dl className="ml-result-details">
        <div>
          <dt>Uncalibrated phishing score</dt>
          <dd>{score}</dd>
        </div>
        <div>
          <dt>Classification threshold</dt>
          <dd>{threshold}</dd>
        </div>
        <div className="ml-model-id">
          <dt>Model identifier</dt>
          <dd>{result.model_id}</dd>
        </div>
      </dl>

      <p className="ml-score-note">
        This score is not a percentage probability and does not prove that a message is malicious or safe.
      </p>
      <p className="ml-disclaimer">{result.disclaimer}</p>
    </section>
  );
}
