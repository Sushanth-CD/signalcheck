export default function SMSAnalysisResult({ result }) {
  if (!result) return null;

  const score = Number(result.smishing_score).toFixed(4);
  const threshold = Number(result.threshold).toFixed(4);
  const isSmishing = result.classification === "smishing";

  return (
    <section className="ml-result-panel sms-result-panel" aria-labelledby="sms-result-title" aria-live="polite">
      <div className="ml-result-heading">
        <div>
          <p className="eyebrow">SMS MODEL CLASSIFICATION</p>
          <h2 id="sms-result-title">SMS analysis result</h2>
        </div>
        <span
          className={`ml-classification ${
            isSmishing ? "ml-classification-phishing" : "ml-classification-not-smishing"
          }`}
        >
          {isSmishing ? "Smishing" : "Not classified as smishing"}
        </span>
      </div>

      <dl className="ml-result-details">
        <div>
          <dt>Uncalibrated model score</dt>
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
        The model score is uncalibrated. A negative classification does not prove that a message is safe. Review the message and its context.
      </p>
      <p className="ml-disclaimer">{result.disclaimer}</p>
    </section>
  );
}
