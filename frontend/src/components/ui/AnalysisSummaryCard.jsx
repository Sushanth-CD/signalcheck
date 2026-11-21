/**
 * AnalysisSummaryCard: Unified threat analysis result card for SignalCheck.
 * Compatible with both:
 * - Web Phishing: classification ('phishing'|'benign'), phishing_score, threshold, model_id, disclaimer
 * - SMS Smishing: classification ('smishing'|'not_smishing'), smishing_score, threshold, model_id, disclaimer
 *
 * CRITICAL SCIENTIFIC & USER-EXPERIENCE RULES:
 * - Uncalibrated model scores are NEVER displayed as percentages or probabilities.
 * - Score is formatted as an exact raw decimal (e.g. 0.8412).
 * - Avoids overstating certainty: uses "Potential Threat Detected" vs "No Characteristic Threat Indicators Detected".
 * - Clearly explains what the model found and explicitly acknowledges detection limitations.
 * - Transparently notes that token-level/feature-level attribution is not provided by the current model.
 * - Contextual, actionable safety recommendations are provided.
 */
import {
  ShieldAlertIcon,
  ShieldCheckIcon,
  InfoIcon,
  ChevronDownIcon,
  AlertTriangleIcon,
} from "./Icons.jsx";
import { useState } from "react";

export default function AnalysisSummaryCard({
  result,
  analyzerType = "web", // 'web' | 'sms'
  className = "",
  id = "analysis-summary",
}) {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  if (!result) return null;

  // Extract fields from actual API response structures
  const rawScore =
    typeof result.phishing_score === "number"
      ? result.phishing_score
      : typeof result.smishing_score === "number"
      ? result.smishing_score
      : null;

  const threshold = typeof result.threshold === "number" ? result.threshold : null;
  const classification = result.classification || "";
  const modelId = result.model_id || "Unspecified Model";
  const disclaimer = result.disclaimer || "";

  // Determine threat severity based on exact API classification strings
  const isThreat =
    classification === "phishing" || classification === "smishing";
  const isBenignWeb = classification === "benign";
  const isNotSmishing = classification === "not_smishing";

  const statusVariant = isThreat ? "threat" : "clean";

  // Detailed plain-language interpretation based on channel and verdict
  let badgeLabel = "";
  let assessmentTitle = "";
  let assessmentExplanation = "";
  let guidanceTitle = "";
  let guidanceList = [];

  if (analyzerType === "sms") {
    if (isThreat) {
      badgeLabel = "Potential Smishing Detected";
      assessmentTitle = "Suspicious Mobile Scam Indicators Flagged";
      assessmentExplanation =
        "The dedicated SMS classifier evaluated this message and identified text patterns frequently associated with smishing, urgent fraud alerts, or deceptive mobile lures. The model flagged this message as potential smishing based on statistical pattern matching.";
      guidanceTitle = "Recommended Actions for Suspicious SMS";
      guidanceList = [
        "Do not tap or open any web links contained in this text message.",
        "Never reply with one-time passcodes (OTPs), account numbers, passwords, or PINs.",
        "Do not call phone numbers supplied directly within the suspicious message.",
        "If the message claims to be from a bank, delivery company, or government agency, contact them through their official website or app.",
        "Report the suspicious sender to your mobile network operator's spam service (e.g. 1909 in India) or official cybercrime authorities.",
      ];
    } else {
      badgeLabel = "Not Classified as Smishing";
      assessmentTitle = "No Characteristic Smishing Patterns Detected";
      assessmentExplanation =
        "The SMS classifier did not identify patterns matching known smishing lures in this text. However, legitimate-looking messages can still be fraudulent, and novel social engineering campaigns may not match previously observed patterns.";
      guidanceTitle = "Safety Best Practices";
      guidanceList = [
        "A negative classification does not prove that an unexpected message is authentic or safe.",
        "Never share sensitive credentials, bank OTPs, or financial details over text message.",
        "Independently verify any message requesting urgent funds, fee payments, or account changes.",
      ];
    }
  } else {
    // Web Phishing & URL Scanner
    if (isThreat) {
      badgeLabel = "Potential Phishing Detected";
      assessmentTitle = "Suspicious Phishing Patterns Flagged";
      assessmentExplanation =
        "The text classification model identified structural or lexical characteristics commonly observed in phishing pages, credential-harvesting forms, or deceptive links. Note: This assessment is based on automated statistical classification and does not constitute independent investigative verification.";
      guidanceTitle = "Recommended Actions for Suspicious Links/Text";
      guidanceList = [
        "Do not enter usernames, passwords, credit card numbers, or personal identity details.",
        "Do not download attachments or install software prompted by this content.",
        "Carefully verify the destination domain in your browser address bar for typosquatting or deceptive subdomains.",
        "If you suspect your organization or credentials have been compromised, immediately notify your IT security team or the National Cyber Crime Portal.",
      ];
    } else {
      badgeLabel = "Benign / No Threat Patterns Detected";
      assessmentTitle = "No Characteristic Phishing Indicators Detected";
      assessmentExplanation =
        "The text classification model did not identify lexical markers typical of known phishing or scam campaigns. However, this automated classification does not establish that the website or message is genuinely safe.";
      guidanceTitle = "Safety Best Practices";
      guidanceList = [
        "This tool provides automated model guidance, not an absolute guarantee of safety.",
        "Always verify the authentic web address before entering login credentials or processing payments.",
        "If an unexpected message prompts high urgency or uncharacteristic requests, verify through an out-of-band channel.",
      ];
    }
  }

  return (
    <section
      id={id}
      className={`sc-analysis-summary sc-analysis-summary--${statusVariant} ${className}`}
      aria-labelledby={`${id}-heading`}
      aria-live="polite"
    >
      {/* 1. Primary Model Assessment Header */}
      <div className="sc-analysis-summary__header">
        <div className="sc-analysis-summary__badge-group">
          <span
            className={`sc-verdict-badge sc-verdict-badge--${statusVariant}`}
            role="status"
          >
            {isThreat ? (
              <ShieldAlertIcon size={16} className="sc-verdict-badge__icon" />
            ) : (
              <ShieldCheckIcon size={16} className="sc-verdict-badge__icon" />
            )}
            <span>{badgeLabel}</span>
          </span>
          <span className="sc-analysis-summary__eyebrow">
            {analyzerType === "sms"
              ? "SMS-05-C CLASSIFICATION"
              : "TEXT CLASSIFIER CLASSIFICATION"}
          </span>
        </div>

        <h3 id={`${id}-heading`} className="sc-analysis-summary__title">
          {assessmentTitle}
        </h3>
        <p className="sc-analysis-summary__subtitle">
          {assessmentExplanation}
        </p>
      </div>

      {/* 2. Explainability & Supporting Evidence Transparency */}
      <div className="sc-analysis-summary__evidence-note">
        <div className="sc-evidence-box">
          <InfoIcon size={18} className="sc-evidence-box__icon" />
          <div className="sc-evidence-box__text">
            <strong>Explainability &amp; Model Evidence:</strong> The current
            endpoint evaluates aggregate statistical text features (e.g. n-gram
            and vocabulary frequencies). Token-level feature attributions or
            extracted rule matches are not supported by the backend model. General
            guidance below reflects recommended safety protocols, not model-derived
            proof of specific elements.
          </div>
        </div>
      </div>

      {/* 3. Recommended Actions Guidance */}
      <div className="sc-analysis-summary__guidance">
        <h4 className="sc-analysis-summary__guidance-title">
          {guidanceTitle}
        </h4>
        <ul className="sc-analysis-summary__guidance-list">
          {guidanceList.map((item, index) => (
            <li key={index} className="sc-analysis-summary__guidance-item">
              <span className="sc-analysis-summary__bullet" aria-hidden="true" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* 4. Collapsible Technical Verification Drawer */}
      <div className="sc-analysis-summary__technical">
        <button
          type="button"
          className="sc-technical-toggle"
          onClick={() => setShowTechnicalDetails((prev) => !prev)}
          aria-expanded={showTechnicalDetails}
          aria-controls={`${id}-technical-details`}
        >
          <InfoIcon size={16} />
          <span>Technical Model Scores &amp; Audit Metadata</span>
          <ChevronDownIcon
            size={16}
            className={`sc-technical-toggle__chevron ${
              showTechnicalDetails ? "sc-technical-toggle__chevron--open" : ""
            }`}
          />
        </button>

        {showTechnicalDetails && (
          <div
            id={`${id}-technical-details`}
            className="sc-technical-details-panel"
          >
            <div className="sc-technical-grid">
              <div className="sc-technical-stat">
                <span className="sc-technical-stat__label">
                  Raw Model Score
                </span>
                <span className="sc-technical-stat__value">
                  {rawScore !== null ? Number(rawScore).toFixed(4) : "N/A"}
                </span>
                <span className="sc-technical-stat__hint">
                  Uncalibrated decision value. Not a probability, confidence percentage, or risk rating.
                </span>
              </div>

              <div className="sc-technical-stat">
                <span className="sc-technical-stat__label">
                  Decision Threshold
                </span>
                <span className="sc-technical-stat__value">
                  {threshold !== null ? Number(threshold).toFixed(4) : "N/A"}
                </span>
                <span className="sc-technical-stat__hint">
                  Saved model boundary. Values above threshold map to positive class.
                </span>
              </div>

              <div className="sc-technical-stat">
                <span className="sc-technical-stat__label">
                  Exact Output Classification
                </span>
                <span className="sc-technical-stat__value sc-technical-stat__value--mono">
                  {classification}
                </span>
                <span className="sc-technical-stat__hint">
                  Categorical label directly returned by the backend service.
                </span>
              </div>

              <div className="sc-technical-stat">
                <span className="sc-technical-stat__label">
                  Model Identifier
                </span>
                <span className="sc-technical-stat__value sc-technical-stat__value--mono">
                  {modelId}
                </span>
                <span className="sc-technical-stat__hint">
                  Trained artifact version registered in backend ML registry.
                </span>
              </div>
            </div>

            {disclaimer && (
              <p className="sc-technical-disclaimer">
                <strong>Verbatim Model Disclaimer:</strong> {disclaimer}
              </p>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
