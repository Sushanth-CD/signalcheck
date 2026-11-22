import { ShieldCheckIcon, AlertTriangleIcon, InfoIcon } from "./ui/Icons.jsx";

export default function AboutSafetySection() {
  return (
    <div className="sc-about-safety-view">
      <header className="sc-view-header">
        <span className="sc-view-header__eyebrow">TRANSPARENCY &amp; LIMITATIONS</span>
        <h1 className="sc-view-header__title">About SignalCheck &amp; Safety Guidelines</h1>
        <p className="sc-view-header__description">
          SignalCheck is an educational cybersecurity awareness tool designed to evaluate suspicious messages, links, and mobile indicators using automated machine learning models.
        </p>
      </header>

      <div className="sc-about-grid">
        <section className="sc-about-card" aria-labelledby="scope-title">
          <div className="sc-about-card__icon-wrap">
            <InfoIcon size={22} />
          </div>
          <h2 id="scope-title" className="sc-about-card__title">What SignalCheck Analyzes</h2>
          <p className="sc-about-card__text">
            SignalCheck uses dedicated statistical models to detect known indicators of deception:
          </p>
          <ul className="sc-about-card__list">
            <li>
              <strong>Web Phishing &amp; Deceptive URLs:</strong> Analyzes email bodies, web links, and credential-harvesting text for lexical patterns common in phishing campaigns.
            </li>
            <li>
              <strong>SMS Smishing:</strong> Evaluates short mobile messages (with or without links) for urgent appeals, deceptive verification prompts, and bank impersonation.
            </li>
            <li>
              <strong>Android Static Analysis (Research Lab):</strong> Performs ephemeral static inspection of uploaded Android packages (.apk) for dangerous permission combinations, component configurations, cryptographic signatures, and bytecode indicators without installing or executing code.
            </li>
            <li>
              <strong>Android Feature Research:</strong> Provides an offline research interface to inspect pre-computed Android permissions and structural indicators against research baselines.
            </li>
          </ul>
        </section>

        <section className="sc-about-card" aria-labelledby="scores-title">
          <div className="sc-about-card__icon-wrap">
            <AlertTriangleIcon size={22} />
          </div>
          <h2 id="scores-title" className="sc-about-card__title">How to Interpret Model Scores</h2>
          <p className="sc-about-card__text">
            Our models produce <strong>uncalibrated decision values</strong>, not percentage probabilities:
          </p>
          <ul className="sc-about-card__list">
            <li>
              <strong>Not a Probability:</strong> A score of <code>0.8200</code> means the input is positioned on the malicious side of the model’s linear decision plane. It does <em>not</em> mean "82% chance of fraud".
            </li>
            <li>
              <strong>Classification Threshold:</strong> A predefined threshold (e.g., <code>0.5000</code>) divides positive and negative classifications based on experimental tuning.
            </li>
            <li>
              <strong>Model Identification:</strong> Every analysis clearly indicates the exact model artifact utilized (e.g., <code>phish-v2-linear-svc</code> or <code>SMS-05-C</code>) for auditability.
            </li>
          </ul>
        </section>

        <section className="sc-about-card" aria-labelledby="limitations-title">
          <div className="sc-about-card__icon-wrap">
            <ShieldCheckIcon size={22} />
          </div>
          <h2 id="limitations-title" className="sc-about-card__title">Detection Limitations &amp; No Safety Guarantees</h2>
          <p className="sc-about-card__text">
            Automated machine learning models have inherent limitations that every user should understand:
          </p>
          <ul className="sc-about-card__list">
            <li>
              <strong>No Guarantee of Safety:</strong> A "Benign" or "Not Smishing" verdict means the model did not identify known markers. Novel campaigns, targeted spear-phishing, or zero-day tactics may evade detection.
            </li>
            <li>
              <strong>Context is Vital:</strong> Always consider context. If an unexpected message asks for urgency, passwords, or one-time codes, pause and verify regardless of automated tool outputs.
            </li>
            <li>
              <strong>Educational Tool Only:</strong> SignalCheck does not offer certifications, technical guarantees, or professional security advice.
            </li>
          </ul>
        </section>
      </div>

      <section className="reporting-banner" aria-labelledby="report-action-title">
        <div className="report-icon" aria-hidden="true">↗</div>
        <div>
          <p className="eyebrow">OFFICIAL INCIDENT REPORTING</p>
          <h2 id="report-action-title">Report cybercrime through official channels</h2>
          <p>If you have been targeted by financial fraud, impersonation, or extortion, contact the National Cyber Crime Portal.</p>
        </div>
        <a className="report-link" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">
          Visit National Cyber Crime Portal <span aria-hidden="true">↗</span>
        </a>
      </section>
    </div>
  );
}
