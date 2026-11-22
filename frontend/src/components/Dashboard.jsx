import { GlobeIcon, MessageIcon, ShieldAlertIcon, InfoIcon } from "./ui/Icons.jsx";
import AwarenessSection from "./AwarenessSection.jsx";

export default function Dashboard({ onNavigate }) {
  return (
    <div className="sc-dashboard-view">
      {/* SaaS Hero Section */}
      <section className="sc-hero-banner" aria-labelledby="dashboard-title">
        <div className="sc-hero-banner__copy">
          <span className="sc-hero-banner__eyebrow">
            EDUCATIONAL THREAT AWARENESS &amp; ANALYSIS
          </span>
          <h1 id="dashboard-title" className="sc-hero-banner__title">
            Verify Suspicious Messages <br />
            <span>Before You Tap</span>
          </h1>
          <p className="sc-hero-banner__description">
            SignalCheck provides targeted machine-learning analysis to help you recognize phishing lures, SMS smishing campaigns, and mobile threats with privacy-first local evaluation.
          </p>
          <div className="sc-hero-banner__actions">
            <button
              type="button"
              className="button button-primary"
              onClick={() => onNavigate("scanners", "web")}
            >
              Open Web Scanner <span aria-hidden="true">→</span>
            </button>
            <button
              type="button"
              className="button button-quiet"
              onClick={() => onNavigate("scanners", "sms")}
            >
              Open SMS Scanner <span aria-hidden="true">→</span>
            </button>
          </div>
        </div>
      </section>

      {/* Primary Tool Modules Grid */}
      <section className="sc-tools-section" aria-labelledby="tools-heading">
        <div className="sc-section-header">
          <div>
            <span className="sc-section-header__eyebrow">SCANNING WORKSPACES</span>
            <h2 id="tools-heading" className="sc-section-header__title">
              Specialized Threat Analyzers
            </h2>
          </div>
          <p className="sc-section-header__subtitle">
            Choose the focused scanner matching your suspect message channel.
          </p>
        </div>

        <div className="sc-tools-grid">
          {/* Card 1: Web & Link Scanner */}
          <article className="sc-tool-card" aria-labelledby="tool-web-title">
            <div className="sc-tool-card__icon-wrap sc-tool-card__icon-wrap--teal">
              <GlobeIcon size={24} />
            </div>
            <div className="sc-tool-card__content">
              <span className="sc-tool-card__badge">ML Model v2</span>
              <h3 id="tool-web-title" className="sc-tool-card__title">
                Web &amp; Link Scanner
              </h3>
              <p className="sc-tool-card__description">
                Evaluates deceptive URLs, suspicious emails, and credential-harvesting text using our dedicated linear text classifier.
              </p>
            </div>
            <div className="sc-tool-card__footer">
              <button
                type="button"
                className="button button-primary"
                onClick={() => onNavigate("scanners", "web")}
              >
                Scan Web Message <span aria-hidden="true">→</span>
              </button>
            </div>
          </article>

          {/* Card 2: SMS Smishing Scanner */}
          <article className="sc-tool-card" aria-labelledby="tool-sms-title">
            <div className="sc-tool-card__icon-wrap sc-tool-card__icon-wrap--emerald">
              <MessageIcon size={24} />
            </div>
            <div className="sc-tool-card__content">
              <span className="sc-tool-card__badge">SMS-05-C</span>
              <h3 id="tool-sms-title" className="sc-tool-card__title">
                SMS Smishing Scanner
              </h3>
              <p className="sc-tool-card__description">
                Specialized classifier designed for mobile SMS alerts. Analyzes both link-bearing and linkless social engineering lures.
              </p>
            </div>
            <div className="sc-tool-card__footer">
              <button
                type="button"
                className="button button-primary button-sms"
                onClick={() => onNavigate("scanners", "sms")}
              >
                Scan SMS Text <span aria-hidden="true">→</span>
              </button>
            </div>
          </article>

          {/* Card 3: Research Tools Entry */}
          <article className="sc-tool-card sc-tool-card--research" aria-labelledby="tool-research-title">
            <div className="sc-tool-card__icon-wrap sc-tool-card__icon-wrap--slate">
              <ShieldAlertIcon size={24} />
            </div>
            <div className="sc-tool-card__content">
              <span className="sc-tool-card__badge sc-tool-card__badge--neutral">
                Static Analysis
              </span>
              <h3 id="tool-research-title" className="sc-tool-card__title">
                Android APK Analysis
              </h3>
              <p className="sc-tool-card__description">
                Performs rule-based static analysis of an uploaded APK (permissions, components, signing, code indicators) in an isolated worker, with plain-language explanations of each finding. Operates using deterministic heuristic rules with no ML model.
              </p>
              <p className="sc-tool-card__subtext" style={{ fontSize: "0.8125rem", color: "var(--color-text-secondary, #64748b)", marginTop: "0.5rem" }}>
                A separate offline benchmark for precomputed 226-feature vectors is also available.
              </p>
            </div>
            <div className="sc-tool-card__footer">
              <button
                type="button"
                className="button button-quiet"
                onClick={() => onNavigate("research", "apk")}
              >
                Analyze an APK <span aria-hidden="true">→</span>
              </button>
            </div>
          </article>
        </div>
      </section>

      {/* Awareness Section Integration */}
      <AwarenessSection />

      {/* Cybercrime Reporting Banner */}
      <section className="reporting-banner" aria-labelledby="dashboard-report-title">
        <div className="report-icon" aria-hidden="true">↗</div>
        <div>
          <p className="eyebrow">NEED TO TAKE ACTION?</p>
          <h2 id="dashboard-report-title">Report cybercrime through official channels</h2>
          <p>SignalCheck is an awareness tool, not a replacement for official support or incident reporting.</p>
        </div>
        <a className="report-link" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">
          Visit National Cyber Crime Portal <span aria-hidden="true">↗</span>
        </a>
      </section>
    </div>
  );
}
