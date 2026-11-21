/**
 * ComponentPreview: An isolated preview gallery for Phase 1 reusable UI components.
 * Only loaded conditionally for manual visual verification and documentation.
 */
import { useState } from "react";
import {
  ScannerCard,
  ModeSelector,
  StatusBanner,
  AnalysisSummaryCard,
  GlobeIcon,
  MessageIcon,
} from "./ui/index.js";

export default function ComponentPreview() {
  const [activeMode, setActiveMode] = useState("web");
  const [showPreview, setShowPreview] = useState(true);

  // Mock structures matching actual API payloads
  const mockWebThreat = {
    classification: "phishing",
    phishing_score: 0.8924,
    threshold: 0.5,
    model_id: "phish-v2-linear-svc",
    disclaimer:
      "This is an uncalibrated statistical model score. A high score indicates statistical similarity to known phishing patterns, not definitive proof of malicious intent.",
  };

  const mockWebClean = {
    classification: "benign",
    phishing_score: 0.1245,
    threshold: 0.5,
    model_id: "phish-v2-linear-svc",
    disclaimer:
      "This is an uncalibrated statistical model score. A low score indicates lack of characteristic phishing markers, not absolute safety.",
  };

  const mockSMSThreat = {
    classification: "smishing",
    smishing_score: 0.9412,
    threshold: 0.5,
    model_id: "SMS-05-C-linear-svc",
    disclaimer:
      "This is an uncalibrated statistical model score from the SMS-05-C model. Evaluate message context carefully.",
  };

  const modes = [
    {
      id: "web",
      label: "Web & Link Scanner",
      icon: GlobeIcon,
      badge: "API v2",
    },
    {
      id: "sms",
      label: "SMS Smishing Scanner",
      icon: MessageIcon,
      badge: "SMS-05-C",
    },
  ];

  if (!showPreview) {
    return (
      <div style={{ textAlign: "center", margin: "24px 0" }}>
        <button
          type="button"
          className="button button-quiet"
          onClick={() => setShowPreview(true)}
          style={{ fontSize: "12px", border: "1px dashed #94a3b8" }}
        >
          View Phase 1 Design System Component Gallery
        </button>
      </div>
    );
  }

  return (
    <section
      style={{
        margin: "32px auto",
        padding: "24px",
        background: "#ffffff",
        border: "2px dashed #0d9488",
        borderRadius: "16px",
        maxWidth: "1000px",
      }}
      aria-labelledby="preview-gallery-heading"
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "20px",
        }}
      >
        <div>
          <span
            style={{
              fontSize: "11px",
              fontWeight: 700,
              color: "#0d9488",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
            }}
          >
            Design System Verification
          </span>
          <h2
            id="preview-gallery-heading"
            style={{ margin: "4px 0 0", fontSize: "20px", color: "#0f172a" }}
          >
            Phase 1 Reusable UI Component Gallery
          </h2>
        </div>
        <button
          type="button"
          className="button button-quiet"
          onClick={() => setShowPreview(false)}
        >
          Close Preview
        </button>
      </div>

      {/* 1. ModeSelector Showcase */}
      <div style={{ marginBottom: "28px" }}>
        <h3 style={{ fontSize: "14px", color: "#475569", marginBottom: "8px" }}>
          1. ModeSelector (Accessible Tabs with WCAG 2.2 Touch Targets)
        </h3>
        <ModeSelector
          modes={modes}
          activeModeId={activeMode}
          onSelectMode={setActiveMode}
        />
      </div>

      {/* 2. StatusBanners Showcase */}
      <div style={{ marginBottom: "28px" }}>
        <h3 style={{ fontSize: "14px", color: "#475569", marginBottom: "8px" }}>
          2. StatusBanner States (Distinct icon, text, and role)
        </h3>
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <StatusBanner variant="info" title="Informational Notice">
            The dedicated SMS-05-C model analyzes both linkless and URL-bearing text messages.
          </StatusBanner>
          <StatusBanner variant="warning" title="Input Length Advisory">
            Input reached 1,445 characters; messages exceeding training length may have less reliable scores.
          </StatusBanner>
          <StatusBanner variant="error" title="Service Connection Error">
            Could not reach the local analysis service. Check that the backend is running.
          </StatusBanner>
          <StatusBanner variant="success" title="Model Loaded">
            The local text classification model is online and ready for requests.
          </StatusBanner>
        </div>
      </div>

      {/* 3. ScannerCard Showcase */}
      <div style={{ marginBottom: "28px" }}>
        <h3 style={{ fontSize: "14px", color: "#475569", marginBottom: "8px" }}>
          3. ScannerCard Layout Example
        </h3>
        <ScannerCard
          id="preview-scanner"
          eyebrow="PREVIEW COMPONENT"
          title="Web & Link Analysis Card"
          description="Evaluate suspected phishing emails and deceptive links using the saved ML model."
          icon={GlobeIcon}
        >
          <p style={{ margin: 0, fontSize: "14px", color: "#64748b" }}>
            The ScannerCard acts as the uniform container for input forms, metadata limits, and action bars across all scanning modules.
          </p>
        </ScannerCard>
      </div>

      {/* 4. AnalysisSummaryCard Showcase */}
      <div>
        <h3 style={{ fontSize: "14px", color: "#475569", marginBottom: "8px" }}>
          4. AnalysisSummaryCard (Threat vs. Clean with Technical Score Accordion)
        </h3>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <AnalysisSummaryCard
            id="summary-phish-threat"
            result={mockWebThreat}
            analyzerType="web"
          />
          <AnalysisSummaryCard
            id="summary-phish-clean"
            result={mockWebClean}
            analyzerType="web"
          />
          <AnalysisSummaryCard
            id="summary-sms-threat"
            result={mockSMSThreat}
            analyzerType="sms"
          />
        </div>
      </div>
    </section>
  );
}
