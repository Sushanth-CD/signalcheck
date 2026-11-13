import { useState } from "react";
import AndroidFeatureAnalysis from "./AndroidFeatureAnalysis.jsx";
import APKStaticAnalysis from "./APKStaticAnalysis.jsx";
import StatusBanner from "./ui/StatusBanner.jsx";
import { FileTextIcon, SlidersIcon } from "./ui/Icons.jsx";

export default function ResearchToolsSection() {
  const [activeTab, setActiveTab] = useState("apk"); // 'apk' | 'vectors'

  return (
    <div className="sc-research-tools-view">
      <header className="sc-view-header">
        <span className="sc-view-header__eyebrow">EXPERIMENTAL / RESEARCH LAB</span>
        <h1 className="sc-view-header__title">Android Security Research Lab</h1>
        <p className="sc-view-header__description">
          Diagnostic tools for evaluating Android application packages (.apk) through static container analysis, alongside offline precomputed feature vector benchmarking.
        </p>

        {/* Tab Switcher */}
        <div className="sc-mode-selector" role="tablist" aria-label="Research Tool Selection" style={{ marginTop: "1.25rem" }}>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "apk"}
            className={`sc-mode-tab ${activeTab === "apk" ? "sc-mode-tab--active" : ""}`}
            onClick={() => setActiveTab("apk")}
          >
            <FileTextIcon size={16} />
            <span>APK Static Analysis</span>
            <span className="sc-mode-tab__badge">Live Static Parser</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "vectors"}
            className={`sc-mode-tab ${activeTab === "vectors" ? "sc-mode-tab--active" : ""}`}
            onClick={() => setActiveTab("vectors")}
          >
            <SlidersIcon size={16} />
            <span>226-Feature Vector Benchmark</span>
            <span className="sc-mode-tab__badge">Offline ML Research</span>
          </button>
        </div>
      </header>

      {activeTab === "apk" ? (
        <APKStaticAnalysis />
      ) : (
        <>
          {/* Mandatory Scope & Limitation Banner for 226-feature prototype */}
          <StatusBanner
            variant="warning"
            title="Precomputed Feature Vectors Only — Experimental Prototype"
          >
            This diagnostic tool analyzes precomputed 226-dimensional Android feature vectors.
            Models evaluated in this workspace represent experimental research baselines and are not intended as standalone production malware verdicts.
          </StatusBanner>

          <AndroidFeatureAnalysis />
        </>
      )}
    </div>
  );
}
