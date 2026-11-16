import { useState } from "react";
import Dashboard from "./components/Dashboard.jsx";
import ScannerWorkspace from "./components/ScannerWorkspace.jsx";
import ResearchToolsSection from "./components/ResearchToolsSection.jsx";
import AboutSafetySection from "./components/AboutSafetySection.jsx";

export default function App() {
  // Navigation states: 'dashboard' | 'scanners' | 'research' | 'about'
  const [currentNav, setCurrentNav] = useState("dashboard");
  const [activeScannerMode, setActiveScannerMode] = useState("web");
  const [researchInitialTab, setResearchInitialTab] = useState("apk");

  function handleNavigate(target, subMode) {
    setCurrentNav(target);
    if (target === "scanners" && subMode) {
      setActiveScannerMode(subMode);
    } else if (target === "research") {
      setResearchInitialTab(subMode || "apk");
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  return (
    <div className="app-shell">
      {/* Primary SaaS Navigation Header */}
      <header className="sc-navbar">
        <a
          className="brand"
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            handleNavigate("dashboard");
          }}
          aria-label="SignalCheck home"
        >
          <span className="brand-mark" aria-hidden="true"><span /></span>
          <span>Signal<span className="brand-light">Check</span></span>
        </a>

        <nav className="sc-navbar__nav" aria-label="Main Navigation">
          <button
            type="button"
            className={`sc-nav-btn ${currentNav === "dashboard" ? "sc-nav-btn--active" : ""}`}
            onClick={() => handleNavigate("dashboard")}
          >
            Dashboard
          </button>
          <button
            type="button"
            className={`sc-nav-btn ${currentNav === "scanners" ? "sc-nav-btn--active" : ""}`}
            onClick={() => handleNavigate("scanners")}
          >
            Scanners
          </button>
          <button
            type="button"
            className={`sc-nav-btn ${currentNav === "research" ? "sc-nav-btn--active" : ""}`}
            onClick={() => handleNavigate("research")}
          >
            Research Lab
          </button>
          <button
            type="button"
            className={`sc-nav-btn ${currentNav === "about" ? "sc-nav-btn--active" : ""}`}
            onClick={() => handleNavigate("about")}
          >
            About &amp; Safety
          </button>
        </nav>
      </header>

      {/* Main Content Workspace Router */}
      <main id="top">
        {currentNav === "dashboard" && (
          <Dashboard onNavigate={handleNavigate} />
        )}

        {currentNav === "scanners" && (
          <ScannerWorkspace
            activeMode={activeScannerMode}
            onModeChange={setActiveScannerMode}
          />
        )}

        {currentNav === "research" && (
          <ResearchToolsSection initialTab={researchInitialTab} />
        )}

        {currentNav === "about" && (
          <AboutSafetySection />
        )}
      </main>

      {/* Global Application Footer */}
      <footer className="site-footer">
        <a
          className="brand footer-brand"
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            handleNavigate("dashboard");
          }}
        >
          <span className="brand-mark" aria-hidden="true"><span /></span>
          <span>Signal<span className="brand-light">Check</span></span>
        </a>
        <p>Clearer signals. Safer choices. Privacy-first local evaluation.</p>
        <span>Model guidance · No guarantee of safety</span>
      </footer>
    </div>
  );
}
