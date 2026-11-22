import { useState } from "react";
import ModeSelector from "./ui/ModeSelector.jsx";
import { GlobeIcon, MessageIcon } from "./ui/Icons.jsx";
import WebPhishingAnalysis from "./WebPhishingAnalysis.jsx";
import SMSAnalysis from "./SMSAnalysis.jsx";

export default function ScannerWorkspace({
  activeMode = "web",
  onModeChange,
}) {
  const [internalMode, setInternalMode] = useState(activeMode);
  const currentMode = onModeChange ? activeMode : internalMode;

  function handleSelectMode(modeId) {
    if (onModeChange) {
      onModeChange(modeId);
    } else {
      setInternalMode(modeId);
    }
  }

  const scannerModes = [
    {
      id: "web",
      label: "Web & Link Scanner",
      icon: GlobeIcon,
      badge: "Phish v2",
    },
    {
      id: "sms",
      label: "SMS Smishing Scanner",
      icon: MessageIcon,
      badge: "SMS-05-C",
    },
  ];

  return (
    <div className="sc-scanner-workspace">
      {/* Workspace Header & Segmented Controller */}
      <div className="sc-workspace-header">
        <div className="sc-workspace-header__title-group">
          <span className="sc-workspace-header__eyebrow">FOCUSED SCANNER WORKSPACE</span>
          <h1 className="sc-workspace-header__title">
            {currentMode === "web" ? "Web & Link Threat Analysis" : "SMS Smishing Message Analysis"}
          </h1>
          <p className="sc-workspace-header__description">
            {currentMode === "web"
              ? "Evaluate suspicious URLs, email bodies, and online messages using the saved text classification model."
              : "Analyze short mobile messages and fraud alerts using the linkless-aware SMS-05-C model."}
          </p>
        </div>

        <div className="sc-workspace-header__controls">
          <ModeSelector
            modes={scannerModes}
            activeModeId={currentMode}
            onSelectMode={handleSelectMode}
            ariaLabel="Scanner Modes"
          />
        </div>
      </div>

      {/* Focused Active Scanner Pane */}
      <div
        id={`panel-${currentMode}`}
        role="tabpanel"
        aria-labelledby={`tab-${currentMode}`}
        className="sc-workspace-panel"
      >
        {currentMode === "web" ? (
          <WebPhishingAnalysis />
        ) : (
          <SMSAnalysis />
        )}
      </div>
    </div>
  );
}
