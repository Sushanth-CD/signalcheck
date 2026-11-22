/**
 * ModeSelector: Accessible segmented tab bar to switch between analysis modes.
 * Complies with WAI-ARIA 1.2 Tabs design pattern.
 * Supports arrow key navigation (ArrowLeft, ArrowRight, Home, End).
 */
import { useRef } from "react";

export default function ModeSelector({
  modes = [],
  activeModeId,
  onSelectMode,
  className = "",
  ariaLabel = "Threat Analysis Modes",
}) {
  const tabsRef = useRef([]);

  function handleKeyDown(event, index) {
    const count = modes.length;
    if (count === 0) return;

    let nextIndex = null;
    if (event.key === "ArrowRight") {
      nextIndex = (index + 1) % count;
    } else if (event.key === "ArrowLeft") {
      nextIndex = (index - 1 + count) % count;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = count - 1;
    }

    if (nextIndex !== null) {
      event.preventDefault();
      const nextMode = modes[nextIndex];
      if (nextMode && !nextMode.disabled) {
        onSelectMode(nextMode.id);
        tabsRef.current[nextIndex]?.focus();
      }
    }
  }

  return (
    <div
      className={`sc-mode-selector ${className}`}
      role="tablist"
      aria-label={ariaLabel}
    >
      {modes.map((mode, index) => {
        const isSelected = mode.id === activeModeId;
        const Icon = mode.icon;

        return (
          <button
            key={mode.id}
            ref={(el) => (tabsRef.current[index] = el)}
            role="tab"
            id={`tab-${mode.id}`}
            aria-selected={isSelected}
            aria-controls={`panel-${mode.id}`}
            tabIndex={isSelected ? 0 : -1}
            disabled={mode.disabled}
            className={`sc-mode-selector__tab ${
              isSelected ? "sc-mode-selector__tab--active" : ""
            } ${mode.disabled ? "sc-mode-selector__tab--disabled" : ""}`}
            onClick={() => onSelectMode(mode.id)}
            onKeyDown={(e) => handleKeyDown(e, index)}
            type="button"
          >
            {Icon && (
              <span className="sc-mode-selector__icon-wrap">
                <Icon size={16} />
              </span>
            )}
            <span className="sc-mode-selector__label">{mode.label}</span>
            {mode.badge && (
              <span className="sc-mode-selector__badge">{mode.badge}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
