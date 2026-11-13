import { useState, useRef, useEffect } from "react";
import {
  analyzeAPK,
  fetchAPKHistory,
  fetchAPKReportJson,
  getAPKReportPdfUrl,
} from "../api/analyze.js";
import {
  FileTextIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  AlertTriangleIcon,
  InfoIcon,
  ChevronDownIcon,
  ChevronUpIcon,
} from "./ui/Icons.jsx";

const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

export default function APKStaticAnalysis() {
  const [file, setFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [copiedSha, setCopiedSha] = useState(false);
  const [expandedSection, setExpandedSection] = useState(null);

  // History & Export States
  const [historyItems, setHistoryItems] = useState([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [isHistoryOpen, setIsHistoryOpen] = useState(true);

  const fileInputRef = useRef(null);
  const abortControllerRef = useRef(null);

  async function loadHistory() {
    setIsHistoryLoading(true);
    setHistoryError("");
    try {
      const data = await fetchAPKHistory(20, 0);
      setHistoryItems(data.items || []);
    } catch (err) {
      setHistoryError(err instanceof Error ? err.message : "Failed to load history.");
    } finally {
      setIsHistoryLoading(false);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  function handleFileSelected(selectedFile) {
    if (!selectedFile) return;

    if (!selectedFile.name.toLowerCase().endsWith(".apk")) {
      setError("Please select a valid Android package file (.apk).");
      setFile(null);
      setResult(null);
      return;
    }

    if (selectedFile.size > MAX_FILE_SIZE) {
      setError(`File size (${(selectedFile.size / (1024 * 1024)).toFixed(1)} MB) exceeds the 25 MB upload limit.`);
      setFile(null);
      setResult(null);
      return;
    }

    setError("");
    setResult(null);
    setFile(selectedFile);
  }

  function handleDragOver(e) {
    e.preventDefault();
    setIsDragging(true);
  }

  function handleDragLeave(e) {
    e.preventDefault();
    setIsDragging(false);
  }

  function handleDrop(e) {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (!file || isLoading) return;

    setIsLoading(true);
    setError("");
    setResult(null);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const response = await analyzeAPK(file, null, controller.signal);
      setResult(response);
      // Reload history to show the newly saved record
      loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze APK.");
    } finally {
      setIsLoading(false);
      abortControllerRef.current = null;
    }
  }

  function handleCancel() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setIsLoading(false);
  }

  function handleReset() {
    handleCancel();
    setFile(null);
    setResult(null);
    setError("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }

  async function handleLoadHistoryItem(recordId) {
    setIsLoading(true);
    setError("");
    try {
      const fullReport = await fetchAPKReportJson(recordId);
      setResult(fullReport);
      window.scrollTo({ top: 300, behavior: "smooth" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load historical report.");
    } finally {
      setIsLoading(false);
    }
  }

  function copySha256() {
    if (!result?.sha256) return;
    navigator.clipboard.writeText(result.sha256).then(() => {
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    });
  }

  const indicatorLevelLabels = {
    no_notable_indicators: {
      title: "No Characteristic Threat Indicators Detected",
      variant: "clean",
      badge: "No Notable Indicators",
      icon: ShieldCheckIcon,
      desc: "Static review of package metadata, permissions, and bytecode did not uncover typical high-risk indicators or known trojan patterns.",
    },
    some_indicators: {
      title: "Some Suspicious Indicators Flagged",
      variant: "warning",
      badge: "Moderate Indicators",
      icon: AlertTriangleIcon,
      desc: "Static inspection flagged sensitive permissions or structural patterns that warrant caution and closer inspection.",
    },
    many_indicators: {
      title: "Multiple High-Risk Indicators Flagged",
      variant: "threat",
      badge: "Elevated Risk Indicators",
      icon: ShieldAlertIcon,
      desc: "Static analysis detected multiple high-risk combinations (such as SMS interception, overlay handling, or unsigned binaries).",
    },
  };

  const levelInfo = result ? indicatorLevelLabels[result.indicator_level] : null;

  return (
    <section className="sc-apk-analysis-container" aria-labelledby="apk-static-heading">
      <div className="analyzer-intro">
        <div className="step-icon" aria-hidden="true">APK</div>
        <div>
          <p className="eyebrow">STATIC PACKAGE INSPECTION (RESEARCH LAB)</p>
          <h2 id="apk-static-heading">Android APK Static Analysis</h2>
          <p>
            Upload an Android package file (.apk) for safe, server-side static structural and bytecode analysis.
          </p>
        </div>
      </div>

      <div className="sc-privacy-notice-banner" role="note">
        <InfoIcon size={18} />
        <span>
          <strong>Ephemeral Safety Guarantee:</strong> The uploaded package is inspected statically inside a restricted container, is <strong>never installed or executed</strong>, and is <strong>deleted immediately</strong> upon completion.
        </span>
      </div>

      <form onSubmit={handleSubmit} className="sc-apk-upload-form">
        <div
          className={`sc-dropzone ${isDragging ? "sc-dropzone--active" : ""} ${file ? "sc-dropzone--has-file" : ""}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !file && fileInputRef.current?.click()}
          role="region"
          aria-label="APK file dropzone"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              if (!file) fileInputRef.current?.click();
            }
          }}
        >
          <input
            type="file"
            ref={fileInputRef}
            accept=".apk,application/vnd.android.package-archive"
            style={{ display: "none" }}
            onChange={(e) => handleFileSelected(e.target.files?.[0])}
            aria-label="Upload APK file"
          />

          {!file ? (
            <div className="sc-dropzone__prompt">
              <FileTextIcon size={40} className="sc-dropzone__icon" />
              <p className="sc-dropzone__title">Drag and drop an .apk package here, or click to browse</p>
              <span className="sc-dropzone__hint">Maximum file size: 25 MB</span>
            </div>
          ) : (
            <div className="sc-dropzone__file-info">
              <FileTextIcon size={32} className="sc-dropzone__icon" />
              <div>
                <strong>{file.name}</strong>
                <span>{(file.size / (1024 * 1024)).toFixed(2)} MB</span>
              </div>
              <button
                type="button"
                className="button button-quiet sc-dropzone__remove-btn"
                onClick={(e) => {
                  e.stopPropagation();
                  handleReset();
                }}
                disabled={isLoading}
              >
                Change File
              </button>
            </div>
          )}
        </div>

        <div className="form-actions" style={{ marginTop: "1rem" }}>
          <button
            className="button button-primary"
            type="submit"
            disabled={!file || isLoading}
          >
            {isLoading ? "Analyzing APK…" : "Start Static Analysis →"}
          </button>
          {isLoading && (
            <button
              className="button button-quiet"
              type="button"
              onClick={handleCancel}
            >
              Cancel
            </button>
          )}
          {file && !isLoading && (
            <button
              className="button button-quiet"
              type="button"
              onClick={handleReset}
            >
              Clear
            </button>
          )}
        </div>
      </form>

      {/* ARIA Live Status Region */}
      <div aria-live="polite" className="sr-only">
        {isLoading && "Static APK analysis in progress. Please wait."}
        {error && `Error: ${error}`}
        {result && `Analysis completed. Indicator level: ${result.indicator_level}`}
      </div>

      {error && (
        <div className="error-banner" role="alert" style={{ marginTop: "1.5rem" }}>
          <span className="error-symbol" aria-hidden="true">!</span>
          <div>
            <strong>Analysis Failed</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* Result Display */}
      {result && (
        <div className="sc-apk-results" id="apk-analysis-result">
          {/* Header Summary Card */}
          <section
            className={`sc-analysis-summary sc-analysis-summary--${levelInfo.variant}`}
            aria-labelledby="apk-verdict-title"
          >
            <div className="sc-analysis-summary__header">
              <div className="sc-analysis-summary__badge-group">
                <span className={`sc-verdict-badge sc-verdict-badge--${levelInfo.variant}`} role="status">
                  <levelInfo.icon size={16} className="sc-verdict-badge__icon" />
                  <span>{levelInfo.badge}</span>
                </span>
                <span className="sc-analysis-summary__eyebrow">APK-STATIC-V1 HEURISTICS</span>
              </div>
              <h3 id="apk-verdict-title" className="sc-analysis-summary__title">
                {levelInfo.title}
              </h3>
              <p className="sc-analysis-summary__desc">{levelInfo.desc}</p>
            </div>

            {/* SHA-256, App Meta, and PDF Download Button */}
            <div className="sc-apk-meta-grid">
              <div className="sc-apk-meta-item">
                <span className="sc-apk-meta-label">SHA-256 Fingerprint:</span>
                <div className="sc-apk-sha-box">
                  <code>{result.sha256}</code>
                  <button
                    type="button"
                    className="button button-quiet sc-copy-btn"
                    onClick={copySha256}
                    aria-label="Copy SHA-256 fingerprint"
                  >
                    {copiedSha ? "Copied!" : "Copy"}
                  </button>

                  {/* Download PDF Report Button */}
                  {result.id && (
                    <a
                      href={getAPKReportPdfUrl(result.id)}
                      download={`signalcheck-report-${result.app.package_name || "apk"}.pdf`}
                      className="button button-primary sc-download-pdf-btn"
                      style={{ marginLeft: "auto", textDecoration: "none" }}
                    >
                      Download PDF Report ↓
                    </a>
                  )}
                </div>
              </div>

              <div className="sc-apk-grid-cols">
                <div>
                  <span className="sc-apk-meta-label">Package Name:</span>
                  <strong>{result.app.package_name || "Unknown"}</strong>
                </div>
                <div>
                  <span className="sc-apk-meta-label">Version:</span>
                  <span>{result.app.version_name || "N/A"} (code {result.app.version_code || "N/A"})</span>
                </div>
                <div>
                  <span className="sc-apk-meta-label">SDK Compatibility:</span>
                  <span>Min: {result.app.min_sdk || "N/A"} | Target: {result.app.target_sdk || "N/A"}</span>
                </div>
                <div>
                  <span className="sc-apk-meta-label">Archive Size:</span>
                  <span>{(result.file_size / (1024 * 1024)).toFixed(2)} MB</span>
                </div>
              </div>
            </div>
          </section>

          {/* Security Findings Table / Cards */}
          <section className="sc-apk-section" aria-labelledby="findings-title">
            <h3 id="findings-title" className="sc-section-title">
              Static Security Findings ({result.findings.length})
            </h3>
            {result.findings.length === 0 ? (
              <p className="sc-empty-state">No specific high-severity heuristic rules triggered.</p>
            ) : (
              <div className="sc-findings-list">
                {result.findings.map((f) => (
                  <div key={f.id} className={`sc-finding-card sc-finding-card--${f.severity}`}>
                    <div className="sc-finding-card__header">
                      <span className={`sc-severity-pill sc-severity-pill--${f.severity}`}>
                        {f.severity.toUpperCase()}
                      </span>
                      <span className="sc-finding-card__category">{f.category}</span>
                      <h4 className="sc-finding-card__title">{f.title}</h4>
                    </div>
                    <div className="sc-finding-card__body">
                      <p><strong>Evidence:</strong> <code>{f.evidence}</code></p>
                      <p><strong>Why It Matters:</strong> {f.why_it_matters}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Grouped Permissions */}
          <section className="sc-apk-section" aria-labelledby="permissions-title">
            <h3 id="permissions-title" className="sc-section-title">
              Declared Permissions ({result.permissions.all_declared.length})
            </h3>
            <div className="sc-permission-groups-grid">
              {Object.entries(result.permissions)
                .filter(([k, list]) => k !== "all_declared" && list.length > 0)
                .map(([category, list]) => (
                  <div key={category} className="sc-perm-card">
                    <h4>{category.replace("_", " ").toUpperCase()} ({list.length})</h4>
                    <ul>
                      {list.map((p) => (
                        <li key={p}><code>{p.replace("android.permission.", "")}</code></li>
                      ))}
                    </ul>
                  </div>
                ))}
            </div>
          </section>

          {/* Signing & Certificate Facts */}
          <section className="sc-apk-section" aria-labelledby="signing-title">
            <h3 id="signing-title" className="sc-section-title">Cryptographic Signature Facts</h3>
            <div className="sc-signing-box">
              <p><strong>Signed:</strong> {result.signing.is_signed ? "Yes" : "No (Unsigned archive)"}</p>
              {result.signing.signature_schemes.length > 0 && (
                <p><strong>Schemes:</strong> {result.signing.signature_schemes.join(", ")}</p>
              )}
              <p><strong>Debug Certificate:</strong> {result.signing.is_debug_signed ? "Yes (Flagged)" : "No"}</p>
              <p><strong>Self-Signed:</strong> {result.signing.is_self_signed ? "Yes" : "No"}</p>

              {result.signing.certificates.map((c, idx) => (
                <div key={idx} className="sc-cert-details">
                  <p><strong>Subject:</strong> <code>{c.subject || "N/A"}</code></p>
                  <p><strong>Issuer:</strong> <code>{c.issuer || "N/A"}</code></p>
                  <p><strong>Validity:</strong> {c.valid_from} to {c.valid_to}</p>
                  <p><strong>Fingerprint:</strong> <code>{c.sha256_fingerprint}</code></p>
                </div>
              ))}
            </div>
          </section>

          {/* Collapsible Technical Bytecode Details */}
          <section className="sc-apk-section">
            <button
              type="button"
              className="sc-collapse-trigger"
              onClick={() => setExpandedSection(expandedSection === "tech" ? null : "tech")}
              aria-expanded={expandedSection === "tech"}
            >
              <span>Technical Bytecode Indicators</span>
              {expandedSection === "tech" ? <ChevronUpIcon size={18} /> : <ChevronDownIcon size={18} />}
            </button>

            {expandedSection === "tech" && (
              <div className="sc-collapsed-panel">
                <dl className="sc-tech-dl">
                  <div>
                    <dt>Dynamic Code Loading:</dt>
                    <dd>{result.code_indicators.dynamic_code_loading ? "Observed" : "Not observed"}</dd>
                  </div>
                  <div>
                    <dt>Reflection API Usage:</dt>
                    <dd>{result.code_indicators.reflection_use ? "Observed" : "Not observed"}</dd>
                  </div>
                  <div>
                    <dt>Runtime.exec / Shell:</dt>
                    <dd>{result.code_indicators.runtime_exec ? "Observed" : "Not observed"}</dd>
                  </div>
                  <div>
                    <dt>Telephony / SMS Send APIs:</dt>
                    <dd>{result.code_indicators.sms_send_apis ? "Observed" : "Not observed"}</dd>
                  </div>
                  <div>
                    <dt>Accessibility Event Handling:</dt>
                    <dd>{result.code_indicators.accessibility_event_handling ? "Observed" : "Not observed"}</dd>
                  </div>
                  <div>
                    <dt>Native Libraries (.so):</dt>
                    <dd>{result.code_indicators.native_library_presence ? "Present" : "None"}</dd>
                  </div>
                  <div>
                    <dt>Short Name Obfuscation Ratio:</dt>
                    <dd>{(result.code_indicators.obfuscation_name_ratio_hint * 100).toFixed(1)}%</dd>
                  </div>
                </dl>

                {result.code_indicators.discovered_urls.length > 0 && (
                  <div style={{ marginTop: "1rem" }}>
                    <h4>Extracted URLs &amp; IP Endpoints (First {result.code_indicators.discovered_urls.length}):</h4>
                    <ul className="sc-url-list">
                      {result.code_indicators.discovered_urls.map((u, idx) => (
                        <li key={idx}><code>{u}</code></li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Mandatory Permanent Static Limitations Section */}
          <section className="sc-limitations-panel" aria-labelledby="limitations-heading">
            <div className="sc-limitations-header">
              <ShieldCheckIcon size={20} />
              <h4 id="limitations-heading">Scientific Scope &amp; Static Limitations</h4>
            </div>
            <ul className="sc-limitations-list">
              {result.limitations.map((lim, idx) => (
                <li key={idx}>{lim}</li>
              ))}
            </ul>
          </section>
        </div>
      )}

      {/* Historical Analyses Panel */}
      <section className="sc-apk-section sc-apk-history-section" aria-labelledby="history-heading" style={{ marginTop: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h3 id="history-heading" className="sc-section-title" style={{ margin: 0 }}>
            Recent Static Analyses ({historyItems.length})
          </h3>
          <button
            type="button"
            className="button button-quiet"
            onClick={loadHistory}
            disabled={isHistoryLoading}
            style={{ fontSize: "var(--sc-text-xs)" }}
          >
            {isHistoryLoading ? "Refreshing…" : "Refresh History"}
          </button>
        </div>

        {historyError && (
          <p className="sc-history-error" style={{ color: "var(--sc-color-danger-600)", fontSize: "var(--sc-text-xs)" }}>
            {historyError}
          </p>
        )}

        {isHistoryLoading && historyItems.length === 0 ? (
          <p className="sc-empty-state">Loading analysis history…</p>
        ) : historyItems.length === 0 ? (
          <p className="sc-empty-state">No previous static APK analyses found on this server.</p>
        ) : (
          <div className="sc-history-list" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {historyItems.map((item) => (
              <div
                key={item.id}
                className="sc-history-item"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "0.75rem 1rem",
                  backgroundColor: "var(--sc-surface-subtle)",
                  border: "1px solid var(--sc-border-subtle)",
                  borderRadius: "var(--sc-radius-md)",
                  gap: "1rem",
                  flexWrap: "wrap",
                }}
              >
                <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", minWidth: "200px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <strong>{item.package_name || "Unknown Package"}</strong>
                    <span className={`sc-severity-pill sc-severity-pill--${item.indicator_level === "many_indicators" ? "high" : item.indicator_level === "some_indicators" ? "medium" : "low"}`}>
                      {item.indicator_level.replace("_", " ")}
                    </span>
                  </div>
                  <span style={{ fontSize: "var(--sc-text-xs)", color: "var(--sc-text-muted)" }}>
                    SHA-256: <code>{item.sha256.slice(0, 16)}…</code> | {(item.file_size / (1024 * 1024)).toFixed(2)} MB
                  </span>
                  <span style={{ fontSize: "0.7rem", color: "var(--sc-text-muted)" }}>
                    {item.created_at ? new Date(item.created_at).toLocaleString() : ""}
                  </span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginLeft: "auto" }}>
                  <button
                    type="button"
                    className="button button-quiet"
                    onClick={() => handleLoadHistoryItem(item.id)}
                    style={{ fontSize: "var(--sc-text-xs)" }}
                  >
                    View Report
                  </button>
                  <a
                    href={getAPKReportPdfUrl(item.id)}
                    download={`signalcheck-report-${item.package_name || "apk"}-${item.sha256.slice(0, 8)}.pdf`}
                    className="button button-quiet"
                    style={{ fontSize: "var(--sc-text-xs)", textDecoration: "none" }}
                  >
                    PDF ↓
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </section>
  );
}
