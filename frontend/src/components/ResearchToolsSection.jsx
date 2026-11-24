import AndroidFeatureAnalysis from "./AndroidFeatureAnalysis.jsx";

export default function ResearchToolsSection() {
  return (
    <div className="sc-research-tools-view">
      <header className="sc-view-header">
        <span className="sc-view-header__eyebrow">EXPERIMENTAL / RESEARCH LAB</span>
        <h1 className="sc-view-header__title">Android Security Research Lab</h1>
        <p className="sc-view-header__description">
          Dedicated research workspace for evaluating precomputed Android permission and feature vectors using the legacy Random Forest benchmark model.
        </p>
      </header>

      <AndroidFeatureAnalysis />
    </div>
  );
}
