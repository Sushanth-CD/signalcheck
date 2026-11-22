/**
 * ScannerCard: Standardized outer container for threat scanners.
 * Provides unified title, description, mode icon, and optional status badge.
 */
export default function ScannerCard({
  id,
  title,
  description,
  eyebrow,
  icon: Icon,
  badge,
  children,
  className = "",
  footer,
}) {
  return (
    <section
      id={id}
      className={`sc-scanner-card ${className}`}
      aria-labelledby={title ? `${id}-title` : undefined}
    >
      <header className="sc-scanner-card__header">
        {Icon && (
          <div className="sc-scanner-card__icon-wrap">
            <Icon size={20} className="sc-scanner-card__icon" />
          </div>
        )}
        <div className="sc-scanner-card__title-group">
          {eyebrow && <span className="sc-scanner-card__eyebrow">{eyebrow}</span>}
          {title && (
            <h2 id={`${id}-title`} className="sc-scanner-card__title">
              {title}
            </h2>
          )}
          {description && (
            <p className="sc-scanner-card__description">{description}</p>
          )}
        </div>
        {badge && <div className="sc-scanner-card__badge-wrap">{badge}</div>}
      </header>

      <div className="sc-scanner-card__body">{children}</div>

      {footer && <footer className="sc-scanner-card__footer">{footer}</footer>}
    </section>
  );
}
