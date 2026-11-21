/**
 * StatusBanner: Accessible, multi-state notification banner for SignalCheck.
 * Variants: 'info' | 'warning' | 'error' | 'success'
 * Communicates status independently through text, icon, and semantic HTML (WCAG 2.2 AA).
 */
import { InfoIcon, AlertTriangleIcon, ShieldAlertIcon, CheckCircleIcon } from "./Icons.jsx";

const BANNER_CONFIG = {
  info: {
    icon: InfoIcon,
    ariaRole: "status",
    defaultTitle: "Information",
  },
  warning: {
    icon: AlertTriangleIcon,
    ariaRole: "status",
    defaultTitle: "Warning",
  },
  error: {
    icon: ShieldAlertIcon,
    ariaRole: "alert",
    defaultTitle: "Error",
  },
  success: {
    icon: CheckCircleIcon,
    ariaRole: "status",
    defaultTitle: "Success",
  },
};

export default function StatusBanner({
  variant = "info",
  title,
  children,
  className = "",
  id,
}) {
  const config = BANNER_CONFIG[variant] || BANNER_CONFIG.info;
  const IconComponent = config.icon;

  return (
    <div
      id={id}
      className={`sc-status-banner sc-status-banner--${variant} ${className}`}
      role={config.ariaRole}
    >
      <div className="sc-status-banner__icon-wrap">
        <IconComponent className="sc-status-banner__icon" size={18} />
      </div>
      <div className="sc-status-banner__content">
        {title && <strong className="sc-status-banner__title">{title}</strong>}
        <div className="sc-status-banner__message">{children}</div>
      </div>
    </div>
  );
}
