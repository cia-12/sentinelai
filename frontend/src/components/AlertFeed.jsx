import { useEffect, useRef } from "react";

const SEVERITY_CONFIG = {
  Critical: { color: "#EF4444", bg: "#EF444415", label: "CRIT" },
  High:     { color: "#F59E0B", bg: "#F59E0B15", label: "HIGH" },
  Medium:   { color: "#7C3AED", bg: "#7C3AED15", label: "MED"  },
  Low:      { color: "#10B981", bg: "#10B98115", label: "LOW"  },
};

const THREAT_ICONS = {
  brute_force:       "🔐",
  c2_beacon:         "📡",
  lateral_movement:  "🔀",
  data_exfil:        "📤",
};

const THREAT_LABELS = {
  brute_force:       "Brute Force",
  c2_beacon:         "C2 Beacon",
  lateral_movement:  "Lateral Movement",
  data_exfil:        "Data Exfil",
};

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString("en-GB", {hour12: false});
  } catch { return "--:--:--"; }
}

function ShapBar({ features }) {
  if (!features?.length) return null;
  const top = features.slice(0, 3);
  return (
    <div className="shap-mini">
      {top.map((f, i) => (
        <div key={i} className="shap-row">
          <span className="shap-label">{f.feature.replace(/_/g," ")}</span>
          <div className="shap-track">
            <div className="shap-fill" style={{width: `${f.weight*100}%`}} />
          </div>
          <span className="shap-val">{(f.weight*100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

export default function AlertFeed({ alerts, selected, onSelect }) {
  const topRef = useRef(null);

  // Scroll to top on new alert
  useEffect(() => {
    topRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [alerts.length]);

  if (!alerts.length) {
    return (
      <div className="feed-empty">
        <div className="feed-empty-icon">🛡</div>
        <div>Monitoring active — no threats detected yet</div>
        <div className="feed-empty-sub">Events are being analyzed in real time</div>
      </div>
    );
  }

  return (
    <div className="feed">
      <div ref={topRef} />
      {alerts.map((alert, idx) => {
        const sev = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Low;
        const isSelected = selected?.alert_id === alert.alert_id;
        const isFP = alert.false_positive_score > 0.6;

        return (
          <div
            key={alert.alert_id}
            className={`alert-card ${isSelected ? "selected" : ""} ${idx === 0 ? "new" : ""}`}
            style={{ borderLeftColor: sev.color }}
            onClick={() => onSelect(isSelected ? null : alert)}
          >
            <div className="alert-card-top">
              <div className="alert-type">
                <span className="alert-icon">{THREAT_ICONS[alert.threat_type] || "⚠"}</span>
                <span className="alert-type-label">{THREAT_LABELS[alert.threat_type] || alert.threat_type}</span>
                {isFP && <span className="fp-badge">⚠ Likely FP</span>}
              </div>
              <div className="alert-meta">
                <span className="severity-badge" style={{color: sev.color, background: sev.bg}}>
                  {sev.label}
                </span>
                <span className="confidence-badge">
                  {(alert.confidence * 100).toFixed(0)}%
                </span>
                <span className="alert-time">{formatTime(alert.ts)}</span>
              </div>
            </div>

            <div className="alert-title">{alert.title}</div>
            <div className="alert-ips">
              <span className="ip src">{alert.src_ip}</span>
              <span className="ip-arrow">→</span>
              <span className="ip dst">{alert.dst_ip}</span>
            </div>

            <div className="alert-mitre">
              <span className="mitre-badge">{alert.mitre_id}</span>
              <span className="mitre-name">{alert.mitre_name}</span>
            </div>

            {isSelected && <ShapBar features={alert.shap_features} />}

            <div className="alert-id">{alert.alert_id}</div>
          </div>
        );
      })}
    </div>
  );
}
