import { useState, useEffect } from "react";
import { buildApiHeaders } from "../api";

const PHASE_COLORS = {
  CONTAIN:     "#EF4444",
  INVESTIGATE: "#F59E0B",
  ERADICATE:   "#7C3AED",
  PREVENT:     "#10B981",
};

const FP_LABEL = (score) => {
  if (score > 0.7) return { text: "HIGH — Likely False Positive", color: "#10B981" };
  if (score > 0.4) return { text: "MEDIUM — Review Recommended", color: "#F59E0B" };
  return { text: "LOW — Confirmed Threat", color: "#EF4444" };
};

function ShapChart({ features }) {
  if (!features?.length) return null;
  return (
    <div className="shap-chart">
      <div className="section-label">SHAP Feature Importance</div>
      {features.map((f, i) => (
        <div key={i} className="shap-full-row">
          <div className="shap-full-header">
            <span className="shap-feat">{f.feature.replace(/_/g, " ")}</span>
            <span className="shap-pct" style={{ color: "#00D4FF" }}>
              {(f.weight * 100).toFixed(0)}%
            </span>
          </div>
          <div className="shap-full-track">
            <div
              className="shap-full-fill"
              style={{ width: `${f.weight * 100}%`, opacity: 0.8 + i * -0.1 }}
            />
          </div>
          <div className="shap-explanation">{f.explanation}</div>
        </div>
      ))}
    </div>
  );
}

function PlaybookPanel({ playbook }) {
  if (!playbook?.steps) return null;
  return (
    <div className="playbook">
      <div className="section-label">Auto-Generated Prevention Playbook</div>
      <div className="playbook-meta">
        <span>⏱ Est. {playbook.estimated_ttc_min} min</span>
        <span>📋 Escalate: {playbook.escalate_to}</span>
        <span>🔧 {playbook.tools_needed?.join(", ")}</span>
      </div>
      {playbook.steps.map((step, i) => (
        <div key={i} className="playbook-step">
          <div
            className="step-header"
            style={{ borderLeftColor: PHASE_COLORS[step.phase] || "#00D4FF" }}
          >
            <span className="step-icon">{step.icon}</span>
            <span className="step-phase" style={{ color: PHASE_COLORS[step.phase] }}>
              {step.phase}
            </span>
          </div>
          <div className="step-actions">
            {step.actions.map((action, j) => (
              <div key={j} className="step-action">
                <span className="action-dot"
                  style={{ background: PHASE_COLORS[step.phase] || "#00D4FF" }} />
                {action}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function AlertDetail({ alert, apiUrl, onClose }) {
  const [playbook, setPlaybook] = useState(alert.playbook || null);
  const [loadingPlaybook, setLoadingPlaybook] = useState(false);
  const [playbookError, setPlaybookError] = useState(null);

  const fpInfo = FP_LABEL(alert.false_positive_score || 0);

  const fetchPlaybook = async () => {
    if (playbook) return;
    setPlaybookError(null);
    setLoadingPlaybook(true);
    try {
      const res = await fetch(`${apiUrl}/api/alerts/${alert.alert_id}/playbook`, {
        method: "POST",
        headers: buildApiHeaders(),
      });
      if (!res.ok) {
        throw new Error(`Playbook request failed (${res.status})`);
      }
      const data = await res.json();
      if (!data.playbook) {
        throw new Error("No playbook returned from server.");
      }
      setPlaybook(data.playbook);
    } catch (e) {
      console.error("Playbook fetch failed:", e);
      setPlaybookError(e.message || "Unable to generate playbook.");
    } finally {
      setLoadingPlaybook(false);
    }
  };

  useEffect(() => {
    setPlaybook(alert.playbook || null);
    if (!alert.playbook) fetchPlaybook();
  }, [alert.alert_id]);

  const severityColor = {
    Critical: "#EF4444", High: "#F59E0B", Medium: "#7C3AED", Low: "#10B981"
  }[alert.severity] || "#00D4FF";

  return (
    <div className="detail-panel">
      {/* Header */}
      <div className="detail-header" style={{ borderLeftColor: severityColor }}>
        <div className="detail-header-top">
          <div>
            <div className="detail-alert-id">{alert.alert_id}</div>
            <div className="detail-title">{alert.title}</div>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>
        <div className="detail-badges">
          <span className="detail-severity" style={{ background: `${severityColor}20`, color: severityColor }}>
            {alert.severity}
          </span>
          <span className="detail-confidence">
            Confidence: {(alert.confidence * 100).toFixed(0)}%
          </span>
          <span className="detail-mitre">{alert.mitre_id} · {alert.mitre_name}</span>
          <span className="detail-layer">{alert.layer?.toUpperCase()}</span>
        </div>
      </div>

      <div className="detail-scroll">
        {/* Why flagged */}
        <div className="detail-section">
          <div className="section-label">Why Flagged</div>
          <div className="why-flagged">{alert.why_flagged}</div>
        </div>

        {/* IPs */}
        <div className="detail-section">
          <div className="detail-ips">
            <div className="ip-block">
              <div className="ip-role">Source</div>
              <div className="ip-addr">{alert.src_ip}</div>
            </div>
            <div className="ip-arrow-big">→</div>
            <div className="ip-block">
              <div className="ip-role">Destination</div>
              <div className="ip-addr">{alert.dst_ip}</div>
            </div>
          </div>
        </div>

        {/* False positive */}
        <div className="detail-section">
          <div className="section-label">False Positive Assessment</div>
          <div className="fp-assessment" style={{ borderColor: fpInfo.color }}>
            <div className="fp-score" style={{ color: fpInfo.color }}>
              {(alert.false_positive_score * 100).toFixed(0)}% FP Probability
            </div>
            <div className="fp-verdict" style={{ color: fpInfo.color }}>{fpInfo.text}</div>
            {alert.false_positive_reason && (
              <div className="fp-reason">{alert.false_positive_reason}</div>
            )}
          </div>
        </div>

        {/* SHAP */}
        <div className="detail-section">
          <ShapChart features={alert.shap_features} />
        </div>

        {/* Playbook */}
        <div className="detail-section">
          {loadingPlaybook ? (
            <div className="loading-playbook">
              <div className="spinner" />
              Generating AI playbook...
            </div>
          ) : playbook ? (
            <PlaybookPanel playbook={playbook} />
          ) : playbookError ? (
            <div className="playbook-error">
              <div className="section-label">Playbook unavailable</div>
              <div>{playbookError}</div>
              <button className="retry-btn" onClick={fetchPlaybook}>
                Retry
              </button>
            </div>
          ) : (
            <div className="playbook-unavailable">
              Playbook will appear here once generated.
            </div>
          )}
        </div>

        {/* Correlated events */}
        {alert.correlated_event_ids?.length > 0 && (
          <div className="detail-section">
            <div className="section-label">Correlated Events ({alert.correlated_event_ids.length})</div>
            <div className="correlated-list">
              {alert.correlated_event_ids.map(id => (
                <span key={id} className="event-id">{id}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
