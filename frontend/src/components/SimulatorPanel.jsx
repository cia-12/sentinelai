import { useState } from "react";
import { buildApiHeaders } from "../api";

const SCENARIOS = [
  { key: "brute_force",       label: "Brute Force",         icon: "🔐", color: "#EF4444",
    desc: "500+ login attempts from 3 distributed IPs" },
  { key: "c2_beacon",         label: "C2 Beacon",           icon: "📡", color: "#F59E0B",
    desc: "Infected host pinging C2 every 5s" },
  { key: "lateral_movement",  label: "Lateral Movement",    icon: "🔀", color: "#7C3AED",
    desc: "Internal host scanning SMB/RDP on subnet" },
  { key: "data_exfil",        label: "Data Exfiltration",   icon: "📤", color: "#00D4FF",
    desc: "8 GB to TOR exit node via port 4444" },
  { key: "false_positive",    label: "False Positive",      icon: "✅", color: "#10B981",
    desc: "Admin backup to AWS S3 (looks like exfil)" },
];

export default function SimulatorPanel({ apiUrl }) {
  const [firing, setFiring]     = useState(null);
  const [lastFired, setLastFired] = useState(null);

  const fire = async (scenario) => {
    if (firing) return;
    setFiring(scenario);
    try {
      await fetch(`${apiUrl}/api/simulate/${scenario}`, {
        method: "POST",
        headers: buildApiHeaders(),
      });
      setLastFired(scenario);
      setTimeout(() => setLastFired(null), 4000);
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => setFiring(null), 800);
    }
  };

  return (
    <div className="simulator">
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
        <span className="panel-title">Attack Simulator</span>
        <span className="simulator-badge">DEMO</span>
      </div>
      <div className="simulator-desc">
        Inject live attacks → watch alerts fire in real time
      </div>
      <div className="simulator-buttons">
        {SCENARIOS.map(s => (
          <button
            key={s.key}
            className={`sim-btn ${firing === s.key ? "firing" : ""} ${lastFired === s.key ? "fired" : ""}`}
            onClick={() => fire(s.key)}
            disabled={!!firing}
            title={s.desc}
            style={{ borderColor: lastFired === s.key ? s.color : undefined,
                     color: lastFired === s.key ? s.color : undefined }}
          >
            <span className="sim-icon">{s.icon}</span>
            <span className="sim-label">{s.label}</span>
            {lastFired === s.key && <span className="sim-check">✓</span>}
          </button>
        ))}
      </div>
    </div>
  );
}
