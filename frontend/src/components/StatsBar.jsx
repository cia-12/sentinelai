// ─── StatsBar ──────────────────────────────────────────────────────────────

export function StatsBar({ stats, threatCounts }) {
  const cards = [
    { label: "Events Processed", value: stats.events_processed?.toLocaleString() || "0", color: "#00D4FF" },
    { label: "Total Alerts", value: stats.alerts_total || 0, color: "#F59E0B" },
    { label: "Active Incidents", value: stats.alerts_active || 0, color: "#EF4444" },
    { label: "Throughput", value: `${stats.eps || 0} eps`, color: "#10B981" },
  ];

  const threatBreakdown = [
    { key: "brute_force",      label: "Brute Force",      color: "#EF4444" },
    { key: "c2_beacon",        label: "C2 Beacon",        color: "#F59E0B" },
    { key: "lateral_movement", label: "Lateral Movement", color: "#7C3AED" },
    { key: "data_exfil",       label: "Data Exfil",       color: "#00D4FF" },
  ];

  return (
    <div className="stats-bar">
      <div className="stat-cards">
        {cards.map(c => (
          <div key={c.label} className="stat-card">
            <div className="stat-value" style={{ color: c.color }}>{c.value}</div>
            <div className="stat-label">{c.label}</div>
          </div>
        ))}
      </div>
      <div className="threat-breakdown">
        {threatBreakdown.map(t => (
          <div key={t.key} className="threat-count">
            <div className="threat-dot" style={{ background: t.color }} />
            <span className="threat-name">{t.label}</span>
            <span className="threat-num" style={{ color: t.color }}>
              {threatCounts[t.key] || 0}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}


// ─── ThreatMap ────────────────────────────────────────────────────────────────

const IP_POSITIONS = {
  "10.0.1.": { x: 38, y: 45, label: "Internal LAN 1" },
  "10.0.2.": { x: 38, y: 65, label: "Internal LAN 2" },
  "10.0.3.": { x: 38, y: 55, label: "Internal LAN 3" },
  "185.220": { x: 82, y: 28, label: "TOR Exit Node 🔴" },
  "45.142":  { x: 82, y: 45, label: "C2 Server 🔴" },
  "54.239":  { x: 82, y: 65, label: "AWS S3 ✅" },
  "8.8.8.8": { x: 82, y: 80, label: "Google DNS" },
};

const THREAT_COLORS = {
  brute_force:       "#EF4444",
  c2_beacon:         "#F59E0B",
  lateral_movement:  "#7C3AED",
  data_exfil:        "#00D4FF",
};

function getPos(ip) {
  const prefix = Object.keys(IP_POSITIONS).find(k => ip?.startsWith(k));
  if (prefix) return IP_POSITIONS[prefix];
  // Default positions for unmapped IPs
  return { x: 60 + Math.random() * 20, y: 40 + Math.random() * 30 };
}

export function ThreatMap({ alerts }) {
  const recent = alerts.filter(a => a.threat_type !== "false_positive").slice(0, 15);

  return (
    <div className="threat-map">
      <div className="panel-title">Network Threat Map</div>
      <svg viewBox="0 0 100 100" className="map-svg">
        {/* Background zones */}
        <rect x="2" y="2" width="44" height="96" rx="3"
          fill="#00D4FF08" stroke="#00D4FF30" strokeWidth="0.3"/>
        <rect x="54" y="2" width="44" height="96" rx="3"
          fill="#EF444408" stroke="#EF444430" strokeWidth="0.3"/>
        <text x="24" y="8" textAnchor="middle" fontSize="3" fill="#00D4FF80">INTERNAL</text>
        <text x="76" y="8" textAnchor="middle" fontSize="3" fill="#EF444480">EXTERNAL</text>

        {/* Firewall line */}
        <line x1="49" y1="4" x2="49" y2="96"
          stroke="#94A3B8" strokeWidth="0.3" strokeDasharray="2,2"/>
        <text x="49" y="99" textAnchor="middle" fontSize="2.5" fill="#94A3B880">FIREWALL</text>

        {/* Connection lines for alerts */}
        {recent.map((alert, i) => {
          const src = getPos(alert.src_ip);
          const dst = getPos(alert.dst_ip);
          const col = THREAT_COLORS[alert.threat_type] || "#888";
          return (
            <g key={alert.alert_id}>
              <line
                x1={src.x} y1={src.y} x2={dst.x} y2={dst.y}
                stroke={col} strokeWidth="0.4" strokeOpacity="0.5"
                strokeDasharray={alert.threat_type === "c2_beacon" ? "1,1" : "none"}
              />
              <circle cx={dst.x} cy={dst.y} r="0.8" fill={col} opacity="0.7" />
            </g>
          );
        })}

        {/* Internal nodes */}
        {[{x:38,y:45},{x:38,y:55},{x:38,y:65}].map((p,i) => (
          <g key={i}>
            <circle cx={p.x} cy={p.y} r="2" fill="#1A2235" stroke="#00D4FF60" strokeWidth="0.3"/>
            <circle cx={p.x} cy={p.y} r="0.8" fill="#00D4FF"/>
          </g>
        ))}
      </svg>

      {/* Legend */}
      <div className="map-legend">
        {Object.entries(THREAT_COLORS).map(([k, c]) => (
          <div key={k} className="legend-item">
            <div className="legend-dot" style={{ background: c }} />
            <span>{k.replace(/_/g," ")}</span>
          </div>
        ))}
      </div>
    </div>
  );
}


// ─── SimulatorPanel ───────────────────────────────────────────────────────────

const SCENARIOS = [
  { key: "brute_force",      label: "Brute Force Attack",     icon: "🔐", color: "#EF4444" },
  { key: "c2_beacon",        label: "C2 Beacon",              icon: "📡", color: "#F59E0B" },
  { key: "lateral_movement", label: "Lateral Movement",       icon: "🔀", color: "#7C3AED" },
  { key: "data_exfil",       label: "Data Exfiltration",      icon: "📤", color: "#00D4FF" },
  { key: "false_positive",   label: "False Positive (Admin)", icon: "✅", color: "#10B981" },
];

export function SimulatorPanel({ apiUrl }) {
  const [firing, setFiring] = useState(null);
  const [lastFired, setLastFired] = useState(null);

  const fire = async (scenario) => {
    setFiring(scenario);
    try {
      await fetch(`${apiUrl}/api/simulate/${scenario}`, { method: "POST" });
      setLastFired(scenario);
      setTimeout(() => setLastFired(null), 3000);
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => setFiring(null), 1000);
    }
  };

  return (
    <div className="simulator">
      <div className="panel-title">
        Attack Simulator
        <span className="simulator-badge">DEMO MODE</span>
      </div>
      <div className="simulator-desc">
        Trigger live attack scenarios — watch alerts appear in real time
      </div>
      <div className="simulator-buttons">
        {SCENARIOS.map(s => (
          <button
            key={s.key}
            className={`sim-btn ${firing === s.key ? "firing" : ""} ${lastFired === s.key ? "fired" : ""}`}
            style={{ "--accent": s.color }}
            onClick={() => fire(s.key)}
            disabled={!!firing}
          >
            <span className="sim-icon">{s.icon}</span>
            <span className="sim-label">{s.label}</span>
            {lastFired === s.key && <span className="sim-check">✓ Injected</span>}
          </button>
        ))}
      </div>
    </div>
  );
}

export default StatsBar;
