import { useMemo } from "react";

const THREAT_COLORS = {
  brute_force:       "#EF4444",
  c2_beacon:         "#F59E0B",
  lateral_movement:  "#7C3AED",
  data_exfil:        "#00D4FF",
};

const INTERNAL_ZONE = { x: 5, y: 10, w: 38, h: 78 };
const EXTERNAL_ZONE = { x: 57, y: 10, w: 38, h: 78 };

const KNOWN_POSITIONS = {
  "185.220.101.42": { x: 70, y: 25, label: "TOR Exit", threat: true },
  "45.142.212.100": { x: 80, y: 45, label: "C2 Server", threat: true },
  "91.108.4.0":     { x: 75, y: 65, label: "Botnet C2", threat: true },
  "54.239.28.85":   { x: 68, y: 80, label: "AWS S3",    threat: false },
  "8.8.8.8":        { x: 85, y: 78, label: "Google DNS",threat: false },
};

function hashPos(ip) {
  let h = 0;
  for (let c of ip) h = (h * 31 + c.charCodeAt(0)) & 0xffff;
  return h;
}

function getPos(ip) {
  if (KNOWN_POSITIONS[ip]) return KNOWN_POSITIONS[ip];
  if (ip?.startsWith("10.")) {
    const h = hashPos(ip);
    return { x: 8 + (h % 28), y: 18 + ((h >> 4) % 60), label: ip, threat: false };
  }
  const h = hashPos(ip || "");
  return { x: 60 + (h % 28), y: 18 + ((h >> 4) % 60), label: ip, threat: true };
}

export default function ThreatMap({ alerts }) {
  const lines = useMemo(() => {
    const seen = new Set();
    return alerts
      .filter(a => a.src_ip && a.dst_ip)
      .filter(a => {
        const k = `${a.src_ip}>${a.dst_ip}>${a.threat_type}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .slice(0, 20)
      .map(a => ({
        src: getPos(a.src_ip),
        dst: getPos(a.dst_ip),
        color: THREAT_COLORS[a.threat_type] || "#888",
        type: a.threat_type,
        dashed: a.threat_type === "c2_beacon",
      }));
  }, [alerts]);

  const nodes = useMemo(() => {
    const map = {};
    alerts.forEach(a => {
      if (a.src_ip) map[a.src_ip] = { ...getPos(a.src_ip), ip: a.src_ip };
      if (a.dst_ip) map[a.dst_ip] = { ...getPos(a.dst_ip), ip: a.dst_ip };
    });
    return Object.values(map).slice(0, 20);
  }, [alerts]);

  return (
    <div className="threat-map">
      <div className="panel-header" style={{ padding: "10px 16px" }}>
        <span className="panel-title">Network Threat Map</span>
        <span style={{ fontSize: 11, color: "var(--muted)" }}>
          {lines.length} connections tracked
        </span>
      </div>

      <div style={{ flex: 1, padding: "8px 16px 0" }}>
        <svg viewBox="0 0 100 100" style={{ width: "100%", height: "220px" }}>
          {/* Internal zone */}
          <rect x={INTERNAL_ZONE.x} y={INTERNAL_ZONE.y}
            width={INTERNAL_ZONE.w} height={INTERNAL_ZONE.h}
            rx="3" fill="#00D4FF06" stroke="#00D4FF30" strokeWidth="0.4"/>
          <text x="24" y="16" textAnchor="middle" fontSize="3.5"
            fill="#00D4FF60" fontFamily="monospace">INTERNAL NETWORK</text>

          {/* External zone */}
          <rect x={EXTERNAL_ZONE.x} y={EXTERNAL_ZONE.y}
            width={EXTERNAL_ZONE.w} height={EXTERNAL_ZONE.h}
            rx="3" fill="#EF444406" stroke="#EF444430" strokeWidth="0.4"/>
          <text x="76" y="16" textAnchor="middle" fontSize="3.5"
            fill="#EF444460" fontFamily="monospace">EXTERNAL</text>

          {/* Firewall */}
          <line x1="49" y1="8" x2="49" y2="92"
            stroke="#94A3B8" strokeWidth="0.5" strokeDasharray="1.5,1.5" opacity="0.5"/>
          <text x="49" y="96" textAnchor="middle" fontSize="2.5"
            fill="#94A3B860">🔒 FIREWALL</text>

          {/* Connection lines */}
          {lines.map((l, i) => (
            <line key={i}
              x1={l.src.x} y1={l.src.y}
              x2={l.dst.x} y2={l.dst.y}
              stroke={l.color}
              strokeWidth={l.type === "data_exfil" ? "0.8" : "0.4"}
              strokeOpacity="0.6"
              strokeDasharray={l.dashed ? "1,1" : "none"}
            />
          ))}

          {/* Nodes */}
          {nodes.map((n, i) => {
            const known = KNOWN_POSITIONS[n.ip];
            const isThreat = known?.threat ?? n.ip?.startsWith("10.") === false;
            return (
              <g key={i}>
                <circle cx={n.x} cy={n.y} r="2.2"
                  fill={isThreat ? "#EF444420" : "#00D4FF12"}
                  stroke={isThreat ? "#EF4444" : "#00D4FF"}
                  strokeWidth="0.4"/>
                <circle cx={n.x} cy={n.y} r="0.8"
                  fill={isThreat ? "#EF4444" : "#00D4FF"}/>
                {known && (
                  <text x={n.x} y={n.y - 3.5} textAnchor="middle"
                    fontSize="2.2" fill="#94A3B8">{known.label}</text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className="map-legend" style={{ padding: "4px 16px 10px" }}>
        {Object.entries(THREAT_COLORS).map(([k, c]) => (
          <div key={k} className="legend-item">
            <div className="legend-dot" style={{ background: c }}/>
            <span>{k.replace(/_/g, " ")}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
