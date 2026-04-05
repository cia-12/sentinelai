import { useState, useEffect, useRef, useCallback } from "react";
import AlertFeed from "./components/AlertFeed";
import AlertDetail from "./components/AlertDetail";
import { StatsBar } from "./components/StatsBar";
import ThreatMap from "./components/ThreatMap";
import SimulatorPanel from "./components/SimulatorPanel";
import { API_URL, WS_URL } from "./api";

export default function App() {
  const [alerts,    setAlerts]    = useState([]);
  const [stats,     setStats]     = useState({ events_processed:0, alerts_total:0, alerts_active:0, eps:0 });
  const [selected,  setSelected]  = useState(null);
  const [connected, setConnected] = useState(false);
  const [filter,    setFilter]    = useState("all");
  const wsRef        = useRef(null);
  const reconnectRef = useRef(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    ws.onopen  = () => { setConnected(true); clearTimeout(reconnectRef.current); };
    ws.onclose = () => { setConnected(false); reconnectRef.current = setTimeout(connect, 3000); };
    ws.onerror = () => ws.close();
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "init") { setAlerts(msg.alerts||[]); setStats(msg.stats||{}); }
      else if (msg.type === "alert") { setAlerts(prev=>[msg.alert,...prev].slice(0,300)); if(msg.stats)setStats(msg.stats); }
      else if (msg.type === "stats") { setStats(msg.stats||{}); }
    };
  }, []);

  useEffect(() => { connect(); return()=>{clearTimeout(reconnectRef.current);wsRef.current?.close();}; }, [connect]);

  const filteredAlerts = filter==="all" ? alerts : alerts.filter(a=>a.threat_type===filter);
  const displayAlerts = filteredAlerts.slice(0, 100);  // Limit display to 100 most recent
  const threatCounts = alerts.reduce((acc,a)=>{ acc[a.threat_type]=(acc[a.threat_type]||0)+1; return acc; },{});

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <div className="logo">
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
              <path d="M14 2L26 7V14C26 20.627 20.627 25.5 14 27C7.373 25.5 2 20.627 2 14V7L14 2Z" fill="#00D4FF" fillOpacity="0.15" stroke="#00D4FF" strokeWidth="1.5"/>
              <path d="M14 6L22 10V14C22 18.418 18.418 22 14 23C9.582 22 6 18.418 6 14V10L14 6Z" fill="#00D4FF" fillOpacity="0.3"/>
              <path d="M10 14L13 17L18 11" stroke="#00D4FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span className="logo-text">SentinelAI</span>
          </div>
          <div className="subtitle">AI Threat Detection &amp; Simulation Engine</div>
        </div>
        <div className="header-right">
          <div className={`connection-badge ${connected?"live":"offline"}`}>
            <span className="dot"/>
            {connected ? "LIVE" : "RECONNECTING…"}
          </div>
          <div className="hack-badge">Hack Malenadu '26</div>
        </div>
      </header>

      <StatsBar stats={stats} threatCounts={threatCounts}/>

      <div className="main-layout">
        <div className="left-panel">
          <div className="panel-header">
            <span className="panel-title">Incident Feed ({displayAlerts.length})</span>
            <div className="filter-tabs">
              {["all","brute_force","c2_beacon","lateral_movement","data_exfil"].map(f=>(
                <button key={f} className={`filter-tab ${filter===f?"active":""}`} onClick={()=>setFilter(f)}>
                  {f==="all"?"All":f.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase())}
                </button>
              ))}
            </div>
          </div>
          <AlertFeed alerts={displayAlerts} selected={selected} onSelect={setSelected}/>
        </div>

        <div className="right-panel">
          {selected
            ? <AlertDetail alert={selected} apiUrl={API_URL} onClose={()=>setSelected(null)}/>
            : <div className="right-top"><ThreatMap alerts={alerts.slice(0,60)}/></div>
          }
          <SimulatorPanel apiUrl={API_URL}/>
        </div>
      </div>
    </div>
  );
}
