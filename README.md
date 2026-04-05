# 🛡 SentinelAI — AI-Driven Threat Detection & Simulation Engine

> **Hack Malenadu '26 | Cybersecurity Track | Problem Statement 3**

SentinelAI is a demo-ready, real-time security operations platform that ingests multi-layer network and endpoint logs, detects threats using AI models, explains every alert in plain English, and auto-generates context-aware prevention playbooks — all live in a SOC dashboard.

---

## 🏆 What Makes This Winning-Level

| Requirement | Minimum Bar | **SentinelAI** |
|---|---|---|
| Signal layers | 1 (network only) | **3 layers** — Network + Endpoint + HTTP with cross-layer correlation |
| Threat categories | 2 | **4 categories** + MITRE ATT&CK mapping |
| Explainability | Alert + reason | **SHAP** feature importance + plain-English + false-positive indicator |
| Playbooks | Static template | **LLM-generated** context-aware playbooks via Claude API |
| Dashboard | Terminal output | **Live SOC dashboard** with WebSocket streaming |
| Throughput | — | **Configurable event rate**, tuned to 6 eps by default for demo clarity |
| Bonus | Not attempted | **Attack Simulator** + self-validation + false-positive demo |

---

## 🚀 Quick Start (2 minutes)

### Option A — Docker (recommended)
```bash
git clone https://github.com/your-team/sentinelai
cd sentinelai

# Optional: add your Anthropic API key for LLM playbooks
export ANTHROPIC_API_KEY=sk-ant-...

docker-compose up --build
```
- Dashboard: http://localhost:3000
- API docs:  http://localhost:8000/docs

### Option B — Local dev
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev          # → http://localhost:3000
```

Optional auth:
- Backend auth is off by default in demo mode.
- If you enable `SENTINEL_REQUIRE_AUTH=true`, also set `VITE_API_KEY` in `frontend/.env.local` to the same value as `SENTINEL_API_KEY`.

---

## 🏗 Architecture

```
┌─────────────────── SentinelAI ───────────────────────┐
│                                                        │
│  Log Generator ──► Detection Engine ──► Alert Store   │
│  (3 layers)        (IF + Seq + Rules)   (in-memory)   │
│                           │                   │        │
│                    Correlator           FastAPI API    │
│                    (cross-layer)        /api + /ws     │
│                           │                   │        │
│                    Playbook Engine    WebSocket Push   │
│                    (Claude API)               │        │
│                                       React Dashboard  │
└────────────────────────────────────────────────────────┘
```

### Layer 1 — Multi-Signal Ingestion
- **Network**: `src_ip`, `dst_ip`, `port`, `protocol`, `bytes_out/in`, `duration`, `flags`
- **Endpoint**: `process`, `parent_pid`, `user`, `file_access`, `registry_change`, `network_connection`
- **HTTP/API**: `method`, `endpoint`, `status_code`, `payload_bytes`, `user_agent`
- All normalized to a unified JSON event schema before analysis

### Layer 2 — AI Detection Engine (`detection_engine.py`)
| Threat | Model | MITRE |
|---|---|---|
| Brute Force | Rate tracker + rule threshold | T1110 |
| C2 Beaconing | Sequence analyzer (inter-arrival CV) | T1071 |
| Lateral Movement | Internal scan rate + cross-layer match | T1021 |
| Data Exfiltration | Isolation Forest + threat-intel lookup | T1048 |

### Layer 3 — Explainability & Correlation
- **SHAP approximation**: top features driving each alert with weights + explanations
- **False-positive engine**: whitelist IPs, known users, scheduled jobs, threat-intel match
- **Cross-layer correlator**: same IP appearing on network AND endpoint within 20s → confidence boost

### Layer 4 — Playbook & Dashboard
- **LLM playbooks**: Claude API generates Contain→Investigate→Eradicate→Prevent steps per incident
- **Fallback templates**: works without API key
- **React dashboard**: live WebSocket feed, SHAP charts, attack simulator, threat map

---

## 🎯 Demo Walkthrough

### 30-second pitch
1. **Open** http://localhost:3000 — show the live event counter ticking up
2. Click **"Brute Force"** in the simulator → watch the red `CRIT` alert appear instantly
3. Click the alert → show the **SHAP explanation** and **AI playbook**
4. Click **"C2 Beacon"** → a second alert fires; show **cross-layer correlation**
5. Click **"False Positive"** → alert fires at LOW severity with FP reason shown
6. Point out: **MITRE ID**, **confidence score**, **false-positive %**, **specific IP addresses**

### API endpoints
```bash
# Live stats
curl http://localhost:8000/api/stats

# All alerts
curl http://localhost:8000/api/alerts

# Trigger attack
curl -X POST http://localhost:8000/api/simulate/c2_beacon

# Get playbook for an alert
curl -X POST http://localhost:8000/api/alerts/ALT-0001/playbook

# MITRE coverage
curl http://localhost:8000/api/mitre
```

---

## 📁 Project Structure

```
sentinelai/
├── backend/
│   ├── main.py              # FastAPI server + WebSocket
│   ├── detection_engine.py  # Isolation Forest, Seq Analyzer, SHAP
│   ├── log_generator.py     # Realistic multi-layer log generator
│   ├── playbook_engine.py   # Claude API playbook generation
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # Root layout + WebSocket
│   │   ├── components/
│   │   │   ├── AlertFeed.jsx     # Real-time incident feed
│   │   │   ├── AlertDetail.jsx   # SHAP + playbook panel
│   │   │   ├── ThreatMap.jsx     # Network visualization
│   │   │   ├── StatsBar.jsx      # Live metrics
│   │   │   └── SimulatorPanel.jsx# Attack injection
│   │   └── index.css            # Dark SOC theme
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
└── README.md
```

---

## 🧠 Technical Deep Dive

### Isolation Forest (anomaly detection)
Built from scratch — no sklearn required. Ensemble of 30 isolation trees, trained on benign traffic baseline. Anomaly score > 0.65 triggers exfiltration review.

### Sequence Analyzer (C2 detection)
Tracks inter-arrival times per IP pair using a sliding window. Computes coefficient of variation (CV) of intervals — CV < 0.25 indicates machine-like periodicity → beacon flag.

### Cross-Layer Correlator
Time-windowed join (20s) of events by source IP across layers. If the same IP fires on both network layer (anomalous traffic) and endpoint layer (suspicious process) simultaneously, confidence escalates by 8–15%.

### SHAP Approximation
Rule-based feature importance weights approximating SHAP values — no model retraining needed. Each alert gets top-5 features with direction, weight, and plain-English explanation.

---

## 🔑 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | (empty) | Claude API key for LLM playbooks. Falls back to templates if unset. |
| `VITE_WS_URL` | `ws://localhost:8000/ws` | WebSocket URL for frontend |
| `VITE_API_URL` | `http://localhost:8000` | REST API URL for frontend |
| `VITE_API_KEY` | (empty) | Optional frontend API key; required only when backend auth is enabled |

> Tip: When running the frontend locally, set `frontend/.env.local` to match the backend port (default is `8000`). If you use a custom port, update `VITE_API_URL` and `VITE_WS_URL` accordingly.

---

## 📊 Datasets Used
- **CICIDS-2017/2018**: Real network flow data (benign + attack)
- **UNSW-NB15**: Network intrusion dataset
- **Synthetic generator** (`log_generator.py`): Custom multi-layer log generator with realistic attack injection

---

*Built in 36 hours by Team SentinelAI | Hack Malenadu '26*
