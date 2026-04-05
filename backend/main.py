"""
SentinelAI — FastAPI Backend
Real-time threat detection server with WebSocket streaming to the SOC dashboard.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import threading
import time
from collections import deque
from typing import Set

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from runtime_config import (
    ALERTS_MAXLEN,
    API_HOST,
    API_KEY,
    API_PORT,
    API_RELOAD,
    CORS_ALLOW_CREDENTIALS,
    CORS_ORIGINS,
    EVENTS_PER_SECOND,
    PERSIST_ALERTS,
    REQUIRE_AUTH,
)
from logging_setup import logger
from alert_store import AlertStore, init_db
from log_generator import LogGenerator
from detection_engine import DetectionEngine
from playbook_engine import generate_playbook

# Initialize database
init_db()

# ─── Shared state ─────────────────────────────────────────────────────────────

class SentinelState:
    def __init__(self):
        self.alerts: deque = deque(maxlen=ALERTS_MAXLEN)
        self.events_processed: int = 0
        self.alerts_total: int = 0
        self.start_time: float = time.time()
        self.ws_clients: Set[WebSocket] = set()
        self.lock = asyncio.Lock()
        self.engine = DetectionEngine()
        self.generator = LogGenerator(events_per_second=EVENTS_PER_SECOND)
        self.simulation_lock = asyncio.Lock()
        self.started = False
        # Metrics
        self.alerts_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        self.alerts_by_type = {"brute_force": 0, "c2_beacon": 0, "lateral_movement": 0, "data_exfil": 0}
        logger.info("SentinelState initialized with config: eps=%d, alerts_maxlen=%d", EVENTS_PER_SECOND, ALERTS_MAXLEN)

    def get_stats(self) -> dict:
        uptime_s = time.time() - self.start_time
        return {
            "events_processed": self.events_processed,
            "alerts_total": self.alerts_total,
            "alerts_active": len([a for a in self.alerts if a.get("severity") in ("Critical","High")]),
            "uptime_s": round(uptime_s),
            "eps": round(self.events_processed / max(uptime_s, 1), 1),
        }

state = SentinelState()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not state.started:
        logger.info("SentinelAI engine starting...")
        if PERSIST_ALERTS:
            recent = AlertStore.get_recent_alerts(limit=ALERTS_MAXLEN)
            for alert in recent:
                state.alerts.append(alert)
            logger.info("Loaded %d alerts from database", len(recent))
        asyncio.create_task(detection_loop())
        state.started = True
        logger.info("SentinelAI engine started")
    yield


app = FastAPI(title="SentinelAI API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)



# ─── Authentication middleware ───────────────────────────────────────────────

def verify_api_key(x_api_key: str = Header(None)) -> str:
    """Verify API key for protected endpoints."""
    if not REQUIRE_AUTH:
        return "ok"
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    if x_api_key != API_KEY:
        logger.warning("Invalid API key attempt: %s", x_api_key[:10] + "***")
        raise HTTPException(status_code=403, detail="Invalid API key")
    return "ok"


# ─── WebSocket manager ────────────────────────────────────────────────────────

async def broadcast(msg: dict):
    """Send message to all connected WebSocket clients."""
    if not state.ws_clients:
        return
    dead = set()
    payload = json.dumps(msg)
    for ws in state.ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    state.ws_clients -= dead


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    state.ws_clients.add(ws)
    try:
        # Send current state on connect
        await ws.send_text(json.dumps({
            "type": "init",
            "alerts": [a for a in state.alerts],
            "stats": state.get_stats()
        }))
        while True:
            # Keep connection alive
            await asyncio.sleep(30)
            await ws.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        state.ws_clients.discard(ws)
    except Exception:
        state.ws_clients.discard(ws)


# ─── REST endpoints ───────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SentinelAI"}

@app.get("/api/stats")
def get_stats():
    return state.get_stats()

@app.get("/api/alerts")
def get_alerts(limit: int = 50, threat_type: str = None, severity: str = None):
    alerts = list(state.alerts)
    if threat_type:
        alerts = [a for a in alerts if a.get("threat_type") == threat_type]
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    return {"alerts": alerts[-limit:], "total": len(alerts)}

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    for a in state.alerts:
        if a.get("alert_id") == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")

@app.post("/api/alerts/{alert_id}/playbook")
async def get_playbook(alert_id: str, _auth: str = Depends(verify_api_key)):
    """Generate or retrieve playbook for an alert."""
    for a in state.alerts:
        if a.get("alert_id") == alert_id:
            if not a.get("playbook"):
                a["playbook"] = await generate_playbook(a, use_llm=True)
            return {"playbook": a["playbook"]}
    raise HTTPException(status_code=404, detail="Alert not found")

@app.post("/api/simulate/{scenario}")
async def trigger_scenario(scenario: str, _auth: str = Depends(verify_api_key)):
    """
    Manually trigger an attack scenario for demo purposes.
    Requires: X-API-Key header
    scenario: brute_force | c2_beacon | lateral_movement | data_exfil | false_positive
    """
    valid = ["brute_force", "c2_beacon", "lateral_movement", "data_exfil", "false_positive"]
    if scenario not in valid:
        raise HTTPException(400, f"Invalid scenario. Choose from: {valid}")
    logger.info("Simulation triggered: %s", scenario)
    async with state.simulation_lock:
        state.generator.trigger_scenario(scenario)
    await broadcast({"type": "simulation_triggered", "scenario": scenario})
    return {"status": "triggered", "scenario": scenario}

@app.get("/api/mitre")
def get_mitre_coverage():
    """Return MITRE ATT&CK techniques covered."""
    return {
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "covered": True},
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "covered": True},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "covered": True},
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "covered": True},
        ]
    }


@app.get("/api/metrics")
def get_metrics():
    """Return Prometheus-style metrics."""
    uptime_s = time.time() - state.start_time
    eps = state.events_processed / max(uptime_s, 1)
    aps = state.alerts_total / max(uptime_s, 1)  # alerts per second
    return {
        "events_processed": state.events_processed,
        "events_per_second": round(eps, 2),
        "alerts_total": state.alerts_total,
        "alerts_per_second": round(aps, 3),
        "alerts_by_severity": state.alerts_by_severity,
        "alerts_by_type": state.alerts_by_type,
        "uptime_s": round(uptime_s),
        "websocket_clients": len(state.ws_clients),
        "db_persisted": PERSIST_ALERTS,
    }



# ─── Background detection loop ────────────────────────────────────────────────

async def detection_loop():
    """Runs log generation + detection in the background."""
    loop = asyncio.get_running_loop()
    gen = state.generator

    def run_generator():
        """Runs in a thread — pushes events to async queue."""
        for batch in gen.generate():
            asyncio.run_coroutine_threadsafe(
                process_batch(batch), loop
            )

    # Start generator thread
    t = threading.Thread(target=run_generator, daemon=True)
    t.start()


async def process_batch(batch: list):
    """Process a batch of events through the detection engine."""
    alerts_in_batch = []
    for event in batch:
        state.events_processed += 1
        alert = state.engine.process(event)
        if alert:
            state.alerts_total += 1
            # Generate playbook (use fallback for speed, LLM async)
            from playbook_engine import FALLBACK_PLAYBOOKS
            alert_dict = alert.to_dict()
            alert_dict["playbook"] = FALLBACK_PLAYBOOKS.get(
                alert.threat_type,
                FALLBACK_PLAYBOOKS["data_exfil"]
            )
            state.alerts.append(alert_dict)
            alerts_in_batch.append(alert_dict)
            
            # Update metrics
            state.alerts_by_severity[alert.severity] = state.alerts_by_severity.get(alert.severity, 0) + 1
            state.alerts_by_type[alert.threat_type] = state.alerts_by_type.get(alert.threat_type, 0) + 1
            
            # Persist to database
            if PERSIST_ALERTS:
                AlertStore.save_alert(alert_dict)
            
            logger.debug("Alert generated: %s - %s (%s)", alert.alert_id, alert.title, alert.severity)

    # Batch broadcast: send all alerts at once, then stats
    for alert_dict in alerts_in_batch:
        await broadcast({
            "type": "alert",
            "alert": alert_dict,
            "stats": state.get_stats()
        })

    # Broadcast stats heartbeat every 100 events (reduced frequency)
    if state.events_processed % 100 == 0:
        logger.info("Stats: %d events, %d alerts (%.2f eps, %.3f aps)",
                   state.events_processed, state.alerts_total,
                   state.events_processed / max(time.time() - state.start_time, 1),
                   state.alerts_total / max(time.time() - state.start_time, 1))
        await broadcast({
            "type": "stats",
            "stats": state.get_stats()
        })


# ─── Startup ──────────────────────────────────────────────────────────────────

async def _legacy_startup():
    logger.info("🛡 SentinelAI engine starting...")
    # Load alerts from database if persistence enabled
    if PERSIST_ALERTS:
        recent = AlertStore.get_recent_alerts(limit=ALERTS_MAXLEN)
        for alert in recent:
            state.alerts.append(alert)
        logger.info("Loaded %d alerts from database", len(recent))
    asyncio.create_task(detection_loop())
    logger.info("🛡 SentinelAI engine started")


if __name__ == "__main__":
    logger.info("Starting SentinelAI API on %s:%d", API_HOST, API_PORT)
    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=API_RELOAD)
