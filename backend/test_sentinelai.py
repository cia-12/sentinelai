"""
SentinelAI — Comprehensive Backend Tests
Tests for API endpoints, simulation triggers, playbook fallback, and state management.
"""
import asyncio
import json
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from main import app, state, SentinelState
from log_generator import LogGenerator
from detection_engine import DetectionEngine
from playbook_engine import generate_playbook, FALLBACK_PLAYBOOKS, _extract_playbook_text


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """FastAPI test client."""
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.fixture
def mock_generator():
    """Mock LogGenerator for testing."""
    gen = LogGenerator(events_per_second=10)
    return gen


@pytest.fixture
def alert_dict():
    """Sample alert dict for playbook testing."""
    return {
        "alert_id": "ALT-0001",
        "threat_type": "brute_force",
        "severity": "High",
        "confidence": 0.85,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.1.1",
        "description": "Brute force attack detected",
        "why_flagged": "100+ failed login attempts",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "false_positive_score": 0.1,
        "shap_features": [
            {"feature": "login_rate", "value": 100, "weight": 0.9},
            {"feature": "distributed_ips", "value": 3, "weight": 0.8},
        ]
    }


# ─── Test: API Health & Stats ────────────────────────────────────────────────

class TestAPIHealth:
    def test_health_endpoint(self, client):
        """Health check should return ok status."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["service"] == "SentinelAI"

    def test_stats_endpoint(self, client):
        """Stats endpoint should return valid statistics."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "events_processed" in data
        assert "alerts_total" in data
        assert "alerts_active" in data
        assert "uptime_s" in data
        assert "eps" in data
        assert data["events_processed"] >= 0
        assert data["alerts_total"] >= 0


# ─── Test: Alerts Endpoints ───────────────────────────────────────────────────

class TestAlertsEndpoints:
    def test_get_alerts_empty(self, client):
        """Get alerts when none exist."""
        # Clear state
        state.alerts.clear()
        response = client.get("/api/alerts")
        assert response.status_code == 200
        data = response.json()
        assert data["alerts"] == []
        assert data["total"] == 0

    def test_get_alerts_with_limit(self, client):
        """Get alerts respects limit parameter."""
        state.alerts.clear()
        # Add dummy alerts
        for i in range(5):
            state.alerts.append({
                "alert_id": f"ALT-{i:04d}",
                "threat_type": "brute_force",
                "severity": "High"
            })
        response = client.get("/api/alerts?limit=3")
        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 3

    def test_get_alerts_filter_threat_type(self, client):
        """Filter alerts by threat type."""
        state.alerts.clear()
        state.alerts.append({"alert_id": "ALT-0001", "threat_type": "brute_force"})
        state.alerts.append({"alert_id": "ALT-0002", "threat_type": "c2_beacon"})
        state.alerts.append({"alert_id": "ALT-0003", "threat_type": "brute_force"})

        response = client.get("/api/alerts?threat_type=brute_force")
        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 2
        assert all(a["threat_type"] == "brute_force" for a in data["alerts"])

    def test_get_alerts_filter_severity(self, client):
        """Filter alerts by severity."""
        state.alerts.clear()
        state.alerts.append({"alert_id": "ALT-0001", "severity": "Critical"})
        state.alerts.append({"alert_id": "ALT-0002", "severity": "Low"})
        state.alerts.append({"alert_id": "ALT-0003", "severity": "Critical"})

        response = client.get("/api/alerts?severity=Critical")
        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 2
        assert all(a["severity"] == "Critical" for a in data["alerts"])

    def test_get_single_alert_exists(self, client):
        """Retrieve a single alert by ID."""
        state.alerts.clear()
        test_alert = {"alert_id": "ALT-0001", "threat_type": "brute_force"}
        state.alerts.append(test_alert)

        response = client.get("/api/alerts/ALT-0001")
        assert response.status_code == 200
        assert response.json()["alert_id"] == "ALT-0001"

    def test_get_single_alert_not_found(self, client):
        """Return 404 when alert not found."""
        state.alerts.clear()
        response = client.get("/api/alerts/NONEXISTENT")
        assert response.status_code == 404


# ─── Test: Simulation Triggers ──────────────────────────────────────────────

class TestSimulationTriggers:
    def test_trigger_brute_force(self, client):
        """Trigger brute force scenario."""
        response = client.post("/api/simulate/brute_force")
        assert response.status_code == 200
        assert response.json()["status"] == "triggered"
        assert response.json()["scenario"] == "brute_force"

    def test_trigger_c2_beacon(self, client):
        """Trigger C2 beacon scenario."""
        response = client.post("/api/simulate/c2_beacon")
        assert response.status_code == 200
        assert response.json()["scenario"] == "c2_beacon"

    def test_trigger_lateral_movement(self, client):
        """Trigger lateral movement scenario."""
        response = client.post("/api/simulate/lateral_movement")
        assert response.status_code == 200
        assert response.json()["scenario"] == "lateral_movement"

    def test_trigger_data_exfil(self, client):
        """Trigger data exfiltration scenario."""
        response = client.post("/api/simulate/data_exfil")
        assert response.status_code == 200
        assert response.json()["scenario"] == "data_exfil"

    def test_trigger_false_positive(self, client):
        """Trigger false positive scenario."""
        response = client.post("/api/simulate/false_positive")
        assert response.status_code == 200
        assert response.json()["scenario"] == "false_positive"

    def test_trigger_invalid_scenario(self, client):
        """Invalid scenario returns 400."""
        response = client.post("/api/simulate/invalid_scenario")
        assert response.status_code == 400

    def test_trigger_requires_api_key_when_enabled(self, client, monkeypatch):
        """Simulation endpoint enforces API key when auth is enabled."""
        monkeypatch.setattr("main.REQUIRE_AUTH", True)
        monkeypatch.setattr("main.API_KEY", "expected-key")
        response = client.post("/api/simulate/brute_force")
        assert response.status_code == 401

    def test_trigger_accepts_api_key_when_enabled(self, client, monkeypatch):
        """Simulation endpoint accepts valid API key when auth is enabled."""
        monkeypatch.setattr("main.REQUIRE_AUTH", True)
        monkeypatch.setattr("main.API_KEY", "expected-key")
        response = client.post(
            "/api/simulate/brute_force",
            headers={"X-API-Key": "expected-key"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "triggered"

    def test_playbook_requires_api_key_when_enabled(self, client, monkeypatch):
        """Playbook endpoint enforces API key when auth is enabled."""
        state.alerts.clear()
        state.alerts.append({
            "alert_id": "ALT-9999",
            "playbook": FALLBACK_PLAYBOOKS["brute_force"]
        })
        monkeypatch.setattr("main.REQUIRE_AUTH", True)
        monkeypatch.setattr("main.API_KEY", "expected-key")
        response = client.post("/api/alerts/ALT-9999/playbook")
        assert response.status_code == 401


# ─── Test: Log Generator Scenario Injection ──────────────────────────────────

class TestLogGeneratorScenarios:
    def test_trigger_scenario_sets_flag(self):
        """Triggering a scenario sets the internal flag."""
        gen = LogGenerator(events_per_second=5)
        assert gen._manual_scenario is None
        gen.trigger_scenario("brute_force")
        assert gen._manual_scenario == "brute_force"

    def test_pop_manual_batch_brute_force(self):
        """Pop manual batch for brute force returns event."""
        gen = LogGenerator()
        gen.trigger_scenario("brute_force")
        batch = gen._pop_manual_batch()
        assert len(batch) > 0
        assert batch[0].get("label") == "brute_force"

    def test_pop_manual_batch_c2_beacon(self):
        """Pop manual batch for C2 beacon returns event."""
        gen = LogGenerator()
        gen.trigger_scenario("c2_beacon")
        batch = gen._pop_manual_batch()
        assert len(batch) > 0
        assert batch[0].get("label") == "c2_beacon"

    def test_pop_manual_batch_lateral_movement(self):
        """Pop manual batch for lateral movement returns events."""
        gen = LogGenerator()
        gen.trigger_scenario("lateral_movement")
        batch = gen._pop_manual_batch()
        assert len(batch) > 0
        assert any(e.get("label") == "lateral_movement" for e in batch)

    def test_pop_manual_batch_data_exfil(self):
        """Pop manual batch for data exfil returns events."""
        gen = LogGenerator()
        gen.trigger_scenario("data_exfil")
        batch = gen._pop_manual_batch()
        assert len(batch) > 0
        assert any(e.get("label") == "data_exfil" for e in batch)

    def test_pop_manual_batch_false_positive(self):
        """Pop manual batch for false positive returns event."""
        gen = LogGenerator()
        gen.trigger_scenario("false_positive")
        batch = gen._pop_manual_batch()
        assert len(batch) > 0
        assert batch[0].get("label") == "false_positive"

    def test_pop_clears_manual_scenario(self):
        """Popping manual batch clears the flag."""
        gen = LogGenerator()
        gen.trigger_scenario("brute_force")
        assert gen._manual_scenario == "brute_force"
        gen._pop_manual_batch()
        assert gen._manual_scenario is None

    def test_pop_invalid_scenario_returns_empty(self):
        """Popping unknown scenario returns empty list."""
        gen = LogGenerator()
        gen.trigger_scenario("unknown_scenario")
        batch = gen._pop_manual_batch()
        assert batch == []


# ─── Test: Playbook Extraction ───────────────────────────────────────────────

class TestPlaybookExtraction:
    def test_extract_playbook_text_from_valid_response(self):
        """Extract playbook text from valid API response."""
        data = {
            "content": [
                {"text": '{"steps": []}'}
            ]
        }
        text = _extract_playbook_text(data)
        assert text == '{"steps": []}'

    def test_extract_playbook_text_fallback_completion(self):
        """Extract playbook text from completion field."""
        data = {"completion": '{"steps": []}'}
        text = _extract_playbook_text(data)
        assert text == '{"steps": []}'

    def test_extract_playbook_text_fallback_output(self):
        """Extract playbook text from output field."""
        data = {"output": '{"steps": []}'}
        text = _extract_playbook_text(data)
        assert text == '{"steps": []}'

    def test_extract_playbook_text_invalid_response(self):
        """Return None for invalid response."""
        assert _extract_playbook_text(None) is None
        assert _extract_playbook_text({}) is None
        assert _extract_playbook_text({"content": []}) is None


# ─── Test: Playbook Generation with Fallback ────────────────────────────────

class TestPlaybookGeneration:
    @pytest.mark.asyncio
    async def test_generate_playbook_use_llm_false(self, alert_dict):
        """When use_llm=False, return fallback immediately."""
        playbook = await generate_playbook(alert_dict, use_llm=False)
        assert "steps" in playbook
        assert len(playbook["steps"]) == 4
        phases = [s["phase"] for s in playbook["steps"]]
        assert "CONTAIN" in phases
        assert "INVESTIGATE" in phases
        assert "ERADICATE" in phases
        assert "PREVENT" in phases

    @pytest.mark.asyncio
    async def test_generate_playbook_no_api_key(self, alert_dict):
        """When API key is missing, return fallback."""
        with patch("playbook_engine.LLM_ENABLED", False):
            playbook = await generate_playbook(alert_dict, use_llm=True)
            assert "steps" in playbook
            assert len(playbook["steps"]) == 4

    @pytest.mark.asyncio
    async def test_generate_playbook_api_error_fallback(self, alert_dict):
        """When LLM API returns error, fallback gracefully."""
        with patch("playbook_engine.ANTHROPIC_API_KEY", "test-key"), \
             patch("playbook_engine.LLM_ENABLED", True):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = Mock(status_code=500)
                playbook = await generate_playbook(alert_dict, use_llm=True)
                assert "steps" in playbook
                assert len(playbook["steps"]) == 4

    @pytest.mark.asyncio
    async def test_generate_playbook_threat_type_brute_force(self):
        """Fallback playbook for brute force has correct structure."""
        alert = {
            "alert_id": "ALT-0001",
            "threat_type": "brute_force",
            "severity": "High",
            "confidence": 0.9,
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.1.1",
            "description": "Test",
            "why_flagged": "Test",
            "mitre_id": "T1110",
            "mitre_name": "Brute Force",
            "false_positive_score": 0.1,
            "shap_features": []
        }
        playbook = await generate_playbook(alert, use_llm=False)
        assert playbook["escalate_to"] == "SOC Tier 2 / Identity Team"

    @pytest.mark.asyncio
    async def test_generate_playbook_threat_type_c2(self):
        """Fallback playbook for C2 beacon has correct structure."""
        alert = {
            "alert_id": "ALT-0001",
            "threat_type": "c2_beacon",
            "severity": "High",
            "confidence": 0.9,
            "src_ip": "10.0.1.1",
            "dst_ip": "185.220.101.42",
            "description": "Test",
            "why_flagged": "Test",
            "mitre_id": "T1071",
            "mitre_name": "C2",
            "false_positive_score": 0.1,
            "shap_features": []
        }
        playbook = await generate_playbook(alert, use_llm=False)
        assert playbook["escalate_to"] == "SOC Tier 2 / Incident Response Team"

    @pytest.mark.asyncio
    async def test_generate_playbook_malformed_json_fallback(self, alert_dict):
        """When LLM returns malformed JSON, fallback."""
        with patch("playbook_engine.ANTHROPIC_API_KEY", "test-key"), \
             patch("playbook_engine.LLM_ENABLED", True):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "content": [{"text": "not valid json"}]
                }
                mock_post.return_value = mock_response
                playbook = await generate_playbook(alert_dict, use_llm=True)
                assert "steps" in playbook


# ─── Test: State Management ──────────────────────────────────────────────────

class TestStateManagement:
    def test_sentinel_state_initialization(self):
        """SentinelState initializes correctly."""
        test_state = SentinelState()
        assert len(test_state.alerts) == 0
        assert test_state.events_processed == 0
        assert test_state.alerts_total == 0
        assert test_state.engine is not None
        assert test_state.generator is not None

    def test_sentinel_state_get_stats(self):
        """Get stats returns valid structure."""
        test_state = SentinelState()
        stats = test_state.get_stats()
        assert "events_processed" in stats
        assert "alerts_total" in stats
        assert "alerts_active" in stats
        assert "uptime_s" in stats
        assert "eps" in stats

    def test_sentinel_state_alerts_active_count(self):
        """Alert active count calculates correctly."""
        test_state = SentinelState()
        test_state.alerts.append({"severity": "Critical"})
        test_state.alerts.append({"severity": "High"})
        test_state.alerts.append({"severity": "Low"})
        stats = test_state.get_stats()
        assert stats["alerts_active"] == 2


# ─── Test: MITRE Coverage ────────────────────────────────────────────────────

class TestMITRECoverage:
    def test_mitre_endpoint(self, client):
        """MITRE coverage endpoint returns all techniques."""
        response = client.get("/api/mitre")
        assert response.status_code == 200
        data = response.json()
        assert "techniques" in data
        assert len(data["techniques"]) == 4
        technique_ids = {t["id"] for t in data["techniques"]}
        assert "T1110" in technique_ids
        assert "T1021" in technique_ids
        assert "T1048" in technique_ids
        assert "T1071" in technique_ids


# ─── Test: Detection Engine ──────────────────────────────────────────────────

class TestDetectionEngine:
    def test_detection_engine_initialization(self):
        """DetectionEngine initializes correctly."""
        engine = DetectionEngine()
        assert engine.forest is not None
        assert engine.seq is not None
        assert engine.rate_tracker is not None
        assert engine.correlator is not None
        assert engine._trained is False

    def test_detection_engine_process_benign(self):
        """Processing benign event returns None during training."""
        engine = DetectionEngine()
        event = {
            "id": "evt_000001",
            "ts": "2026-04-05T12:00:00Z",
            "layer": "network",
            "src_ip": "10.0.1.1",
            "dst_ip": "10.0.1.2",
            "bytes_out": 100,
            "bytes_in": 500,
            "duration_ms": 100,
            "dst_port": 80,
            "label": "benign"
        }
        alert = engine.process(event)
        # During training phase, should return None
        assert alert is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
