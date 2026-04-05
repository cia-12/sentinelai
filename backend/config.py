"""
SentinelAI — Configuration Management
Centralized settings with environment variable override support.
"""
import os
from pathlib import Path

# ─── Base directories ────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# ─── API configuration ──────────────────────────────────────────────────────

API_HOST = os.getenv("SENTINEL_HOST", "0.0.0.0")
API_PORT = int(os.getenv("SENTINEL_PORT", 8000))
API_RELOAD = os.getenv("SENTINEL_RELOAD", "False").lower() == "true"

# ─── Database configuration ──────────────────────────────────────────────────

DATABASE_URL = os.getenv("SENTINEL_DB_URL", f"sqlite:///{DATA_DIR}/sentinelai.db")

# ─── Authentication configuration ──────────────────────────────────────────

API_KEY = os.getenv("SENTINEL_API_KEY", "demo-key-change-in-production")
REQUIRE_AUTH = os.getenv("SENTINEL_REQUIRE_AUTH", "True").lower() == "true"

# ─── Event generation configuration ──────────────────────────────────────────

EVENTS_PER_SECOND = int(os.getenv("SENTINEL_EPS", 6))
ALERTS_MAXLEN = int(os.getenv("SENTINEL_ALERTS_MAXLEN", 500))

# ─── Detection configuration ──────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = int(os.getenv("SENTINEL_BRUTE_THRESHOLD", 50))
C2_BEACON_THRESHOLD = float(os.getenv("SENTINEL_C2_THRESHOLD", 0.55))
ISOLATION_FOREST_CONTAMINATION = float(os.getenv("SENTINEL_IF_CONTAMINATION", 0.08))

# ─── Logging configuration ──────────────────────────────────────────────────

LOG_LEVEL = os.getenv("SENTINEL_LOG_LEVEL", "INFO")
LOG_FILE = DATA_DIR / "sentinelai.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ─── LLM configuration ──────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
LLM_ENABLED = bool(ANTHROPIC_API_KEY)
LLM_MODEL = "claude-sonnet-4-20250514"

# ─── Metrics configuration ──────────────────────────────────────────────────

METRICS_ENABLED = os.getenv("SENTINEL_METRICS", "True").lower() == "true"

# ─── Feature flags ──────────────────────────────────────────────────────────

PERSIST_ALERTS = os.getenv("SENTINEL_PERSIST", "True").lower() == "true"
DEMO_MODE = os.getenv("SENTINEL_DEMO_MODE", "True").lower() == "true"
