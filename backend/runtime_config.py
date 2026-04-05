"""
SentinelAI runtime configuration.
"""
import os
from pathlib import Path


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


def _load_env_file() -> None:
    """Load backend/.env without overriding exported environment variables."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ[key] = value


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, "true" if default else "false").strip().lower() == "true"


def _env_csv(name: str, default: list[str]) -> list[str]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    values = [item.strip() for item in raw_value.split(",") if item.strip()]
    return values or default


def _is_placeholder_secret(value: str) -> bool:
    return value.strip() in {"", "sk-ant-...", "your-api-key-here"}


_load_env_file()

DEMO_MODE = _env_bool("SENTINEL_DEMO_MODE", True)
PERSIST_ALERTS = _env_bool("SENTINEL_PERSIST", True)
METRICS_ENABLED = _env_bool("SENTINEL_METRICS", True)

API_HOST = os.getenv("SENTINEL_HOST", "0.0.0.0")
API_PORT = int(os.getenv("SENTINEL_PORT", 8000))
API_RELOAD = _env_bool("SENTINEL_RELOAD", False)

_default_cors_origins = ["*"] if DEMO_MODE else [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS_ORIGINS = _env_csv("SENTINEL_CORS_ORIGINS", _default_cors_origins)
CORS_ALLOW_CREDENTIALS = CORS_ORIGINS != ["*"]

DATABASE_URL = os.getenv("SENTINEL_DB_URL", f"sqlite:///{DATA_DIR}/sentinelai.db")

API_KEY = os.getenv("SENTINEL_API_KEY", "demo-key-change-in-production")
REQUIRE_AUTH = _env_bool("SENTINEL_REQUIRE_AUTH", not DEMO_MODE)

EVENTS_PER_SECOND = int(os.getenv("SENTINEL_EPS", 6))
ALERTS_MAXLEN = int(os.getenv("SENTINEL_ALERTS_MAXLEN", 500))

BRUTE_FORCE_THRESHOLD = int(os.getenv("SENTINEL_BRUTE_THRESHOLD", 50))
C2_BEACON_THRESHOLD = float(os.getenv("SENTINEL_C2_THRESHOLD", 0.55))
ISOLATION_FOREST_CONTAMINATION = float(os.getenv("SENTINEL_IF_CONTAMINATION", 0.08))

LOG_LEVEL = os.getenv("SENTINEL_LOG_LEVEL", "INFO")
LOG_FILE = DATA_DIR / "sentinelai.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
LLM_ENABLED = not _is_placeholder_secret(ANTHROPIC_API_KEY)
LLM_MODEL = os.getenv("SENTINEL_LLM_MODEL", "claude-sonnet-4-20250514")
