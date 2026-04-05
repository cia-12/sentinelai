"""
SentinelAI — Alert Persistence Layer
SQLite-based alert storage with automatic recovery on startup.
"""
import json
import sqlite3
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from runtime_config import DATABASE_URL, DATA_DIR, PERSIST_ALERTS

logger = logging.getLogger("AlertStore")

# ─── Database initialization ────────────────────────────────────────────────────────────────

DB_PATH = str(DATABASE_URL).replace("sqlite:///", "")
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


def _connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Initialize SQLite database schema."""
    if not PERSIST_ALERTS:
        return
    conn = _connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            alert_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY,
            events_processed INTEGER,
            alerts_total INTEGER,
            uptime_s INTEGER,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


class AlertStore:
    """Manages alert persistence and recovery."""

    @staticmethod
    def _retry(fn, retries=3, delay=0.1):
        for attempt in range(retries):
            try:
                return fn()
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < retries - 1:
                    time.sleep(delay * (attempt + 1))
                    continue
                raise

    @staticmethod
    def save_alert(alert_dict: dict) -> bool:
        """Save an alert to the database."""
        if not PERSIST_ALERTS:
            return True

        def _insert():
            conn = _connect_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO alerts
                (alert_id, ts, threat_type, severity, confidence, src_ip, dst_ip, alert_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_dict.get("alert_id"),
                alert_dict.get("ts"),
                alert_dict.get("threat_type"),
                alert_dict.get("severity"),
                alert_dict.get("confidence"),
                alert_dict.get("src_ip"),
                alert_dict.get("dst_ip"),
                json.dumps(alert_dict)
            ))
            conn.commit()
            rowcount = cursor.rowcount
            conn.close()
            return rowcount

        try:
            inserted = AlertStore._retry(_insert)
            if inserted == 0:
                logger.debug("Alert already persisted: %s", alert_dict.get("alert_id"))
            return True
        except Exception as e:
            logger.warning("[AlertStore] Failed to save alert %s: %s", alert_dict.get("alert_id"), e)
            return False

    @staticmethod
    def get_recent_alerts(limit: int = 100) -> List[dict]:
        """Retrieve recent alerts from database."""
        if not PERSIST_ALERTS:
            return []
        try:
            conn = _connect_db()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT alert_json FROM alerts
                ORDER BY created_at DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [json.loads(row["alert_json"]) for row in rows]
        except Exception as e:
            logger.warning("[AlertStore] Failed to retrieve alerts: %s", e)
            return []

    @staticmethod
    def save_stats(events_processed: int, alerts_total: int, uptime_s: int) -> bool:
        """Save statistics snapshot."""
        if not PERSIST_ALERTS:
            return True

        def _insert():
            conn = _connect_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO stats (events_processed, alerts_total, uptime_s)
                VALUES (?, ?, ?)
            """, (events_processed, alerts_total, uptime_s))
            conn.commit()
            conn.close()
            return cursor.rowcount

        try:
            AlertStore._retry(_insert)
            return True
        except Exception as e:
            logger.warning("[AlertStore] Failed to save stats: %s", e)
            return False

    @staticmethod
    def cleanup_old_alerts(days: int = 7) -> int:
        """Remove alerts older than specified days."""
        if not PERSIST_ALERTS:
            return 0

        def _delete():
            conn = _connect_db()
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM alerts
                WHERE created_at < datetime('now', ? || ' days')
            """, (f"-{days}",))
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return deleted

        try:
            return AlertStore._retry(_delete)
        except Exception as e:
            logger.warning("[AlertStore] Failed to cleanup alerts: %s", e)
            return 0
