"""
SentinelAI — Structured Logging
Centralized logging with file + console output.
"""
import logging
from logging.handlers import RotatingFileHandler
from runtime_config import LOG_LEVEL, LOG_FILE, LOG_FORMAT


def setup_logging():
    """Configure structured logging for the application."""
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    return root_logger


# Initialize logger
logger = setup_logging()
