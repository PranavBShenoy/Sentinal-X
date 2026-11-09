"""
Structured logging configuration for SENTINEL-X.

Provides JSON-formatted log entries suitable for log aggregation systems.
Falls back cleanly to standard library logging if structlog is not installed.
IMPORTANT: Never log secrets, tokens, passwords, or repository file contents.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class SafeJSONFormatter(logging.Formatter):
    """Formats log records as JSON with timestamp, level, name, message, and extra fields."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include standard extra attributes if attached
        for key in ("request_id", "assessment_id", "status", "tool", "error"):
            if hasattr(record, key):
                log_obj[key] = getattr(record, key)

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


class StructuredLoggerAdapter(logging.LoggerAdapter):
    """Adapter allowing structlog-style key-value arguments (e.g. logger.info('msg', key=val))."""

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        extra = kwargs.get("extra", {})
        std_kwargs = {"exc_info", "stack_info", "stacklevel", "extra"}
        custom_kwargs = {k: v for k, v in kwargs.items() if k not in std_kwargs}
        for k in list(custom_kwargs.keys()):
            del kwargs[k]
        extra.update(custom_kwargs)
        kwargs["extra"] = extra
        return msg, kwargs


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structured JSON logging for root logger."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeJSONFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Suppress verbose third-party loggers
    for noisy in ["sqlalchemy.engine", "httpx", "uvicorn.access"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str = __name__) -> StructuredLoggerAdapter:
    """Return a logger wrapped with keyword-argument support."""
    base_logger = logging.getLogger(name)
    return StructuredLoggerAdapter(base_logger, {})
