from __future__ import annotations

"""Logging configuration helpers."""

import logging


def configure_logging(level: str) -> None:
    """Configure Python logging using a connector-style log level string."""
    normalized = (level or "info").strip().lower()
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }
    logging.basicConfig(
        level=level_map.get(normalized, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
