"""Attach a host-visible file handler to the root logger for benchmarks."""

from __future__ import annotations

import logging
from pathlib import Path

from pycti.utils.opencti_logger import CustomJsonFormatter

# Match connectors-sdk / pycti JSON log line shape so file logs grep like stdout.
_PYCTI_LOG_RECORD_FORMAT = "%(timestamp)s %(level)s %(name)s %(message)s"


def attach_file_logging(log_file: str, log_level: str | None = None) -> Path:
    """Add a JSON ``FileHandler`` on the root logger if not already present.

    Call this **after** ``OpenCTIConnectorHelper`` / SDK logging setup: those
    steps may replace root handlers with ``force=True``.

    The handler uses ``log_level`` (``CONNECTOR_LOG_LEVEL``). ``error`` keeps
    errors only; ``info`` also writes operational lines and ``[BENCH]`` timings.

    Args:
        log_file: Absolute or relative path inside the container (e.g.
            ``/var/log/checkfirst-connector/connector.log``).
        log_level: Level name such as ``error`` or ``info``. When omitted, the
            root logger's effective level is used.

    Returns:
        Resolved path of the log file.
    """
    path = Path(log_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    level = _resolve_level(log_level)

    root = logging.getLogger()
    for handler in root.handlers:
        if (
            isinstance(handler, logging.FileHandler)
            and Path(handler.baseFilename).resolve() == resolved
        ):
            handler.setLevel(level)
            return resolved

    handler = logging.FileHandler(resolved)
    handler.setLevel(level)
    handler.setFormatter(CustomJsonFormatter(_PYCTI_LOG_RECORD_FORMAT))
    root.addHandler(handler)
    return resolved


def _resolve_level(log_level: str | None) -> int:
    """Map a connector log-level name to a logging level number."""
    if log_level:
        name = log_level.strip().upper()
        mapped = logging.getLevelNamesMapping().get(name)
        if mapped is not None:
            return mapped
    return logging.getLogger().getEffectiveLevel()
