"""Per-source logger wrapper.

Source modules should not hardcode a bracketed prefix (e.g. ``[BOTNET]``) in
every log call: that is repetitive and lets the label drift from the source
(which is how a ``[NIST NVD-2]`` line once leaked into vulncheck-nvd2 output).

``SourceLogger`` wraps the connector's logger and prepends a single ``[label]``
taken from one place (the source registry), so call sites just log plain
messages. It mirrors the ``info/debug/warning/error`` interface of pycti's logger
(and ``connectors_sdk.ConnectorLogger``).
"""

from typing import Any


class SourceLogger:
    """Delegating logger that prefixes every message with ``[label] ``."""

    def __init__(self, logger: Any, label: str) -> None:
        self._logger = logger
        self._prefix = f"[{label}] "

    def info(self, message: str, meta: dict[str, Any] | None = None) -> None:
        self._logger.info(f"{self._prefix}{message}", meta)

    def debug(self, message: str, meta: dict[str, Any] | None = None) -> None:
        self._logger.debug(f"{self._prefix}{message}", meta)

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None:
        self._logger.warning(f"{self._prefix}{message}", meta)

    def error(self, message: str, meta: dict[str, Any] | None = None) -> None:
        self._logger.error(f"{self._prefix}{message}", meta)
