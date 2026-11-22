"""Deprecation notice of the Monty Security C2 Tracker connector.

Single source of truth for every runtime warning about the deprecation of this
connector. ``DEPRECATION_DATE`` is the date the deprecation took effect
(ISO 8601, YYYY-MM-DD).

The module is deliberately not named ``deprecation`` to avoid shadowing the
PyPI package of the same name.
"""

import warnings
from typing import Any, Protocol

DEPRECATION_DATE = "2026-11-17"
REASON = (
    "the upstream MontySecurity C2-Tracker repository is archived and its data "
    "was removed, so the connector no longer imports data"
)
REPLACEMENT = "none"

DEPRECATION_MESSAGE = (
    f"The Monty Security C2 Tracker connector is DEPRECATED since "
    f"{DEPRECATION_DATE} and will be removed in a future release: {REASON}. "
    f"No replacement connector is available."
)


class _ConnectorLogger(Protocol):
    """The part of the pycti ``connector_logger`` used by this module."""

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None: ...


def warn_deprecated() -> None:
    """Emit a ``FutureWarning`` on stderr.

    Meant for the very start of the process, before the configuration is
    validated: a user whose configuration is broken still sees the notice.
    ``FutureWarning`` is shown by default, unlike ``DeprecationWarning``.
    """
    warnings.warn(DEPRECATION_MESSAGE, FutureWarning, stacklevel=2)


def log_deprecation(logger: _ConnectorLogger) -> None:
    """Log the deprecation notice at WARNING level.

    :param logger: The ``connector_logger`` of the OpenCTI connector helper.
    """
    logger.warning(
        "[DEPRECATED] The Monty Security C2 Tracker connector is deprecated "
        "and will be removed",
        {
            "deprecated_since": DEPRECATION_DATE,
            "reason": REASON,
            "replacement": REPLACEMENT,
        },
    )
