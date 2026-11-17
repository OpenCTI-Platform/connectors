"""Deprecation notice of the Mandiant connector.

Single source of truth for every runtime warning about the deprecation of this
connector: the deprecation date and the replacement connector.

The module is deliberately not named ``deprecation`` to avoid shadowing the
PyPI package of the same name.
"""

import warnings
from typing import Any, Protocol

DEPRECATION_DATE = "April 2027"
REPLACEMENT = "google-ti-feeds"

DEPRECATION_MESSAGE = (
    f"The Mandiant connector is DEPRECATED, effective {DEPRECATION_DATE}, and will "
    f"be removed in a future release. Migrate to {REPLACEMENT}."
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
        "[DEPRECATED] The Mandiant connector is deprecated and will be removed",
        {
            "deprecation_date": DEPRECATION_DATE,
            "replacement": REPLACEMENT,
        },
    )
