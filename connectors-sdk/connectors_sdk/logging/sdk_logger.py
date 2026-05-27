"""Internal logger used for logging inside the connectors-sdk private modules."""

from __future__ import annotations

from connectors_sdk.logging._base_logger import BaseLogger


class SDKLogger(BaseLogger):
    r"""Logger for connectors-sdk internal/private modules.

    Logs immediately to stderr via a `StreamHandler` using `CustomJsonFormatter` (same format as pycti's `AppLogger`).
    The log level is determined by connector's configuration (see `BaseLogger` for more details).

    /!\\ This logger is intended to log internally within the connectors-sdk,
    it shouldn't be used by connectors directly (for that, see `Logger`).

    Example:
        >>> from connectors_sdk.logging.sdk_logger import sdk_logger # anywhere in the codebase, at any time
        >>> sdk_logger.info("Works even if pycti is not available yet")
        ... # Output to stderr (in JSON format):
        ... # {
        ... #     "timestamp": "2026-01-01T00:00:00Z",
        ... #     "level": "INFO",
        ... #     "name": "connectors_sdk",
        ... #     "message": "Works even if pycti is not available yet"
        ... # }
    """

    def __init__(self, name: str = "connectors_sdk") -> None:
        """Set up logger with the default `StreamHandler` handler."""
        if not name.startswith("connectors_sdk"):
            raise ValueError("SDKLogger name must start with 'connectors_sdk'")

        super().__init__(name=name)


# For convenience, this module provides a default logger instance,
# but `SDKLogger` can also be instantiated directly if needed (e.g. for testing purpose).
sdk_logger = SDKLogger()
