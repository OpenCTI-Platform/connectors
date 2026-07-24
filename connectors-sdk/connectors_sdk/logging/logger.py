"""Logger to be used within a connector."""

from connectors_sdk.logging._base_logger import BaseLogger


class Logger(BaseLogger):
    """Logger to use within a connector.
    Logs to stderr via a `StreamHandler` using `CustomJsonFormatter` (same format as pycti's `AppLogger`).
    The log level is determined by connector's configuration, with the following precedence:
        1. `CONNECTOR_LOG_LEVEL` environment variable
        2. `connector.log_level` field in `config.yml`
        3. `CONNECTOR_LOG_LEVEL` field in `.env` file
        4. Default to `"ERROR"` if none of the above is found or if the value is invalid.

    Example:
        >>> from connectors_sdk import Logger
        >>> logger = Logger("my_connector")
        >>> logger.info("This is an info message")
        ... # Output to stderr (in JSON format):
        ... # {
        ... #     "timestamp": "2026-01-01T00:00:00Z",
        ... #     "level": "INFO",
        ... #     "name": "my_connector",
        ... #     "message": "This is an info message"
        ... # }
    """

    def __init__(self, name: str) -> None:
        """Set up logger with default handler and formatter."""
        super().__init__(name=name)
