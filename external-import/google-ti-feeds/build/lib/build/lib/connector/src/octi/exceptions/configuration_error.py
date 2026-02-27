"""Custom exception for configuration errors in the connectors."""

from typing import Any


class ConfigurationError(Exception):
    """Raised when the application configuration is invalid."""

    def __init__(self, message: str, *, errors: Any = None):
        """Initialize the ConfigurationError with a message and original traceback."""
        super().__init__(message)
        self.errors = errors
