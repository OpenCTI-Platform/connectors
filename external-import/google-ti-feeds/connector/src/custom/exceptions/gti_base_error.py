"""Base class for GTI exceptions."""

from typing import Any, Dict, Optional


class GTIBaseError(Exception):
    """Base exception for all GTI-related errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Initialize a GTIBaseError instance."""
        super().__init__(message)
        self.message = message
        self.details = details or {}
