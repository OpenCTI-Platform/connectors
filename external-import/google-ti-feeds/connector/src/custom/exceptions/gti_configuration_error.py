"""Exception raised for errors in the configuration."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIConfigurationError(GTIBaseError):
    """Exception raised for GTI configuration errors."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize a GTIConfigurationError instance."""
        super().__init__(message, details)
        self.config_key = config_key
