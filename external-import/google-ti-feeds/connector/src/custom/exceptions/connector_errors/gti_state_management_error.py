"""Exception for errors related to state management in the connector."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIStateManagementError(GTIBaseError):
    """Exception raised when there's an error managing connector state."""

    def __init__(
        self,
        message: str,
        state_key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            state_key: State key that was being accessed or modified
            details: Additional details about the error

        """
        if state_key:
            error_msg = "State management error for key: {message}"
        else:
            error_msg = message

        super().__init__(error_msg)
        self.state_key = state_key
        self.details = details or {}

        # Add structured data for logging
        if state_key:
            self.details.update(
                {
                    "state_key": state_key,
                    "original_message": message,
                }
            )
