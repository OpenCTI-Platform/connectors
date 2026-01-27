"""API network error exception."""

from .api_error import ApiError


class ApiNetworkError(ApiError):
    """Exception raised specifically for network connectivity issues.

    This class is used to differentiate network connectivity issues (like DNS resolution failures,
    connection refused, etc.) from other types of API errors.
    """

    def __init__(self, message: str):
        """Initialize the network error with a message.

        Args:
            message (str): Descriptive message about the network error

        """
        super().__init__(f"Network connectivity error: {message}")
