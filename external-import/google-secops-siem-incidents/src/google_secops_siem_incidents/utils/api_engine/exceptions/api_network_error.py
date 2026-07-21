"""Network connectivity error."""

from .api_error import ApiError


class ApiNetworkError(ApiError):
    """Raised when a network connectivity problem is detected."""

    def __init__(self, message: str) -> None:
        """Initialise with a description of the network failure.

        Args:
            message: Description of the network connectivity problem.
        """
        super().__init__(f"Network connectivity error: {message}")
