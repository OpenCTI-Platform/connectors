"""Rate limit error."""

from .api_error import ApiError


class ApiRateLimitError(ApiError):
    """Raised when the server responds with a rate-limit signal (HTTP 429)."""

    def __init__(self, message: str = "Rate limit exceeded") -> None:
        """Initialise with an optional descriptive message.

        Args:
            message: Human-readable rate limit description.
        """
        super().__init__(message)
