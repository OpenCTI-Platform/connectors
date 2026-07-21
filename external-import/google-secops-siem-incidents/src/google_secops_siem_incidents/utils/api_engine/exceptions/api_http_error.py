"""HTTP error with status code."""

from .api_error import ApiError


class ApiHttpError(ApiError):
    """Raised when the server returns an HTTP error status code."""

    def __init__(self, message: str, status_code: int) -> None:
        """Initialise with a message and the HTTP status code.

        Args:
            message: Human-readable error description.
            status_code: HTTP status code returned by the server.
        """
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}: {message}")
