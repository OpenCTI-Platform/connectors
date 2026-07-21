"""Circuit open error."""

from .api_error import ApiError


class ApiCircuitOpenError(ApiError):
    """Raised when the circuit breaker is open and the request is blocked."""
