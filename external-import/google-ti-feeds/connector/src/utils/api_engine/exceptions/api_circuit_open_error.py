"""Base class for circuit open errors."""

from .api_error import ApiError


class ApiCircuitOpenError(ApiError):
    """Raised when the circuit is open."""

    pass
