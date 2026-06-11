"""Custom exceptions for the HTTP client."""

from __future__ import annotations

from typing import Any


class ApiClientError(Exception):
    """Base exception for API client errors.

    Attributes:
        status_code: HTTP status code (if available).
        response_body: Raw response body (if available).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_body: Any = None,
    ) -> None:
        """Initialize with message, optional status code and response body."""
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class ApiUnauthorizedError(ApiClientError):
    """Raised on 401 responses."""


class ApiForbiddenError(ApiClientError):
    """Raised on 403 responses."""


class ApiNotFoundError(ApiClientError):
    """Raised on 404 responses."""


class ApiRateLimitError(ApiClientError):
    """Raised on 429 responses.

    Attributes:
        retry_after: Number of seconds to wait before retrying (from Retry-After header).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = 429,
        response_body: Any = None,
        retry_after: float | None = None,
    ) -> None:
        """Initialize with message, status code, response body, and retry delay."""
        super().__init__(message, status_code=status_code, response_body=response_body)
        self.retry_after = retry_after


class ApiServerError(ApiClientError):
    """Raised on 5xx responses."""
