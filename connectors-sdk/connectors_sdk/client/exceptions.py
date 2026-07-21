"""Custom exceptions for the HTTP client."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any


class ApiClientError(Exception):
    """Base exception for API client errors.

    Attributes:
        status_code: HTTP status code (if available).
        response_body: Raw response body (if available).
    """

    status_code: int | None = None

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_body: Any = None,
    ) -> None:
        """Initialize with message, optional status code and response body."""
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code
        self.response_body = response_body


class ApiUnauthorizedError(ApiClientError):
    """Raised on 401 responses."""

    status_code: int | None = 401


class ApiForbiddenError(ApiClientError):
    """Raised on 403 responses."""

    status_code: int | None = 403


class ApiNotFoundError(ApiClientError):
    """Raised on 404 responses."""

    status_code: int | None = 404


class ApiRateLimitError(ApiClientError):
    """Raised on 429 responses.

    Attributes:
        retry_after: Number of seconds to wait before retrying (from Retry-After header).
    """

    status_code: int | None = 429

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_body: Any = None,
        retry_after: float | None = None,
    ) -> None:
        """Initialize with message, status code, response body, and retry delay."""
        super().__init__(message, status_code=status_code, response_body=response_body)
        self.retry_after = retry_after

    @staticmethod
    def parse_retry_after(headers: dict[str, str]) -> float | None:
        """Extract Retry-After value in seconds from response headers.

        Handles both delta-seconds and HTTP-date formats per RFC 9110.
        """
        retry_after = headers.get("Retry-After")
        if retry_after is None:
            return None
        try:
            return float(retry_after)
        except (ValueError, TypeError):
            pass
        # Try HTTP-date format (e.g. "Wed, 21 Oct 2015 07:28:00 GMT")
        try:
            dt = parsedate_to_datetime(retry_after)
            now = datetime.now(tz=timezone.utc)
            delta: float = (dt - now).total_seconds()
            return max(delta, 0)
        except (ValueError, TypeError):
            return None


class ApiServerError(ApiClientError):
    """Raised on 5xx responses."""
