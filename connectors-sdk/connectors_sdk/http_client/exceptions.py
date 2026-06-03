"""Custom exceptions for the HTTP client."""

from __future__ import annotations

from typing import Any


class HttpClientException(Exception):
    """Base exception for HTTP client errors."""


class HttpClientRateLimitError(HttpClientException):
    """Raised when the rate limit configured on HTTP client is exceeded."""


class HttpRequestError(HttpClientException):
    """Base exception for HTTP client errors.

    Attributes:
        status_code: HTTP status code (if available).
        response_body: Raw response body (if available).
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: Any = None,
    ) -> None:
        """Initialize with message, optional status code and response body."""
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class HttpRequestClientError(HttpRequestError):
    """Raised on 4xx responses."""

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: Any = None,
    ) -> None:
        """Initialize with message, optional status code and response body."""
        if status_code >= 400 and status_code < 500:
            super().__init__(
                message, status_code=status_code, response_body=response_body
            )

        raise ValueError("HttpClientError must have a 4xx status code")


class HttpRequestServerError(HttpRequestError):
    """Raised on 5xx responses."""

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: Any = None,
    ) -> None:
        """Initialize with message, optional status code and response body."""
        if status_code >= 500 and status_code < 600:
            super().__init__(
                message, status_code=status_code, response_body=response_body
            )

        raise ValueError("HttpServerError must have a 5xx status code")
