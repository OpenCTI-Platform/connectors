"""HTTP client base of the hunt connectors.

A hunt run has a time budget (``limits.timeout_seconds``): every call to the
platform API must stay within it, and every failure must surface as a hunt
error whose message explains what the platform answered, so that the run
report is actionable.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import requests
from connectors_sdk.client.base_client_api import BaseClientApi
from connectors_sdk.client.exceptions import ApiClientError
from connectors_sdk.connectors.internal_hunt.errors import (
    HuntExecutionError,
    HuntTimeoutError,
)
from connectors_sdk.connectors.internal_hunt.timing import RunDeadline

API_ERROR_MAX_LENGTH = 500
"""Maximum length of the platform error message kept in a hunt error."""

RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
"""HTTP statuses of the transient failures retried by ``hunt_request``."""

RETRY_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PUT", "TRACE"})
"""Idempotent methods retried by ``hunt_request`` (a search job is never sent twice)."""

_MESSAGE_KEYS = ("message", "reason", "error_description", "detail", "text", "msg")
_NESTED_KEYS = ("error", "errors", "messages", "root_cause", "innererror")
_MAX_DEPTH = 4


def _find_message(body: Any, depth: int = 0) -> str | None:
    """Find the human-readable message of a decoded API error body."""
    if depth > _MAX_DEPTH:
        return None
    if isinstance(body, str):
        return body.strip() or None
    if isinstance(body, list):
        parts = [_find_message(item, depth + 1) for item in body]
        return "; ".join(part for part in parts if part) or None
    if isinstance(body, Mapping):
        for key in _MESSAGE_KEYS:
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for key in _NESTED_KEYS:
            found = _find_message(body.get(key), depth + 1)
            if found:
                return found
    return None


def api_error_message(body: Any, max_length: int = API_ERROR_MAX_LENGTH) -> str | None:
    """Extract a readable, size-capped message from an API error body.

    Common error shapes are recognized (``{"message": ...}``,
    ``{"error": {"reason": ...}}``, ``{"messages": [{"text": ...}]}``...);
    other bodies are serialized as JSON.

    Args:
        body: Decoded error body (JSON value or text), or ``None``.
        max_length: Maximum length of the message.

    Returns:
        The message on a single line, or ``None`` when the body is empty.
    """
    message = _find_message(body)
    if message is None and body not in (None, "", {}, []):
        message = json.dumps(body, sort_keys=True, default=str)
    if not message:
        return None
    return " ".join(message.split())[:max_length]


class HuntApiClient(BaseClientApi):
    """Base client of the platform APIs queried by hunt connectors.

    ``hunt_request`` bounds every call with the run deadline and turns HTTP and
    network failures into hunt errors. It retries transient failures of
    idempotent calls with exponential (or ``Retry-After``) backoff, re-checking
    the deadline before every attempt; the session adapter does not retry, as
    its retries would each reuse the full request timeout past the deadline.

    Examples:
        >>> class MySiemClient(HuntApiClient):
        ...     def search(self, query: str, deadline: RunDeadline) -> Any:
        ...         return self.hunt_request(
        ...             "POST", "/search", deadline, "The search", json={"q": query}
        ...         )
    """

    def __init__(
        self,
        base_url: str,
        *,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        **kwargs: Any,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: Base URL of the platform API.
            max_retries: Maximum number of retries of a transient failure.
            backoff_factor: Multiplier of the exponential backoff between retries.
            **kwargs: Other ``BaseClientApi`` arguments (``ssl_verify``...).
        """
        super().__init__(
            base_url, max_retries=0, backoff_factor=backoff_factor, **kwargs
        )
        self._hunt_max_retries = max_retries

    def _retry_delay(self, method: str, attempt: int, error: Exception) -> float | None:
        """Return the backoff before retrying a failed call, or ``None``."""
        if method.upper() not in RETRY_METHODS or attempt >= self._hunt_max_retries:
            return None
        if isinstance(error, ApiClientError):
            if error.status_code not in RETRY_STATUSES:
                return None
            retry_after = getattr(error, "retry_after", None)
            if retry_after is not None:
                return float(retry_after)
        elif not isinstance(error, requests.ConnectionError):
            return None
        return float(self._backoff_factor * 2**attempt)

    def hunt_request(
        self,
        method: str,
        path: str,
        deadline: RunDeadline,
        operation: str,
        *,
        max_timeout: float = 60.0,
        **kwargs: Any,
    ) -> Any:
        """Call the platform API within the run deadline.

        Args:
            method: HTTP method.
            path: Path relative to the base URL (or an absolute URL).
            deadline: Run deadline bounding the call.
            operation: Description of the call, used in error messages.
            max_timeout: Upper bound of the request timeout in seconds.
            **kwargs: Arguments forwarded to ``requests`` (``params``, ``json``...).

        Returns:
            The decoded response body (``None`` for 204 answers).

        Raises:
            HuntTimeoutError: If the deadline is reached or the call times out.
            HuntExecutionError: If the platform rejects the call or cannot be reached.
        """
        attempt = 0
        while True:
            deadline.check(operation)
            kwargs["timeout"] = deadline.request_timeout(max_timeout)
            try:
                return self._request(method, path, **kwargs)
            except requests.Timeout as err:
                raise HuntTimeoutError(
                    f"{operation} did not answer within the run timeout."
                ) from err
            except (ApiClientError, requests.RequestException) as err:
                delay = self._retry_delay(method, attempt, err)
                if delay is None or delay >= deadline.remaining():
                    raise self._hunt_error(operation, err) from err
            deadline.sleep(delay)
            attempt += 1

    @staticmethod
    def _hunt_error(operation: str, error: Exception) -> HuntExecutionError:
        """Build the hunt error of a failed platform call."""
        if isinstance(error, ApiClientError):
            details = api_error_message(error.response_body)
            suffix = f": {details}" if details else ""
            return HuntExecutionError(f"{operation} failed ({error}){suffix}")
        return HuntExecutionError(
            f"{operation} failed: {type(error).__name__}: {error}"
        )

    def cleanup_request(
        self,
        method: str,
        path: str,
        operation: str,
        *,
        timeout: float = 10.0,
        **kwargs: Any,
    ) -> str | None:
        """Send a best-effort cleanup call (cancel or delete a platform job).

        Cleanup runs after the run outcome is known (or after a timeout), so it
        never raises: the caller logs the returned error.

        Args:
            method: HTTP method.
            path: Path relative to the base URL.
            operation: Description of the call, used in the error message.
            timeout: Request timeout in seconds.
            **kwargs: Arguments forwarded to ``requests``.

        Returns:
            The error message when the call failed, else ``None``.
        """
        kwargs["timeout"] = timeout
        try:
            self._request(method, path, **kwargs)
        except (ApiClientError, requests.RequestException) as err:
            return f"{operation} failed: {err}"
        return None
