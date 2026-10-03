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
    network failures into hunt errors. Retries with backoff on 429 and 5xx
    answers are inherited from ``BaseClientApi``.

    Examples:
        >>> class MySiemClient(HuntApiClient):
        ...     def search(self, query: str, deadline: RunDeadline) -> Any:
        ...         return self.hunt_request(
        ...             "POST", "/search", deadline, "The search", json={"q": query}
        ...         )
    """

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
        deadline.check(operation)
        kwargs["timeout"] = deadline.request_timeout(max_timeout)
        try:
            return self._request(method, path, **kwargs)
        except ApiClientError as err:
            details = api_error_message(err.response_body)
            suffix = f": {details}" if details else ""
            raise HuntExecutionError(f"{operation} failed ({err}){suffix}") from err
        except requests.Timeout as err:
            raise HuntTimeoutError(
                f"{operation} did not answer within the run timeout."
            ) from err
        except requests.RequestException as err:
            raise HuntExecutionError(
                f"{operation} failed: {type(err).__name__}: {err}"
            ) from err

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
