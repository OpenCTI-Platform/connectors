"""Checks shared by every CrowdStrike API call."""

from typing import Any

from crowdstrike_indicators.errors import CrowdStrikeAPIError

NO_ERROR_MESSAGE = "no error message returned by CrowdStrike API"


def api_error_message(body: Any) -> str:
    """Extract the first error message of a CrowdStrike response body.

    The upstream shape is not guaranteed: ``body`` or ``errors`` may be
    missing, ``None``, not a list, or hold a non-dict entry.
    """
    errors = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errors, list | tuple) or not errors:
        return NO_ERROR_MESSAGE
    first_error = errors[0]
    message = first_error.get("message") if isinstance(first_error, dict) else None
    return str(message) if message else NO_ERROR_MESSAGE


def response_body(response: Any) -> dict[str, Any]:
    """Return the body of a FalconPy response, or raise its error.

    FalconPy returns ``{"status_code": ..., "headers": ..., "body": ...}``.
    A body that is not a dict reads as an empty one.

    :raises CrowdStrikeAPIError: when the status code is 400 or above, or is
        not an integer (status 0 then: an unexpected shape is never read as
        an empty success).
    """
    status_code = response.get("status_code") if isinstance(response, dict) else None
    body = response.get("body") if isinstance(response, dict) else None
    if not isinstance(status_code, int):
        raise CrowdStrikeAPIError(0, api_error_message(body))
    if status_code >= 400:
        raise CrowdStrikeAPIError(status_code, api_error_message(body))
    return body if isinstance(body, dict) else {}
