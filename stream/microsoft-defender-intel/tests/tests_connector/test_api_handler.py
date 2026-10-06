"""Tests for :class:`DefenderApiHandler` request building.

Regression coverage for the OData ``$filter`` encoding bug: URL indicators
containing query parameters (``?``, ``&``, ``=``) used to be interpolated raw
into the query string, corrupting the ``$filter`` and producing a 400
"unterminated string literal" from the Defender API on update/delete.
"""

from unittest.mock import MagicMock

from microsoft_defender_intel_connector.api_handler import DefenderApiHandler


def _make_handler() -> DefenderApiHandler:
    """Build a handler with a stubbed request layer (no network / no OAuth)."""
    handler = DefenderApiHandler(
        helper=MagicMock(),
        tenant_id="test-tenant-id",
        client_id="test-client-id",
        client_secret="test-client-secret",
        base_url="https://api.securitycenter.microsoft.com",
        resource_path="api/indicators",
        action="Alert",
        expired_after=30,
    )
    # Bypass _send_request entirely so no token generation / HTTP call happens.
    handler._send_request = MagicMock(return_value={"value": []})
    return handler


def _captured_params(handler: DefenderApiHandler) -> str:
    """Return the ``params`` string passed to the mocked _send_request."""
    _, kwargs = handler._send_request.call_args
    return kwargs["params"]


def test_find_indicators_percent_encodes_reserved_chars():
    """URL indicator values with ?, & and = must be percent-encoded so they
    can't leak into the query-string structure and truncate the $filter."""
    handler = _make_handler()

    handler.find_indicators("https://example.com/path?a=b&c=d&e=f")
    params = _captured_params(handler)

    # The "$filter=" prefix stays literal; the expression is encoded after it.
    assert params.startswith("$filter=")
    encoded = params[len("$filter=") :]

    # No raw reserved character from the value survives in the encoded part.
    assert "&" not in encoded
    assert "?" not in encoded
    assert "=" not in encoded

    # They are present in their percent-encoded form.
    assert "%26" in params  # &
    assert "%3F" in params  # ?
    assert "%3D" in params  # =


def test_find_indicators_escapes_single_quotes_for_odata():
    """Single quotes in the value must be doubled (OData escaping) and then
    percent-encoded, i.e. appear as %27%27."""
    handler = _make_handler()

    handler.find_indicators("o'brien")
    params = _captured_params(handler)

    assert "%27%27" in params
