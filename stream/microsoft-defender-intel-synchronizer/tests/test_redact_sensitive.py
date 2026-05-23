"""Regression tests for the OAuth response redaction helper.

The Defender token endpoint returns a 2xx body that contains
``access_token`` (and, on some tenants, ``refresh_token`` /
``id_token``). The connector previously surfaced that whole body
through the error log when a companion field (e.g. ``expires_in``)
was missing, which leaked the bearer into log aggregation. The
``_redact_sensitive`` helper masks those keys in a shallow copy
before the payload is handed to ``connector_logger.error``.

This suite pins the helper's contract so the leak cannot regress:

- Every key in ``_SENSITIVE_RESPONSE_KEYS`` is replaced by the
  literal mask string when its value is non-empty.
- Empty / ``None`` values pass through untouched so operators can
  still tell which fields the upstream did and did not populate.
- Non-sensitive keys (``error``, ``error_description``, ``scope``,
  ``expires_in``, ``token_type``) round-trip unchanged so the
  diagnostic surface is preserved.
- The input dict is not mutated — the caller can keep using the
  live response object.
- Non-dict inputs (``None``, lists, strings) pass through as-is
  so the helper is safe to call on whatever ``response.json()``
  returns.
"""

import pytest
from microsoft_defender_intel_synchronizer_connector.api_handler import (
    _SENSITIVE_RESPONSE_KEYS,
    _redact_sensitive,
)


class TestRedactSensitive:
    """Mask bearer-bearing fields in OAuth response payloads."""

    @pytest.mark.parametrize("key", sorted(_SENSITIVE_RESPONSE_KEYS))
    def test_each_sensitive_key_is_masked(self, key):
        payload = {key: "super-secret-value", "token_type": "Bearer"}
        result = _redact_sensitive(payload)
        assert result[key] == "***redacted***"
        assert result["token_type"] == "Bearer"

    def test_redacts_multiple_sensitive_keys_in_one_payload(self):
        payload = {
            "access_token": "eyJ...bearer...",
            "refresh_token": "1//abc",
            "id_token": "eyJ...id...",
            "client_secret": "shh",
            "client_assertion": "jwt-here",
            "assertion": "saml-here",
            "expires_in": 3599,
            "token_type": "Bearer",
        }
        result = _redact_sensitive(payload)
        for k in _SENSITIVE_RESPONSE_KEYS:
            assert result[k] == "***redacted***"
        assert result["expires_in"] == 3599
        assert result["token_type"] == "Bearer"

    def test_empty_sensitive_values_pass_through(self):
        payload = {"access_token": "", "refresh_token": None, "scope": "openid"}
        result = _redact_sensitive(payload)
        assert result["access_token"] == ""
        assert result["refresh_token"] is None
        assert result["scope"] == "openid"

    def test_non_sensitive_keys_are_preserved(self):
        payload = {
            "error": "invalid_client",
            "error_description": "AADSTS70002: …",
            "error_codes": [70002],
            "timestamp": "2025-01-01 00:00:00Z",
            "trace_id": "abc",
            "correlation_id": "def",
        }
        result = _redact_sensitive(payload)
        assert result == payload

    def test_input_dict_is_not_mutated(self):
        original = {"access_token": "live-bearer", "expires_in": 3599}
        snapshot = dict(original)
        _ = _redact_sensitive(original)
        assert original == snapshot

    @pytest.mark.parametrize("payload", [None, "string", [], 42, 0.1, True])
    def test_non_dict_inputs_round_trip_unchanged(self, payload):
        assert _redact_sensitive(payload) is payload
