"""Unit tests for ``teamt5_connector.settings.TeamT5Config``.

Pins the auth-required validator: at least one usable authentication
path (``api_key`` OR both ``client_id`` + ``client_secret``) must be
configured before the connector starts. Empty / whitespace-only
``SecretStr`` values count as unset — pins the Copilot review thread
on ``settings.py:83`` (Compose deployments commonly materialise an
unset env var as ``""`` rather than ``None``, and the previous
``is not None`` check let those empties through validation, so the
connector silently started without any auth header and only crashed
at the first API call).
"""

import pytest
from pydantic import SecretStr, ValidationError
from teamt5_connector.settings import TeamT5Config


class TestRequireSomeAuthentication:
    """At least one populated auth path is required."""

    def test_neither_path_is_rejected(self):
        with pytest.raises(ValidationError) as exc:
            TeamT5Config()
        message = str(exc.value)
        assert "api_key" in message
        assert "client_id" in message
        assert "client_secret" in message

    def test_api_key_alone_is_accepted(self):
        cfg = TeamT5Config(api_key=SecretStr("k"))
        assert cfg.api_key.get_secret_value() == "k"

    def test_oauth_pair_alone_is_accepted(self):
        cfg = TeamT5Config(
            client_id=SecretStr("cid"),
            client_secret=SecretStr("csec"),
        )
        assert cfg.client_id.get_secret_value() == "cid"
        assert cfg.client_secret.get_secret_value() == "csec"

    def test_oauth_only_one_half_set_is_rejected(self):
        # ``client_id`` set but ``client_secret`` missing — must fail.
        with pytest.raises(ValidationError):
            TeamT5Config(client_id=SecretStr("cid"))
        # ``client_secret`` set but ``client_id`` missing — must fail.
        with pytest.raises(ValidationError):
            TeamT5Config(client_secret=SecretStr("csec"))


class TestEmptySecretsAreTreatedAsMissing:
    """Pins the Copilot review thread on ``settings.py:83``.

    ``SecretStr("")`` is not None — Pydantic accepts the empty
    string as a populated value — so the previous ``is not None``
    check let empty-env-var Compose deployments through validation.
    The validator now treats empty / whitespace-only secrets as
    missing so the operator sees the actionable startup error this
    validator is supposed to produce, instead of a silent no-auth
    start that fails at the first API call.
    """

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty_string"),
            pytest.param("   ", id="whitespace_only"),
            pytest.param("\t\n", id="whitespace_chars"),
        ],
    )
    def test_empty_api_key_is_rejected(self, value):
        with pytest.raises(ValidationError) as exc:
            TeamT5Config(api_key=SecretStr(value))
        assert "empty" in str(exc.value).lower() or "api_key" in str(exc.value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty_string"),
            pytest.param("   ", id="whitespace_only"),
        ],
    )
    def test_empty_oauth_credentials_are_rejected(self, value):
        # Both empty.
        with pytest.raises(ValidationError):
            TeamT5Config(
                client_id=SecretStr(value),
                client_secret=SecretStr(value),
            )
        # Only ``client_id`` empty.
        with pytest.raises(ValidationError):
            TeamT5Config(
                client_id=SecretStr(value),
                client_secret=SecretStr("real-secret"),
            )
        # Only ``client_secret`` empty.
        with pytest.raises(ValidationError):
            TeamT5Config(
                client_id=SecretStr("real-id"),
                client_secret=SecretStr(value),
            )

    def test_mixed_empty_oauth_plus_valid_api_key_is_accepted(self):
        """Empty OAuth credentials don't disqualify a valid api_key fallback."""
        cfg = TeamT5Config(
            api_key=SecretStr("real-key"),
            client_id=SecretStr(""),
            client_secret=SecretStr(""),
        )
        assert cfg.api_key.get_secret_value() == "real-key"
