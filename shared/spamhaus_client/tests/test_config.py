"""Tests for the abuse.ch authentication settings (community and Spamhaus)."""

import traceback
from typing import ClassVar

import pytest
from connectors_sdk import (
    ProviderApiAuthenticationError,
    ProviderApiInvalidResponseError,
    ProviderApiServerError,
)
from pydantic import BaseModel, ValidationError
from spamhaus_client import (
    AbuseChAuthConfigMixin,
    SpamhausAuthenticationError,
    SpamhausCommercialError,
    SpamhausInvalidResponseError,
    SpamhausUnavailableError,
    build_user_agent,
)


class _Section(AbuseChAuthConfigMixin, BaseModel):
    """Connector section using the mixin, as a connector settings would."""

    auth_env_prefix: ClassVar[str] = "MYCONN"


class TestAuthModes:
    def test_community_only(self):
        config = _Section(auth_key="community-key")

        assert config.community_configured is True
        assert config.commercial_configured is False

    def test_commercial_only(self):
        config = _Section(spamhaus_username="user@example.com", spamhaus_password="pw")

        assert config.commercial_configured is True
        assert config.community_configured is False

    def test_both_modes_are_allowed_and_commercial_wins(self):
        config = _Section(
            auth_key="community-key",
            spamhaus_username="user@example.com",
            spamhaus_password="pw",
        )

        assert config.commercial_configured is True
        assert config.community_configured is True
        assert config.use_commercial is True

    def test_community_mode_is_used_without_commercial_credentials(self):
        assert _Section(auth_key="community-key").use_commercial is False

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_values_count_as_unset(self, blank):
        config = _Section(
            auth_key="community-key", spamhaus_username=blank, spamhaus_password=blank
        )

        assert config.commercial_configured is False
        assert config.spamhaus_username is None
        assert config.spamhaus_password is None

    def test_blank_auth_key_counts_as_unset(self):
        config = _Section(
            auth_key="  ", spamhaus_username="user@example.com", spamhaus_password="pw"
        )

        assert config.community_configured is False


class TestValidation:
    def test_no_mode_fails_and_names_both_options(self):
        with pytest.raises(ValidationError) as exc_info:
            _Section()

        message = str(exc_info.value)
        assert "MYCONN_AUTH_KEY" in message
        assert "MYCONN_SPAMHAUS_USERNAME" in message
        assert "MYCONN_SPAMHAUS_PASSWORD" in message

    def test_username_without_password_fails(self):
        with pytest.raises(ValidationError) as exc_info:
            _Section(auth_key="community-key", spamhaus_username="user@example.com")

        assert "MYCONN_SPAMHAUS_PASSWORD" in str(exc_info.value)

    def test_password_without_username_fails(self):
        with pytest.raises(ValidationError) as exc_info:
            _Section(auth_key="community-key", spamhaus_password="pw")

        assert "MYCONN_SPAMHAUS_USERNAME" in str(exc_info.value)

    def test_error_message_without_prefix(self):
        class _NoPrefix(AbuseChAuthConfigMixin, BaseModel):
            pass

        with pytest.raises(ValidationError) as exc_info:
            _NoPrefix()

        assert "AUTH_KEY" in str(exc_info.value)

    def test_secrets_are_not_shown_in_repr(self):
        config = _Section(
            auth_key="community-secret",
            spamhaus_username="user@example.com",
            spamhaus_password="pw-secret",
        )

        text = repr(config) + str(config.model_dump())
        assert "community-secret" not in text
        assert "pw-secret" not in text
        assert "user@example.com" not in text


class TestCommunityOverride:
    def test_a_connector_can_widen_what_counts_as_community(self):
        class _Widened(AbuseChAuthConfigMixin, BaseModel):
            export_url: str | None = None

            @property
            def community_configured(self) -> bool:
                return self.auth_key is not None or self.export_url is not None

        config = _Widened(export_url="https://example.com/export.csv")

        assert config.community_configured is True
        assert config.use_commercial is False


class TestUserAgent:
    def test_user_agent_format(self):
        assert build_user_agent("threatfox", "7.261119.0") == (
            "OpenCTI-threatfox/7.261119.0"
        )


class TestErrors:
    def test_authentication_error_is_a_commercial_error(self):
        error = SpamhausAuthenticationError("check the Spamhaus credentials")

        assert isinstance(error, SpamhausCommercialError)
        assert isinstance(error, ProviderApiAuthenticationError)

    def test_unavailable_error_is_a_commercial_error(self):
        error = SpamhausUnavailableError("down")

        assert isinstance(error, SpamhausCommercialError)
        assert isinstance(error, ProviderApiServerError)

    def test_invalid_response_error_is_a_commercial_error(self):
        error = SpamhausInvalidResponseError("bad page")

        assert isinstance(error, SpamhausCommercialError)
        assert isinstance(error, ProviderApiInvalidResponseError)

    def test_commercial_error_is_abstract(self):
        with pytest.raises(TypeError):
            SpamhausCommercialError("abstract")


class TestSecretsInValidationErrors:
    """A failed validation must not echo the raw input, which holds the password."""

    @pytest.mark.parametrize(
        "values",
        [
            {"spamhaus_password": "pw-do-not-leak"},
            {"spamhaus_password": "pw-do-not-leak", "auth_key": "community-key"},
            {"spamhaus_username": "user-do-not-leak"},
            {"spamhaus_username": "user-do-not-leak", "auth_key": "community-key"},
            {"spamhaus_username": "user-do-not-leak", "spamhaus_password": "  "},
        ],
    )
    def test_no_secret_reaches_the_formatted_exception_chain(self, values):
        with pytest.raises(ValidationError) as excinfo:
            _Section(**values)

        formatted = "".join(traceback.format_exception(excinfo.value))
        for secret in ("pw-do-not-leak", "user-do-not-leak", "community-key"):
            assert secret not in formatted
        assert "MYCONN_SPAMHAUS" in formatted  # the message still names the variables

    def test_the_error_still_says_what_is_wrong(self):
        with pytest.raises(ValidationError, match="MYCONN_SPAMHAUS_USERNAME"):
            _Section(spamhaus_password="pw-do-not-leak")
