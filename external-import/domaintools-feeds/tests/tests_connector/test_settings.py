from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "domaintools": {
        "api_base_url": "https://api.domaintools.com",
        "api_key": "test-api-key",
        "feed_type": "nod",
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com",
                    "api_key": "test-api-key",
                    "feed_type": "domainrisk",
                    "session_id": "OpenCTI-DomainTools-Feeds",
                    "domain": "*bank*",
                    "top": 10,
                    "tlp_level": "amber+strict",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.domaintools, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "domaintools": MINIMAL_VALID_SETTINGS_DICT["domaintools"],
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "domaintools": MINIMAL_VALID_SETTINGS_DICT["domaintools"],
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "domaintools": {
                    **MINIMAL_VALID_SETTINGS_DICT["domaintools"],
                    "feed_type": "unknown",
                },
            },
            id="invalid_feed_type",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "domaintools": {
                    **MINIMAL_VALID_SETTINGS_DICT["domaintools"],
                    "top": 0,
                },
            },
            id="invalid_top",
        ),
        *[
            pytest.param(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "domaintools": {
                        key: value
                        for key, value in MINIMAL_VALID_SETTINGS_DICT[
                            "domaintools"
                        ].items()
                        if key != missing_key
                    },
                },
                id=f"missing_domaintools_{missing_key}",
            )
            for missing_key in ("api_key", "feed_type")
        ],
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "7eae6a8d-4c09-424f-822d-bc2529680596"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_apply_defaults():
    """Optional settings MUST fall back on their documented defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "domaintools": {
                        key: value
                        for key, value in MINIMAL_VALID_SETTINGS_DICT[
                            "domaintools"
                        ].items()
                        if key != "api_base_url"
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.connector.name == "DomainToolsFeedsConnector"
    assert settings.connector.scope == ["domaintools-feeds"]
    assert settings.connector.duration_period == timedelta(hours=1)
    assert str(settings.domaintools.api_base_url) == "https://api.domaintools.com/"
    assert settings.domaintools.session_id == "OpenCTI-DomainTools-Feeds"
    assert settings.domaintools.domain is None
    assert settings.domaintools.top is None
    assert settings.domaintools.tlp_level == "clear"
