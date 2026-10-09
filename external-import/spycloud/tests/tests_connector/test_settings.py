from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from spycloud_connector.settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "spycloud": {
        "api_base_url": "https://api.spycloud.io/enterprise-v2/",
        "api_key": "test-api-key",
    },
}


def build_fake_connector_settings(settings_dict: dict[str, Any]) -> type:
    """Build a `ConnectorSettings` subclass validating `settings_dict` instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "SpyCloud",
                    "scope": "spycloud",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "spycloud": {
                    "api_base_url": "https://api.spycloud.io/enterprise-v2",
                    "api_key": "test-api-key",
                    "severity_levels": "20,25",
                    "watchlist_types": "domain,subdomain",
                    "tlp_level": "red",
                    "import_start_date": "2024-01-01T00:00:00Z",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            MINIMAL_VALID_SETTINGS_DICT,
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    settings = build_fake_connector_settings(settings_dict)()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.spycloud, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """Test that optional fields fall back on the defaults of the legacy configuration."""
    settings = build_fake_connector_settings(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.name == "SpyCloud"
    assert settings.connector.scope == ["spycloud"]
    assert settings.connector.log_level == "debug"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert settings.spycloud.severity_levels == []
    assert settings.spycloud.watchlist_types == []
    assert settings.spycloud.tlp_level == "amber+strict"
    assert (
        datetime.now(UTC) - timedelta(days=30, minutes=1)
        < settings.spycloud.import_start_date
        <= datetime.now(UTC) - timedelta(days=30)
    )


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = build_fake_connector_settings(
        {**MINIMAL_VALID_SETTINGS_DICT, "connector": {}}
    )()

    assert settings.connector.id == "fac85592-0596-437b-8ee2-96e3c23c2fe9"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "spycloud_overrides, expected",
    [
        pytest.param(
            {"api_base_url": "https://api.spycloud.io/enterprise-v2"},
            {"api_base_url": "https://api.spycloud.io/enterprise-v2/"},
            id="api_base_url_without_trailing_slash",
        ),
        pytest.param(
            {"api_base_url": "https://api.spycloud.io/enterprise-v2/"},
            {"api_base_url": "https://api.spycloud.io/enterprise-v2/"},
            id="api_base_url_with_trailing_slash",
        ),
        pytest.param(
            {"severity_levels": " 2, 5 ,20,25, "},
            {"severity_levels": [2, 5, 20, 25]},
            id="severity_levels_from_comma_separated_string",
        ),
        pytest.param(
            {"severity_levels": [20, 25]},
            {"severity_levels": [20, 25]},
            id="severity_levels_from_list",
        ),
        pytest.param(
            {"severity_levels": ""},
            {"severity_levels": []},
            id="severity_levels_from_empty_string",
        ),
        pytest.param(
            {"watchlist_types": "email, domain,subdomain ,ip"},
            {"watchlist_types": ["email", "domain", "subdomain", "ip"]},
            id="watchlist_types_from_comma_separated_string",
        ),
        pytest.param(
            {"watchlist_types": ""},
            {"watchlist_types": []},
            id="watchlist_types_from_empty_string",
        ),
        pytest.param(
            {"import_start_date": "2024-01-01"},
            {"import_start_date": datetime(2024, 1, 1, tzinfo=UTC)},
            id="import_start_date_without_timezone",
        ),
    ],
)
def test_settings_should_parse_spycloud_values(spycloud_overrides, expected):
    """Test that `SPYCLOUD_*` values are parsed and normalized like the legacy configuration."""
    settings = build_fake_connector_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "spycloud": {
                **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                **spycloud_overrides,
            },
        }
    )()

    for field_name, expected_value in expected.items():
        assert getattr(settings.spycloud, field_name) == expected_value


def test_settings_should_parse_relative_import_start_date():
    """An ISO 8601 duration MUST be converted into a date relative to now."""
    settings = build_fake_connector_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "spycloud": {
                **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                "import_start_date": "P7D",
            },
        }
    )()

    assert (
        datetime.now(UTC) - timedelta(days=7, minutes=1)
        < settings.spycloud.import_start_date
        <= datetime.now(UTC) - timedelta(days=7)
    )


def test_settings_should_hide_api_key():
    """The SpyCloud API key MUST be a secret."""
    settings = build_fake_connector_settings(MINIMAL_VALID_SETTINGS_DICT)()

    assert "test-api-key" not in str(settings.spycloud)
    assert settings.spycloud.api_key.get_secret_value() == "test-api-key"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "spycloud": MINIMAL_VALID_SETTINGS_DICT["spycloud"],
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123456},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "every hour"},
            },
            id="invalid_connector_duration_period",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {"api_key": "test-api-key"},
            },
            id="missing_spycloud_api_base_url",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {"api_base_url": "https://api.spycloud.io/"},
            },
            id="missing_spycloud_api_key",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {
                    **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                    "severity_levels": "3,20",
                },
            },
            id="invalid_spycloud_severity_levels",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {
                    **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                    "severity_levels": "high",
                },
            },
            id="non_numeric_spycloud_severity_levels",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {
                    **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                    "watchlist_types": "domain,url",
                },
            },
            id="invalid_spycloud_watchlist_types",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {
                    **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                    "tlp_level": "clear",
                },
            },
            id="invalid_spycloud_tlp_level",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "spycloud": {
                    **MINIMAL_VALID_SETTINGS_DICT["spycloud"],
                    "import_start_date": "yesterday",
                },
            },
            id="invalid_spycloud_import_start_date",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    with pytest.raises(ConfigValidationError) as err:
        build_fake_connector_settings(settings_dict)()

    assert "Error validating configuration" in str(err.value)
