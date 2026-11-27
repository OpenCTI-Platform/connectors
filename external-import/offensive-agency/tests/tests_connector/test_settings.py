from datetime import timedelta
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import (
    BaseConfigModel,
    BaseExternalImportConnectorSettings,
    ConfigValidationError,
)


def _settings_from(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_settings_should_be_external_import_connector_settings():
    assert issubclass(ConnectorSettings, BaseExternalImportConnectorSettings) is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "Indicator,Tool",
                    "log_level": "error",
                    "duration_period": "PT12H",
                },
                "offensive_agency": {
                    "api_base_url": "https://example.com/api/v1",
                    "tlp_level": "green",
                    "indicator_validity": "P14D",
                    "create_observables": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = _settings_from(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.offensive_agency, BaseConfigModel) is True


def test_settings_should_have_feed_defaults():
    settings = _settings_from(
        {"opencti": {"url": "http://localhost:8080", "token": "test-token"}}
    )

    assert settings.connector.duration_period == timedelta(hours=6)
    assert settings.connector.scope == ["Indicator", "Tool", "IPv4-Addr"]
    assert (
        str(settings.offensive_agency.api_base_url)
        == "https://www.offensive.agency/api/v1"
    )
    assert settings.offensive_agency.tlp_level == "clear"
    assert settings.offensive_agency.indicator_validity == timedelta(days=30)
    assert settings.offensive_agency.create_observables is True


@pytest.mark.parametrize(
    "offensive_agency, field_name",
    [
        pytest.param({"tlp_level": "purple"}, "tlp_level", id="invalid_tlp_level"),
        pytest.param(
            {"indicator_validity": "PT1H"},
            "indicator_validity",
            id="indicator_validity_under_one_day",
        ),
        pytest.param(
            {"api_base_url": "not a url"}, "api_base_url", id="invalid_api_base_url"
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(offensive_agency, field_name):
    with pytest.raises(ConfigValidationError) as err:
        _settings_from(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "offensive_agency": offensive_agency,
            }
        )

    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)


def test_settings_should_raise_when_opencti_token_is_missing():
    with pytest.raises(ConfigValidationError) as err:
        _settings_from({"opencti": {"url": "http://localhost:8080"}})

    assert "opencti.token" in str(err.value.__cause__)
