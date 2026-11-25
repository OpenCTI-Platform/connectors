from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "rst_noise_control": {"api_key": "test-api-key"},
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict, without reading env vars or files."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Noise Control",
                    "scope": "IPv4-Addr,Domain-Name,Url,StixFile,indicator",
                    "log_level": "info",
                    "auto": True,
                    "max_tlp": "TLP:GREEN",
                },
                "rst_noise_control": {
                    "base_url": "https://api.example.com/v1",
                    "api_key": "test-api-key",
                    "timeout": 30,
                    "update_confidence": False,
                    "update_score": False,
                    "change_action_score_change": 5,
                    "drop_action_score_change": 25,
                    "drop_action_detection_flag": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` accepts valid input.
    """
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.rst_noise_control, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """
    Test that `ConnectorSettings` applies the documented defaults.
    """
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "RST Noise Control"
    assert settings.connector.scope == [
        "IPv4-Addr",
        "Domain-Name",
        "Url",
        "StixFile",
        "indicator",
    ]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.auto is False
    assert settings.connector.log_level == "error"
    assert settings.connector.max_tlp == TLPLevel.AMBER_STRICT
    assert settings.rst_noise_control.base_url == "https://api.rstcloud.net/v1"
    assert settings.rst_noise_control.api_key.get_secret_value() == "test-api-key"
    assert settings.rst_noise_control.timeout == 10
    assert settings.rst_noise_control.update_confidence is True
    assert settings.rst_noise_control.update_score is True
    assert settings.rst_noise_control.change_action_score_change == 10
    assert settings.rst_noise_control.drop_action_score_change == 50
    assert settings.rst_noise_control.drop_action_detection_flag is True


def test_settings_should_default_connector_id():
    """
    Test that `connector.id` defaults to the UUIDv4 declared in `settings.py`.
    """
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "04543793-50e8-4d02-b472-e88a62e8f161"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "rst_noise_control": {"api_key": "test-api-key"},
            },
            "token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "rst_noise_control": {"api_key": "test-api-key"},
            },
            "id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "rst_noise_control": {},
            },
            "api_key",
            id="missing_rst_noise_control_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` raises on invalid input, on the expected field.
    """
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err.value)
    cause = err.value.__cause__
    assert cause is not None, "ConfigValidationError must wrap the pydantic error"
    error_fields = [str(error["loc"][-1]) for error in cause.errors() if error["loc"]]
    assert field_name in error_fields


def test_settings_should_migrate_deprecated_max_tlp_to_connector_max_tlp():
    """
    Test that the deprecated `rst_noise_control.max_tlp` (`RST_NOISE_CONTROL_MAX_TLP`)
    is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "rst_noise_control": {"api_key": "test-api-key", "max_tlp": "TLP:RED"},
    }

    with pytest.warns(UserWarning, match="rst_noise_control.max_tlp"):
        settings = build_settings(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.RED


def test_settings_should_prefer_connector_max_tlp_over_deprecated_max_tlp():
    """
    Test that `connector.max_tlp` wins when the deprecated `rst_noise_control.max_tlp` is also set.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"max_tlp": "TLP:GREEN"},
        "rst_noise_control": {"api_key": "test-api-key", "max_tlp": "TLP:RED"},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.max_tlp'"):
        settings = build_settings(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.GREEN


def test_settings_should_accept_legacy_section_name():
    """
    Test that the legacy `rst-noise-control` section of `config.yml` is still read.
    """
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "rst-noise-control": {"api_key": "legacy-api-key", "timeout": 5},
    }

    settings = build_settings(settings_dict)

    assert settings.rst_noise_control.api_key.get_secret_value() == "legacy-api-key"
    assert settings.rst_noise_control.timeout == 5
