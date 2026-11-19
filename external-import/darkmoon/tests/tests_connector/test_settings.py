from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Darkmoon",
                    "scope": "Vulnerability,Note,Report",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "darkmoon": {
                    "export_path": "/opt/darkmoon-data",
                    "tlp_level": "red",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "darkmoon": {"export_path": "/opt/darkmoon-data"},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """`ConnectorSettings` must accept valid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.darkmoon, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "darkmoon": {"export_path": "/opt/darkmoon-data"},
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "darkmoon": {"tlp_level": "red"},  # export_path missing, no default
            },
            "darkmoon.export_path",
            id="missing_darkmoon_export_path",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """`ConnectorSettings` must raise on invalid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)
