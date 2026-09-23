from datetime import timedelta
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from enisa_euvd import ConnectorSettings


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
                    "name": "Test Connector",
                    "scope": "vulnerability",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "euvd": {
                    "api_base_url": "https://euvdservices.enisa.europa.eu/api",
                    "import_start_date": "P30D",
                    "tlp_level": "clear",
                    "ingest_software": True,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
            },
            id="minimal_valid_settings_dict_uses_all_defaults",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """`ConnectorSettings` accepts valid input and every EUVD field has a sane default."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.euvd, BaseConfigModel) is True

    assert str(settings.euvd.api_base_url).rstrip("/") == (
        "https://euvdservices.enisa.europa.eu/api"
    )
    assert settings.euvd.import_start_date == timedelta(days=30)
    assert settings.euvd.tlp_level == TLPLevel.CLEAR
    assert isinstance(settings.euvd.ingest_software, bool)
    assert settings.connector.scope == ["vulnerability"]


def test_settings_duration_period_defaults_to_two_hours():
    """`connector.duration_period` defaults to `PT2H` when not overridden."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.connector.duration_period == timedelta(hours=2)
    assert settings.connector.name == "ENISA EUVD"


def test_settings_default_id_is_a_valid_uuidv4():
    """The `connector.id` default is a fixed, valid UUIDv4 placeholder."""
    import uuid

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                }
            )

    settings = FakeConnectorSettings()
    parsed = uuid.UUID(settings.connector.id)
    assert parsed.version == 4


def test_settings_should_raise_when_opencti_url_invalid():
    """`ConnectorSettings` raises a `ConfigValidationError` on invalid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:PORT",
                        "token": "test-token",
                    },
                }
            )

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(err.value)
    assert "opencti.url" in str(err.value.__cause__)
