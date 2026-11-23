from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from enisa_euvd import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict,expected_start_days",
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
                "enisa_euvd": {
                    "api_base_url": "https://euvdservices.enisa.europa.eu/api",
                    "import_start_date": "P30D",
                    "tlp_level": "clear",
                    "min_score": 7.0,
                    "exploited_only": True,
                    "critical_only": True,
                    "ingest_software": True,
                },
            },
            30,
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
            },
            90,
            id="minimal_valid_settings_dict_uses_all_defaults",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict, expected_start_days):
    """`ConnectorSettings` accepts valid input and every EUVD field has a sane default."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.enisa_euvd, BaseConfigModel) is True

    assert str(settings.enisa_euvd.api_base_url).rstrip("/") == (
        "https://euvdservices.enisa.europa.eu/api"
    )
    expected_start = datetime.now(timezone.utc) - timedelta(days=expected_start_days)
    assert abs(settings.enisa_euvd.import_start_date - expected_start) < timedelta(
        minutes=1
    )
    assert settings.enisa_euvd.tlp_level == TLPLevel.CLEAR
    assert isinstance(settings.enisa_euvd.ingest_software, bool)
    assert settings.connector.scope == ["vulnerability"]


def test_settings_duration_period_defaults_to_one_day():
    """`connector.duration_period` defaults to `P1D` when not overridden."""

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
    assert settings.connector.duration_period == timedelta(days=1)
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


def test_settings_filters_default_to_importing_everything():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {"opencti": {"url": "http://localhost:8080", "token": "test-token"}}
            )

    settings = FakeConnectorSettings()

    assert settings.enisa_euvd.min_score is None
    assert settings.enisa_euvd.exploited_only is False
    assert settings.enisa_euvd.critical_only is False
    assert settings.enisa_euvd.effective_min_score is None
    assert settings.enisa_euvd.tlp_level == TLPLevel.CLEAR


def test_settings_accept_an_absolute_import_start_date():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "enisa_euvd": {"import_start_date": "2026-01-01T00:00:00Z"},
                }
            )

    settings = FakeConnectorSettings()

    assert settings.enisa_euvd.import_start_date == datetime(
        2026, 1, 1, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("min_score", [-1, 10.5])
def test_settings_should_raise_when_min_score_out_of_range(min_score):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "enisa_euvd": {"min_score": min_score},
                }
            )

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
