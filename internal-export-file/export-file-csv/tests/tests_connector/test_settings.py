from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings


def _full_valid_settings() -> dict[str, Any]:
    """A configuration dict setting every field (required + optional)."""
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "ExportFileCsv",
            "scope": "text/csv",
            "log_level": "info",
        },
        "export_file_csv": {
            "delimiter": ",",
        },
    }


def _minimal_valid_settings() -> dict[str, Any]:
    """A configuration dict setting only the required fields."""
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
        },
        "export_file_csv": {},
    }


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(_full_valid_settings(), id="full_valid_settings_dict"),
        pytest.param(_minimal_valid_settings(), id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.export_file_csv, BaseConfigModel) is True
    # Required values are exposed as validated Pydantic settings.
    assert settings.connector.id == "connector-id"
    assert settings.connector.type == "INTERNAL_EXPORT_FILE"
    assert settings.opencti.token.get_secret_value() == "test-token"


def test_settings_should_apply_defaults():
    """Optional fields fall back to the defaults declared in settings.py."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_minimal_valid_settings())

    settings = FakeConnectorSettings()

    assert settings.connector.name == "ExportFileCsv"
    assert settings.connector.scope == ["text/csv"]
    assert settings.connector.log_level == "error"
    assert settings.export_file_csv.delimiter == ";"


def test_settings_should_default_connector_id():
    """The connector id falls back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            settings_dict = _minimal_valid_settings()
            settings_dict["connector"] = {}
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.connector.id == "177c0a43-9dfe-4350-9706-040e12414d11"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_be_convertible_to_helper_config():
    """`to_helper_config()` returns a `pycti.OpenCTIConnectorHelper` compatible dict."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_full_valid_settings())

    helper_config = FakeConnectorSettings().to_helper_config()

    assert helper_config["opencti"]["token"] == "test-token"
    assert helper_config["connector"]["scope"] == "text/csv"
    assert helper_config["connector"]["type"] == "INTERNAL_EXPORT_FILE"
    assert helper_config["export_file_csv"]["delimiter"] == ","


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {"id": "connector-id"},
                "export_file_csv": {},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123},
                "export_file_csv": {},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "log_level": "verbose"},
                "export_file_csv": {},
            },
            id="invalid_connector_log_level",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()
