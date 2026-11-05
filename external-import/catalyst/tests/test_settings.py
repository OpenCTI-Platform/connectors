"""Tests for the CATALYST connector Pydantic settings (manager-supported mode)."""

from typing import Any
from uuid import UUID

import pytest
from catalyst.settings import ConnectorSettings
from connectors_sdk import ConfigValidationError

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-opencti-token",
    },
    "connector": {
        "id": "d2107025-9f07-40c0-ae3d-373e01643256",
        "name": "CATALYST",
        "scope": "catalyst",
    },
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-opencti-token",
    },
    "connector": {
        "id": "d2107025-9f07-40c0-ae3d-373e01643256",
        "name": "CATALYST",
        "scope": "catalyst",
        "log_level": "info",
        "duration_period": "PT60M",
    },
    "catalyst": {
        "base_url": "https://prod.blindspot.prodaft.com/api",
        "api_key": "test-api-key",
        "tlp_level": "white",
        "tlp_filter": "AMBER,RED",
        "category_filter": "RESEARCH",
        "sync_days_back": 730,
        "create_observables": True,
        "create_indicators": False,
    },
}

EMPTY_SETTINGS_DICT: dict[str, Any] = {}

MISSING_OPENCTI_TOKEN_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
    },
    "connector": {
        "id": "d2107025-9f07-40c0-ae3d-373e01643256",
        "name": "CATALYST",
        "scope": "catalyst",
    },
}

INVALID_CONNECTOR_ID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-opencti-token",
    },
    "connector": {
        "id": 1234,
        "name": "CATALYST",
        "scope": "catalyst",
    },
}


def build_settings_class(config_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """Return a `ConnectorSettings` subclass loading `config_dict` instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config_dict)

    return FakeConnectorSettings


@pytest.mark.parametrize(
    "config_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(config_dict: dict[str, Any]) -> None:
    """The settings should be instantiated from a valid configuration."""
    settings = build_settings_class(config_dict)()

    assert str(settings.opencti.url) == "http://localhost:8080/"
    assert settings.opencti.token.get_secret_value() == "test-opencti-token"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.name == "CATALYST"
    assert settings.connector.scope == ["catalyst"]
    assert settings.catalyst.base_url == "https://prod.blindspot.prodaft.com/api"
    assert settings.catalyst.sync_days_back == 730
    assert settings.catalyst.create_observables is True
    assert settings.catalyst.create_indicators is False


@pytest.mark.parametrize(
    "config_dict",
    [
        pytest.param(EMPTY_SETTINGS_DICT, id="empty_settings_dict"),
        pytest.param(MISSING_OPENCTI_TOKEN_SETTINGS_DICT, id="missing_opencti_token"),
        pytest.param(INVALID_CONNECTOR_ID_SETTINGS_DICT, id="invalid_connector_id"),
    ],
)
def test_settings_should_raise_when_invalid_input(config_dict: dict[str, Any]) -> None:
    """The settings should raise a `ConfigValidationError` on an invalid configuration."""
    with pytest.raises(ConfigValidationError) as exc_info:
        build_settings_class(config_dict)()

    assert "Error validating configuration" in str(exc_info.value)


def test_settings_should_default_connector_id() -> None:
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = build_settings_class({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})()

    assert settings.connector.id == "d2107025-9f07-40c0-ae3d-373e01643256"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_expose_catalyst_defaults() -> None:
    """The CATALYST section defaults must mirror the connector's documented defaults."""
    settings = build_settings_class(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.catalyst.base_url == "https://prod.blindspot.prodaft.com/api"
    assert settings.catalyst.api_key is None
    assert settings.catalyst.tlp_level == "white"
    assert settings.catalyst.tlp_filter == "ALL"
    assert settings.catalyst.category_filter == "ALL"
    assert settings.catalyst.sync_days_back == 730
    assert settings.catalyst.create_observables is True
    assert settings.catalyst.create_indicators is False


def test_settings_should_convert_to_helper_config() -> None:
    """`to_helper_config()` must return a dict consumable by `pycti.OpenCTIConnectorHelper`."""
    settings = build_settings_class(FULL_VALID_SETTINGS_DICT)()

    helper_config = settings.to_helper_config()

    assert isinstance(helper_config, dict)
    # The OpenCTI token must be revealed for pycti.
    assert helper_config["opencti"]["token"] == "test-opencti-token"
    # The scope must be serialized as a comma-separated string for pycti.
    assert helper_config["connector"]["scope"] == "catalyst"
    assert helper_config["connector"]["type"] == "EXTERNAL_IMPORT"
    assert helper_config["connector"]["duration_period"] == "PT1H"
    assert helper_config["catalyst"]["sync_days_back"] == 730
