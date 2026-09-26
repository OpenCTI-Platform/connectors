# -*- coding: utf-8 -*-
"""Unit tests for ConnectorSettings in Lamis Network connector."""

from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from lamis_network.settings import ConnectorSettings


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
                    "name": "Lamis Network IP Intelligence",
                    "scope": "IPv4-Addr,IPv6-Addr",
                    "log_level": "info",
                    "auto": True,
                },
                "lamis_network": {
                    "api_key": "test-api-key",
                    "api_url": "https://api.lamisnetwork.com",
                    "timeout": 15,
                    "suspicious_threshold": 80,
                    "create_indicator": True,
                    "add_relationships": True,
                    "default_tlp": "TLP:CLEAR",
                    "max_tlp": "TLP:AMBER",
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
                "connector": {
                    "id": "connector-id",
                    "scope": "IPv4-Addr,IPv6-Addr",
                },
                "lamis_network": {
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
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
    assert isinstance(settings.lamis_network, BaseConfigModel) is True
    assert settings.lamis_network.default_tlp == "TLP:CLEAR"
    assert settings.lamis_network.max_tlp == "TLP:AMBER"
    if "auto" in settings_dict.get("connector", {}):
        assert settings.connector.auto is settings_dict["connector"]["auto"]
    else:
        assert settings.connector.auto is False
    assert isinstance(settings.connector.scope, list)
    assert settings.to_helper_config()["connector"]["scope"] == "IPv4-Addr,IPv6-Addr"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "IPv4-Addr",
                },
                "lamis_network": {
                    "api_key": "test-api-key",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "name": "Lamis Network IP Intelligence",
                    "scope": "IPv4-Addr",
                },
                "lamis_network": {
                    "api_key": "test-api-key",
                },
            },
            "connector.id",
            id="missing_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "IPv4-Addr",
                },
                "lamis_network": {},
            },
            "lamis_network.api_key",
            id="missing_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "IPv4-Addr",
                },
                "lamis_network": {
                    "api_key": "   ",
                },
            },
            "lamis_network.api_key",
            id="empty_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)
