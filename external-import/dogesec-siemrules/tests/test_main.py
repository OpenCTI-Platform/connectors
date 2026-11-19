"""Tests wiring the Pydantic settings into the existing SIEM Rules connector code."""

from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import SiemrulesConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

PYCTI_MODULE_IMPORT_PATH = "pycti.connector.opencti_connector_helper"

STUB_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://opencti:8080",
        "token": "test-opencti-token",
    },
    "connector": {
        "id": "2085fda5-47ff-4c6d-97b2-78f7b6f1bf51",
        "name": "SIEM Rules",
        "scope": "siemrules",
        "log_level": "error",
        "duration_period": "PT12H",
    },
    "siemrules": {
        "base_url": "https://api.siemrules.com/",
        "api_key": "test-api-key",
        "detection_packs": "pack-1,pack-2",
    },
}


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` loading a static, valid configuration."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(STUB_SETTINGS_DICT)


@pytest.fixture(name="mock_opencti_connector_helper")
def fixture_mock_opencti_connector_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize every `OpenCTIConnectorHelper` side effect (network, threads, signals)."""
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{PYCTI_MODULE_IMPORT_PATH}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated() -> None:
    """`to_helper_config()` returns the dict expected by `OpenCTIConnectorHelper`."""
    settings = StubConnectorSettings()

    assert isinstance(settings.to_helper_config(), dict)


@pytest.mark.usefixtures("mock_opencti_connector_helper")
def test_opencti_connector_helper_is_instantiated() -> None:
    """`OpenCTIConnectorHelper` is configurable from `to_helper_config()`."""
    settings = StubConnectorSettings()

    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://opencti:8080/"
    assert helper.opencti_token == "test-opencti-token"
    assert helper.connect_id == "2085fda5-47ff-4c6d-97b2-78f7b6f1bf51"
    assert helper.connect_name == "SIEM Rules"
    assert helper.connect_scope == "siemrules"
    assert helper.connect_type == "EXTERNAL_IMPORT"
    assert helper.log_level == "ERROR"


@pytest.mark.usefixtures("mock_opencti_connector_helper")
def test_connector_is_instantiated(monkeypatch: pytest.MonkeyPatch) -> None:
    """`SiemrulesConnector` builds its helper and API session from the settings."""
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)
    session = MagicMock()
    monkeypatch.setattr("connector.requests.Session", MagicMock(return_value=session))

    connector = SiemrulesConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "2085fda5-47ff-4c6d-97b2-78f7b6f1bf51"
    assert connector.helper.connect_name == "SIEM Rules"
    assert connector.base_url == "https://api.siemrules.com/"
    assert connector.api_key == "test-api-key"
    assert connector.detection_packs == ["pack-1", "pack-2"]
    assert connector.duration_period == 12 * 3600
    assert connector.session is session
    assert session.headers == {"API-KEY": "test-api-key"}
