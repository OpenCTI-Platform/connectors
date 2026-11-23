from typing import Any
from unittest.mock import MagicMock

import eset
import pytest
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

STUB_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "ESET Cyber Threat Intelligence",
        "scope": "eset",
        "log_level": "error",
    },
    "eset": {
        "api_url": "eti.eset.com",
        "username": "test-user",
        "password": "test-password",
        "collections": "ei.misp,ei.cc,ei.urls",
        "import_apt_reports": True,
        "import_start_date": "2022-04-01",
        "create_observables": True,
        "interval": 60,
    },
}


class StubConnectorSettings(ConnectorSettings):
    """Settings stub returning a fixed config dict instead of env/config.yml values."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(STUB_SETTINGS_DICT)


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    """The settings must build a dict usable by OpenCTIConnectorHelper."""
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """The helper must be built from the settings with the expected attributes."""
    settings = StubConnectorSettings()

    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ESET Cyber Threat Intelligence"
    assert helper.connect_scope == "eset"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(
    mock_opencti_connector_helper, monkeypatch, tmp_path
):
    """The existing Eset class must read its configuration from the settings."""
    monkeypatch.setattr(eset, "ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr(eset, "TMP_DIR", str(tmp_path / "TMP"))

    connector = eset.Eset()

    assert connector.eset_api_url == "eti.eset.com"
    assert connector.eset_username == "test-user"
    assert connector.eset_password == "test-password"
    assert connector.eset_collections == ["ei.misp", "ei.cc", "ei.urls"]
    assert connector.eset_import_apt_reports is True
    assert connector.eset_create_observables is True
    assert connector.get_interval() == 3600
