from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "BeaconBeagle",
                    "scope": "beaconbeagle",
                    "log_level": "error",
                    "duration_period": "PT2H",
                },
                "beaconbeagle": {
                    "url": "https://beaconbeagle.com/api/v1/c2?q=&sort=firsttime",
                    "add_urls": True,
                    "add_useragent": True,
                    "link_tool": "CobaltStrike",
                    "link_ap": "T1071 Standard Application Layer Protocol",
                    "link_country": True,
                    "link_bgpas": True,
                    "search_bgpas": False,
                    "link_watermark_txt": "",
                    "links_duration": 24,
                    "marking": "TLP:GREEN",
                },
            }
        )


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
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `pycti.OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `pycti.OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `pycti.OpenCTIConnectorHelper`'s dependencies are mocked
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "BeaconBeagle"
    assert helper.connect_scope == "beaconbeagle"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the existing `BeaconBeagle` connector class can be instantiated with the settings:
        - every BeaconBeagle option MUST be read from the validated settings
        - the helper MUST be built from the settings

    :param mock_opencti_connector_helper: `pycti.OpenCTIConnectorHelper`'s dependencies are mocked
    """
    import BeaconBeagle

    monkeypatch.setattr(BeaconBeagle, "ConnectorSettings", StubConnectorSettings)

    connector = BeaconBeagle.BeaconBeagle()

    assert connector.helper.connect_id == "connector-id"
    assert connector.beaconbeagle_url.startswith("https://beaconbeagle.com/")
    assert connector.beaconbeagle_add_urls is True
    assert connector.beaconbeagle_add_useragent is True
    assert connector.beaconbeagle_link_tool == "CobaltStrike"
    assert connector.beaconbeagle_link_country is True
    assert connector.beaconbeagle_link_bgpas is True
    assert connector.beaconbeagle_search_bgpas is False
    assert connector.beaconbeagle_link_watermark == ""
    assert connector.beaconbeagle_links_duration == 24
    assert connector.beaconbeagle_interval == timedelta(hours=2)
    assert connector.beaconbeagle_marking == "TLP:GREEN"
