from typing import Any
from unittest.mock import MagicMock

import pytest
from cpe import ConnectorSettings, CPEConnector
from pycti import OpenCTIConnectorHelper


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
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "cpe": {
                    "base_url": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
                    "api_key": "test-api-key",
                    "interval": "6h",
                },
            }
        )


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
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Test Connector"
    assert helper.connect_scope == "test,connector"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = CPEConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


def test_deterministic_id(mock_opencti_connector_helper):
    """
    testing that two identical CPE provide the same STIX object,
    while two different CPE do not provide the same STIX object

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    _json_object = {
        "cpe": {
            "cpeName": "cpe:2.3:a:adobe:flash_player:18.0:*:*:*:*:internet_explorer_10:*:*",
            "deprecated": False,
            "titles": [
                {
                    "title": "Adobe Flash Player 18.0 for Internet Explorer 10",
                    "lang": "en",
                }
            ],
        }
    }
    _other_json_object = {
        "cpe": {
            "cpeName": "cpe:2.3:a:microsoft:internet_explorer:5.5:sp2:*:*:*:*:*:*",
            "deprecated": False,
            "titles": [
                {
                    "title": "Microsoft Internet Explorer 5.5 Service Pack 2",
                    "lang": "en",
                }
            ],
        }
    }
    json_objects = {
        "resultsPerPage": 3,
        "products": [
            _json_object,
            _json_object,
            _other_json_object,
        ],
    }
    connector = CPEConnector(config=settings, helper=helper)

    stix_objects = connector._json_to_stix(json_objects)

    assert len(stix_objects) == 3
    assert stix_objects[0] == stix_objects[1]
    assert stix_objects[0].id == stix_objects[1].id
    assert stix_objects[0] != stix_objects[2]
    assert stix_objects[0].id != stix_objects[2].id
