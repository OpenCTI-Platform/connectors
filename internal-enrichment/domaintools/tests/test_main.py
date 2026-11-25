from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, DomainToolsConnector
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
                    "auto": True,
                    "max_tlp": "TLP:AMBER",
                },
                "domaintools": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
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
    assert helper.connect_auto == True


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = DomainToolsConnector(config=settings, helper=helper)

    assert connector.config == settings
    assert connector.helper == helper


@pytest.mark.parametrize(
    "object_marking",
    [
        [{"definition_type": "TLP", "definition": "TLP:RED"}],
        [
            {"definition_type": "TLP", "definition": "TLP:CLEAR"},
            {"definition_type": "TLP", "definition": "TLP:RED"},
        ],
    ],
)
def test_process_message_refuses_entity_above_max_tlp(
    mock_opencti_connector_helper, object_marking
):
    """An entity with any TLP above the max TLP (amber) is never sent to DomainTools."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = DomainToolsConnector(config=settings, helper=helper)
    connector._process_file = MagicMock()

    data = {
        "enrichment_entity": {"objectMarking": object_marking},
        "stix_objects": [],
    }
    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector._process_message(data)

    connector._process_file.assert_not_called()


def test_process_message_accepts_entity_without_tlp(mock_opencti_connector_helper):
    """An entity without TLP is enriched."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = DomainToolsConnector(config=settings, helper=helper)
    connector._process_file = MagicMock(return_value="done")

    data = {"enrichment_entity": {"objectMarking": []}, "stix_objects": []}

    assert connector._process_message(data) == "done"
