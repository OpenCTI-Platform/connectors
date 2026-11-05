from typing import Any
from unittest.mock import MagicMock

import pytest
from import_doc_ai import Connector, ConnectorSettings
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
    Subclass of ConnectorSettings for testing purpose.
    Overrides _load_config_dict to return a fake but valid config dict.
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
                    "name": "ImportDocumentAI",
                    "scope": "application/pdf,text/plain,text/html,text/markdown",
                    "log_level": "error",
                    "validate_before_import": True,
                    "auto": False,
                },
                "import_document_ai": {
                    # include_relationships is disabled so that instantiating the
                    # connector does not trigger a live OpenCTI GraphQL query.
                    "include_relationships": False,
                    "create_indicator": False,
                    "api_base_url": "http://testserver",
                    "api_key": None,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that ConnectorSettings can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from BaseConnectorSettings)
        - the method `to_helper_config` MUST return a dict
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that OpenCTIConnectorHelper can be instantiated successfully:
        - the value of settings.to_helper_config MUST be the expected dict for OpenCTIConnectorHelper
        - the helper MUST be able to get its instance's attributes from the config dict
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ImportDocumentAI"
    assert helper.connect_scope == "application/pdf,text/plain,text/html,text/markdown"
    assert helper.log_level == "ERROR"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST access env/config vars through self.config
        - the connector's main class MUST access pycti API through self.helper
    """
    config = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())

    connector = Connector(config=config, helper=helper)

    assert connector.config is config
    assert connector.helper is helper
