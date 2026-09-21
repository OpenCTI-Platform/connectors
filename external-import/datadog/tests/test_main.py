from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import DataDogConnector
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


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
                    "name": "DataDog",
                    "scope": "stix2",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "datadog": {
                    "token": "test-api-key",
                    "app_key": "test-app-key",
                    "api_base_url": "https://api.datadoghq.com",
                    "app_base_url": "https://app.datadoghq.com",
                    "import_interval": 60,
                    "max_tlp": "TLP:AMBER",
                    "batch_size": 100,
                    "import_alerts": True,
                    "create_incident_response_cases": False,
                    "alert_priorities": "P1,P2",
                    "alert_tags_filter": "env:prod, team:secops",
                    "extract_observables_from_alerts": True,
                    "include_alert_context": True,
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
    assert helper.connect_name == "DataDog"
    assert helper.connect_scope == "stix2"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT5M"


def test_connector_is_instantiated(monkeypatch, mock_opencti_connector_helper):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`

    `DataDogConnector.__init__` builds its own `ConnectorSettings` and `OpenCTIConnectorHelper`,
    so `connector.ConnectorSettings` is patched with the stub to keep the test hermetic.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)

    datadog_connector = DataDogConnector()

    assert isinstance(datadog_connector.config, ConnectorSettings)
    assert isinstance(datadog_connector.helper, OpenCTIConnectorHelper)


def test_connector_config_is_wired_to_connector_attributes(
    monkeypatch, mock_opencti_connector_helper
):
    """
    Test that every `DATADOG_*` setting is read from `self.config` and propagated to the
    attributes (and the collaborators) the rest of the connector relies on.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    monkeypatch.setattr("connector.ConnectorSettings", StubConnectorSettings)

    datadog_connector = DataDogConnector()

    # Secrets are unwrapped from `SecretStr` for the DataDog HTTP client
    assert datadog_connector.api_token == "test-api-key"
    assert datadog_connector.app_key == "test-app-key"
    assert datadog_connector.api_base_url == "https://api.datadoghq.com"
    assert datadog_connector.app_base_url == "https://app.datadoghq.com"
    assert datadog_connector.import_interval == 60
    assert datadog_connector.import_start_date is None
    assert datadog_connector.max_tlp == "TLP:AMBER"
    assert datadog_connector.batch_size == 100
    assert datadog_connector.import_alerts is True
    assert datadog_connector.create_incident_response_cases is False
    assert datadog_connector.extract_observables_from_alerts is True
    assert datadog_connector.include_alert_context is True
    # Comma-separated variables are normalized into lists by `ListFromString`
    assert datadog_connector.alert_priorities == ["P1", "P2"]
    assert datadog_connector.alert_tags_filter == ["env:prod", "team:secops"]

    # Collaborators are built from the configured values
    assert datadog_connector.client.base_url == "https://api.datadoghq.com"
    assert datadog_connector.client.batch_size == 100
    assert datadog_connector.converter.app_base_url == "https://app.datadoghq.com"
