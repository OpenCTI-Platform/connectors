from typing import Any
from unittest.mock import MagicMock

import pytest
from cybersixgill import Cybersixgill
from cybersixgill.settings import ConnectorSettings
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
                    "duration_period": "PT10M",
                },
                "cybersixgill": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "create_observables": True,
                    "create_indicators": False,
                    "enable_relationships": True,
                    "fetch_size": 1000,
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


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST load its env/config vars through `ConnectorSettings` into `self.config`
        - the connector's main class MUST build its `pycti` helper from `self.config.to_helper_config()`
        - the Cybersixgill settings MUST be forwarded to the client and the importer

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    mock_client = MagicMock()
    monkeypatch.setattr("cybersixgill.core.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("cybersixgill.core.CybersixgillClient", mock_client)

    connector = Cybersixgill()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.interval_sec == 600
    mock_client.assert_called_once_with("test-client-id", "test-client-secret", 1000)

    importer = connector.indicator_importer
    assert importer.helper == connector.helper
    assert importer.create_observables is True
    assert importer.create_indicators is False
    assert importer.enable_relationships is True
    assert importer.limit == 1000


class _StopLoop(Exception):
    """Raised by the patched `_sleep` to leave the connector's infinite loop."""


@pytest.fixture
def connector(mock_opencti_connector_helper, monkeypatch):
    """Build a connector with a stubbed client, a fixed clock and a patched `_sleep`."""
    monkeypatch.setattr("cybersixgill.core.ConnectorSettings", StubConnectorSettings)
    monkeypatch.setattr("cybersixgill.core.CybersixgillClient", MagicMock())
    connector = Cybersixgill()
    monkeypatch.setattr(connector, "_current_unix_timestamp", lambda: 10_000)
    monkeypatch.setattr(connector, "_sleep", MagicMock(side_effect=_StopLoop))
    return connector


def test_run_should_sleep_until_next_run_when_not_scheduled(connector, monkeypatch):
    """The loop MUST wait for the next run instead of spinning when it is not due yet."""
    monkeypatch.setattr(
        connector.helper, "get_state", MagicMock(return_value={"last_run": 9_410})
    )
    monkeypatch.setattr(connector.indicator_importer, "run", MagicMock())

    with pytest.raises(_StopLoop):
        connector.run()

    # interval is 600s and last run was 590s ago: next run in 10s
    connector._sleep.assert_called_once_with(delay_sec=10)
    connector.indicator_importer.run.assert_not_called()


def test_run_should_sleep_after_a_successful_run(connector, monkeypatch):
    """The loop MUST also wait after a successful run."""
    monkeypatch.setattr(connector.helper, "get_state", MagicMock(return_value={}))
    monkeypatch.setattr(connector.helper, "set_state", MagicMock())
    monkeypatch.setattr(connector.helper.api.work, "initiate_work", MagicMock())
    monkeypatch.setattr(connector.helper.api.work, "to_processed", MagicMock())
    monkeypatch.setattr(connector.indicator_importer, "run", MagicMock(return_value={}))

    with pytest.raises(_StopLoop):
        connector.run()

    connector.indicator_importer.run.assert_called_once()
    connector._sleep.assert_called_once_with(
        delay_sec=Cybersixgill._CONNECTOR_RUN_INTERVAL_SEC
    )
