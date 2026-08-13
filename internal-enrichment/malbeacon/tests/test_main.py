from typing import Any

import malbeacon_config_variables
from main import MalBeaconConnector
from malbeacon_config_variables import ConfigMalbeacon
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
                    "name": "Malbeacon",
                    "scope": "IPv4-Addr,IPv6-Addr,Domain-Name",
                    "log_level": "error",
                    "auto": True,
                },
                "malbeacon": {
                    "api_key": "test-api-key",
                    "api_base_url": "https://api.malbeacon.com/v1/",
                    "indicator_score_level": 50,
                    "max_tlp": "TLP:AMBER",
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
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Malbeacon"
    assert helper.connect_scope == "IPv4-Addr,IPv6-Addr,Domain-Name"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is True


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class can be instantiated successfully.

    The `MalBeaconConnector` builds its own configuration and helper internally
    (via `ConfigMalbeacon` -> `ConnectorSettings`). We patch `ConnectorSettings`
    where `ConfigMalbeacon` looks it up so the connector uses the stubbed config:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
    """
    monkeypatch.setattr(
        malbeacon_config_variables, "ConnectorSettings", StubConnectorSettings
    )

    connector = MalBeaconConnector()

    assert isinstance(connector.config, ConfigMalbeacon)
    assert connector.helper is not None
    assert connector.config.api_key == "test-api-key"
    assert connector.config.api_base_url == "https://api.malbeacon.com/v1/"
    assert connector.config.indicator_score_level == 50
    assert connector.config.max_tlp == "TLP:AMBER"
    assert connector.config.connector_scope == "IPv4-Addr,IPv6-Addr,Domain-Name"
