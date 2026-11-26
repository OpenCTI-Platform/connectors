from typing import Any

import malbeacon_config_variables
import pytest
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
                    "max_tlp": "TLP:AMBER",
                },
                "malbeacon": {
                    "api_key": "test-api-key",
                    "api_base_url": "https://api.malbeacon.com/v1/",
                    "indicator_score_level": 50,
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
    assert connector.config.settings.connector.max_tlp == "amber"
    assert connector.config.connector_scope == "IPv4-Addr,IPv6-Addr,Domain-Name"


@pytest.fixture
def connector(mock_opencti_connector_helper, monkeypatch) -> MalBeaconConnector:
    """A connector built from the stubbed config (max TLP: amber)."""
    monkeypatch.setattr(
        malbeacon_config_variables, "ConnectorSettings", StubConnectorSettings
    )
    return MalBeaconConnector()


def test_extract_and_check_markings_checks_every_tlp(connector):
    entity = {
        "objectMarking": [
            {"definition_type": "TLP", "definition": "TLP:RED"},
            {"definition_type": "TLP", "definition": "TLP:GREEN"},
        ]
    }

    assert connector.extract_and_check_markings(entity) is False


def test_extract_and_check_markings_does_not_reuse_previous_tlp(connector):
    red_entity = {
        "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}]
    }
    assert connector.extract_and_check_markings(red_entity) is False

    # A following entity without any marking must not inherit TLP:RED
    assert connector.extract_and_check_markings({"objectMarking": []}) is True
