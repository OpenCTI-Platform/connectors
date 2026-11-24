from typing import Any
from unittest.mock import MagicMock

from main import RSTNoiseControlConnector
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
                    "name": "RST Noise Control",
                    "scope": "IPv4-Addr,Domain-Name,Url,StixFile,indicator",
                    "log_level": "error",
                    "auto": False,
                    "max_tlp": "TLP:AMBER+STRICT",
                },
                "rst_noise_control": {
                    "base_url": "https://api.example.com/v1/",
                    "api_key": "test-api-key",
                    "timeout": 15,
                    "update_confidence": False,
                    "update_score": True,
                    "change_action_score_change": 5,
                    "drop_action_score_change": 25,
                    "drop_action_detection_flag": False,
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
    assert helper.connect_name == "RST Noise Control"
    assert helper.connect_scope == "IPv4-Addr,Domain-Name,Url,StixFile,indicator"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is False


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class builds its settings and helper, and that
    the custom values reach the attributes used by the enrichment code.
    """
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)

    connector = RSTNoiseControlConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.base_url == "https://api.example.com/v1"
    assert connector.api_key == "test-api-key"
    assert connector.max_tlp == "TLP:AMBER+STRICT"
    assert connector.timeout == 15
    assert connector.update_confidence is False
    assert connector.update_score is True
    assert connector.change_score == 5
    assert connector.drop_score == 25
    assert connector.detection_flag is False
    assert connector.connector_auto is False


def test_connector_sends_settings_to_the_api(
    mock_opencti_connector_helper, monkeypatch
):
    """
    Test that the base URL, API key and timeout from the settings are used in the API request.
    """
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)
    response = MagicMock()
    response.json.return_value = {"benign": "false"}
    requests_get = MagicMock(return_value=response)
    monkeypatch.setattr("main.requests.get", requests_get)

    connector = RSTNoiseControlConnector()
    result = connector._process_message(
        {
            "entity_type": "IPv4-Addr",
            "enrichment_entity": {"objectMarking": []},
            "stix_entity": {"value": "198.51.100.7"},
        }
    )

    assert result == "[CONNECTOR] No changes required"
    requests_get.assert_called_once()
    args, kwargs = requests_get.call_args
    assert args == ("https://api.example.com/v1/benign/lookup",)
    assert kwargs["headers"]["x-api-key"] == "test-api-key"
    assert kwargs["params"] == {"value": "198.51.100.7"}
    assert kwargs["timeout"] == 15
