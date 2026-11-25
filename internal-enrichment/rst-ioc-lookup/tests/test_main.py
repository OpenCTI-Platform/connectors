from typing import Any
from unittest.mock import MagicMock

import pytest
from main import RSTIocLookupConnector
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
    opencti_connector = MagicMock()
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", opencti_connector)
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())
    return opencti_connector


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
                    "name": "RST IoC Lookup",
                    "scope": "IPv4-Addr,Domain-Name,Url,StixFile,indicator",
                    "log_level": "info",
                    "auto": False,
                    "max_tlp": "TLP:AMBER+STRICT",
                },
                "rst_ioc_lookup": {
                    "base_url": "https://api.rstcloud.net/v1/",
                    "api_key": "test-api-key",
                    "update_confidence": True,
                    "update_score": True,
                    "update_valid_from": True,
                    "score_type": "last",
                    "update_description_action": "overwrite",
                    "detection_flag_threshold": 45,
                    "label_format": "short",
                    "timeout": 10,
                },
            }
        )


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "RST IoC Lookup"
    assert helper.connect_scope == "IPv4-Addr,Domain-Name,Url,StixFile,indicator"
    assert helper.log_level == "INFO"
    assert helper.connect_auto is False


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)

    connector = RSTIocLookupConnector()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert mock_opencti_connector_helper.call_args.kwargs["playbook_compatible"]
    assert connector.base_url == "https://api.rstcloud.net/v1"
    assert connector.api_key == "test-api-key"
    assert connector.max_tlp == "amber+strict"
    assert connector.update_confidence is True
    assert connector.update_score is True
    assert connector.update_valid_from is True
    assert connector.score_type == "last"
    assert connector.update_description_action == "overwrite"
    assert connector.detection_flag_threshold == 45
    assert connector.label_format == "short"
    assert connector.timeout == 10
    assert connector.connector_auto is False


def test_connector_sends_settings_to_rst_cloud_api(
    mock_opencti_connector_helper, monkeypatch
):
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)
    requests_get = MagicMock()
    requests_get.return_value.json.return_value = {}
    monkeypatch.setattr("main.requests.get", requests_get)
    connector = RSTIocLookupConnector()

    result = connector._process_message(
        {
            "entity_id": "ipv4-addr--00000000-0000-4000-8000-000000000000",
            "entity_type": "IPv4-Addr",
            "enrichment_entity": {"objectMarking": []},
            "stix_entity": {"value": "198.51.100.1"},
            "stix_objects": [],
        }
    )

    assert result == "[CONNECTOR] No changes required"
    requests_get.assert_called_once()
    assert requests_get.call_args.args == ("https://api.rstcloud.net/v1/ioc",)
    assert requests_get.call_args.kwargs["headers"]["x-api-key"] == "test-api-key"
    assert requests_get.call_args.kwargs["params"] == {"value": "198.51.100.1"}
    assert requests_get.call_args.kwargs["timeout"] == 10


def test_connector_rejects_entity_above_max_tlp(
    mock_opencti_connector_helper, monkeypatch
):
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)
    requests_get = MagicMock()
    monkeypatch.setattr("main.requests.get", requests_get)
    connector = RSTIocLookupConnector()

    with pytest.raises(ValueError, match="MAX TLP"):
        connector._process_message(
            {
                "entity_type": "IPv4-Addr",
                "enrichment_entity": {
                    "objectMarking": [
                        {"definition_type": "TLP", "definition": "TLP:RED"}
                    ]
                },
                "stix_entity": {"value": "198.51.100.1"},
                "stix_objects": [],
            }
        )
    requests_get.assert_not_called()
