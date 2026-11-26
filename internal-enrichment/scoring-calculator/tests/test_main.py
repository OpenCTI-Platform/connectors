from typing import Any
from unittest.mock import MagicMock

import pytest
from internal_enrichment_connector import ConnectorScoring
from internal_enrichment_connector.settings import ConnectorSettings
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
                    "name": "Scoring calculator",
                    "scope": "Indicator",
                    "log_level": "error",
                    "auto": True,
                },
                "connector_scoring": {
                    "high_priority_labels": '["[Scoring] High priority"]',
                    "medium_priority_labels": ["[Scoring] Medium priority"],
                    "low_priority_labels": '["Low"]',
                    "indicator_type_enrichable": "IPv4-Addr, IPv6-Addr,Domain-Name,StixFile",
                    "browse_report": False,
                    "threat_impact_score": True,
                    "threat_high_priority": 20,
                    "threat_medium_priority": 10,
                    "threat_low_priority": 5,
                    "toolbox_impact_score": True,
                    "toolbox_high_priority": 20,
                    "toolbox_medium_priority": 10,
                    "toolbox_low_priority": 5,
                    "location_impact_score": False,
                    "location_high_priority": 20,
                    "location_medium_priority": 10,
                    "location_low_priority": 5,
                    "sector_impact_score": False,
                    "sector_high_priority": 20,
                    "sector_medium_priority": 10,
                    "sector_low_priority": 5,
                    "ttp_impact_score": False,
                    "ttp_high_priority": 20,
                    "ttp_medium_priority": 10,
                    "ttp_low_priority": 5,
                    "author_impact_score": False,
                    "author_high_priority": 20,
                    "author_medium_priority": 10,
                    "author_low_priority": 5,
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
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "Scoring calculator"
    assert helper.connect_scope == "Indicator"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is True


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """
    Test that the connector is wired as in `main.py`:
        - the helper MUST be built from `settings.to_helper_config()`
        - the connector MUST receive the settings, the helper and the API client
        - the connector MUST read its configuration from `settings.connector_scoring`

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    api = MagicMock()
    connector = ConnectorScoring(settings=settings, helper=helper, api=api)

    # Label lists from env vars (JSON string) and config.yml (list)
    scoring = settings.connector_scoring
    assert scoring.high_priority_labels == ["[Scoring] High priority"]
    assert scoring.medium_priority_labels == ["[Scoring] Medium priority"]
    assert scoring.low_priority_labels == ["Low"]
    assert scoring.indicator_type_enrichable == [
        "IPv4-Addr",
        "IPv6-Addr",
        "Domain-Name",
        "StixFile",
    ]
    assert scoring.browse_report is False

    # Labels are compared case-insensitively by the connector
    assert connector._high_priority_labels == {"[scoring] high priority"}
    assert connector._medium_priority_labels == {"[scoring] medium priority"}
    assert connector._low_priority_labels == {"low"}
    assert connector.impact_map["Threat"] == {"high": 20, "medium": 10, "low": 5}
    assert connector.impact_enabled == {
        "Threat": True,
        "Toolbox": True,
        "Location": False,
        "Sector": False,
        "TTP": False,
        "Author": False,
    }

    assert connector.settings is settings
    assert connector.config is scoring
    assert connector.helper is helper
    assert helper.connect_id == "connector-id"
    assert connector.client.api is api
