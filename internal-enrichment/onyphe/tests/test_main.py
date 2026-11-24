from typing import Any
from unittest.mock import MagicMock

import pytest
from internal_enrichment_connector.settings import ConnectorSettings
from onyphe_import import ONYPHEConnector
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


@pytest.fixture
def mock_onyphe_client(monkeypatch):
    """Mock the ONYPHE API client so no request leaves the test."""
    client_class = MagicMock()
    monkeypatch.setattr("onyphe_import.Onyphe", client_class)
    return client_class


class StubConnectorSettings(ConnectorSettings):
    """`ConnectorSettings` reading a fake but valid config dict instead of env vars or `config.yml`."""

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
                    "name": "ONYPHE",
                    "scope": "ipv4-addr,ipv6-addr,indicator,hostname,x509-certificate,text",
                    "log_level": "info",
                    "auto": False,
                    "max_tlp": "TLP:AMBER+STRICT",
                },
                "onyphe": {
                    "api_key": "test-api-key",
                    "base_url": "https://www.onyphe.io/api/v2/",
                    "category": "riskscan",
                    "time_since": "1w",
                    "default_score": 50,
                    "import_search_results": True,
                    "create_note": False,
                    "import_full_data": False,
                    "pivot_threshold": 10,
                    "indicator_max_results": 1000,
                    "pattern_type": "onyphe",
                    "enrichment_types": "IPv4-Address,Vulnerability",
                    "text_fingerprints": "favicon-sha256,ssh-fingerprint-sha256",
                },
            }
        )


def test_connector_settings_is_instantiated():
    """`ConnectorSettings` builds a helper config dict."""
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """`OpenCTIConnectorHelper` reads its attributes from `to_helper_config()`."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ONYPHE"
    assert (
        helper.connect_scope
        == "ipv4-addr,ipv6-addr,indicator,hostname,x509-certificate,text"
    )
    assert helper.connect_type == "INTERNAL_ENRICHMENT"
    assert helper.connect_auto is False
    assert helper.log_level == "INFO"


def test_connector_is_instantiated(mock_opencti_connector_helper, mock_onyphe_client):
    """`ONYPHEConnector` built as in `main.py` uses the settings values."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )

    connector = ONYPHEConnector(config=settings, helper=helper)

    assert connector.config is settings
    assert connector.helper is helper
    mock_onyphe_client.assert_called_once_with(
        "test-api-key", "https://www.onyphe.io/api/v2/"
    )
    assert connector.onyphe_client is mock_onyphe_client.return_value
    assert connector.max_tlp == "TLP:AMBER+STRICT"
    assert connector.onyphe_category == "riskscan"
    assert connector.profile.category == "riskscan"
    # The enrichment type filter keeps only the generators of the enabled types.
    assert connector.profile.stix_generators["ipv4-addr"] == [
        "_generate_stix_identity",
        "_generate_stix_vulnerability",
        "_upsert_stix_observable",
    ]
    assert [label for _, label in connector.active_pivots] == [
        "favicon-sha256",
        "ssh-fingerprint-sha256",
    ]


def test_connector_checks_max_tlp_from_connector_section(
    mock_opencti_connector_helper, mock_onyphe_client
):
    """The max TLP check uses `connector.max_tlp` in the `TLP:XXX` form pycti expects."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    connector = ONYPHEConnector(config=settings, helper=helper)

    amber_entity = {
        "objectMarking": [{"definition_type": "TLP", "definition": "TLP:AMBER"}]
    }
    red_entity = {
        "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}]
    }

    assert connector._extract_and_check_markings(amber_entity) == "TLP:AMBER"
    with pytest.raises(ValueError, match="greater than MAX TLP"):
        connector._extract_and_check_markings(red_entity)
