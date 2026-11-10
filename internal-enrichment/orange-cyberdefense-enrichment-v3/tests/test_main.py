from typing import Any
from unittest.mock import MagicMock

import pytest
from main import OrangeCyberdefenseEnrichment
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

STUB_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Orange Cyberdefense CTI Enrichment",
        "scope": "IPv4-Addr,Domain-Name,URL",
        "log_level": "error",
        "auto": True,
        "max_tlp": "amber",
    },
    "ocd_enrich": {
        "datalake_token": "test-datalake-token",
        "datalake_env": "preprod",
        "ignore_unscored_indicators": False,
        "ignore_whitelisted_indicators": False,
        "fallback_score": 42,
        "add_tags_as_labels": False,
        "add_scores_as_labels": False,
        "add_score": False,
        "add_tlp": False,
        "add_extref": False,
        "add_summary": False,
        "add_related": False,
        "add_sightings": False,
        "add_createdby": False,
        "curate_labels": False,
        "threat_actor_as_intrusion_set": False,
    },
}


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
def mock_datalake(monkeypatch):
    """Mock the Datalake API client to avoid any external call."""
    datalake = MagicMock()
    monkeypatch.setattr("main.Datalake", datalake)
    return datalake


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(STUB_SETTINGS_DICT)


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
    assert helper.connect_name == "Orange Cyberdefense CTI Enrichment"
    assert helper.connect_type == "INTERNAL_ENRICHMENT"
    assert helper.connect_scope == "IPv4-Addr,Domain-Name,URL"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is True


def test_connector_is_instantiated(
    monkeypatch, mock_opencti_connector_helper, mock_datalake
):
    """
    Test that the connector's main class builds its settings and helper from `ConnectorSettings`,
    and that the configured values reach the attributes used by the connector.
    """
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)

    connector = OrangeCyberdefenseEnrichment()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)
    assert connector.helper.connect_id == "connector-id"
    assert connector.helper.connect_scope == "IPv4-Addr,Domain-Name,URL"

    mock_datalake.assert_called_once_with(
        longterm_token="test-datalake-token", env="preprod"
    )

    assert connector.ocd_enrich_datalake_token == "test-datalake-token"
    assert connector.ocd_enrich_datalake_env == "preprod"
    assert connector.ocd_enrich_ignore_unscored_indicators is False
    assert connector.ocd_enrich_ignore_whitelisted_indicators is False
    assert connector.ocd_enrich_fallback_score == 42
    assert connector.ocd_enrich_add_tags_as_labels is False
    assert connector.ocd_enrich_add_scores_as_labels is False
    assert connector.ocd_enrich_add_score is False
    assert connector.ocd_enrich_add_tlp is False
    assert connector.ocd_enrich_add_extref is False
    assert connector.ocd_enrich_add_summary is False
    assert connector.ocd_enrich_add_related is False
    assert connector.ocd_enrich_add_sightings is False
    assert connector.ocd_enrich_add_createdby is False
    assert connector.ocd_enrich_curate_labels is False
    assert connector.ocd_enrich_threat_actor_as_intrusion_set is False
    assert connector.max_tlp == "TLP:AMBER"


def test_connector_normalizes_scope(
    monkeypatch, mock_opencti_connector_helper, mock_datalake
):
    """
    The connector keeps normalizing `CONNECTOR_SCOPE` with `validate_scope`:
    known types are mapped to their OpenCTI name, unknown types are dropped.
    """

    class ScopeStubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **STUB_SETTINGS_DICT,
                    "connector": {"scope": "ipv4-addr, domain-name, unknown-type"},
                }
            )

    monkeypatch.setattr("main.ConnectorSettings", ScopeStubConnectorSettings)

    connector = OrangeCyberdefenseEnrichment()

    assert connector.helper.connect_scope == "IPv4-Addr,Domain-Name"


def test_connector_raises_when_no_valid_scope(
    monkeypatch, mock_opencti_connector_helper, mock_datalake
):
    """The connector refuses to start when `CONNECTOR_SCOPE` holds no supported type."""

    class InvalidScopeStubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {**STUB_SETTINGS_DICT, "connector": {"scope": "unknown-type"}}
            )

    monkeypatch.setattr("main.ConnectorSettings", InvalidScopeStubConnectorSettings)

    with pytest.raises(ValueError, match="No valid scopes found"):
        OrangeCyberdefenseEnrichment()
