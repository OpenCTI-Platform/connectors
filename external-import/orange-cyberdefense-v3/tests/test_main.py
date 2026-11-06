import json
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock

import pytest
from main import OrangeCyberdefense
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

DATALAKE_QUERIES = [
    {
        "query_hash": "bb08a750538baea3e1c8cda0ae5b3aca",
        "label": "high_confidence_network_iocs",
    },
    {
        "query_hash": "1ac760cbaec854a6c463d92c8f862c98",
        "label": "ocd_peerpressure_c2_tracker",
    },
]

STUB_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Orange Cyberdefense Cyber Threat Intelligence",
        "scope": "Orange-Cyberdefense",
        "log_level": "error",
        "duration_period": "PT45M",
    },
    "ocd": {
        "import_datalake": True,
        "import_threat_library": True,
        "import_worldwatch": True,
        "datalake_env": "preprod",
        "datalake_token": "test-datalake-token",
        "datalake_queries": json.dumps(DATALAKE_QUERIES),
        "datalake_create_observables": False,
        "datalake_ignore_unscored_indicators": False,
        "datalake_ignore_whitelisted_indicators": False,
        "datalake_fallback_score": 20,
        "datalake_add_tags_as_labels": False,
        "datalake_add_scores_as_labels": False,
        "datalake_add_score": False,
        "datalake_add_tlp": False,
        "datalake_add_extref": False,
        "datalake_add_summary": False,
        "datalake_add_related": False,
        "datalake_add_sightings": False,
        "datalake_add_createdby": False,
        "datalake_zip_file_path": "/tmp/ocd-data",
        "datalake_zip_file_delete": False,
        "datalake_curate_labels": False,
        "datalake_threat_actor_as_intrusion_set": False,
        "worldwatch_api_key": "test-worldwatch-api-key",
        "worldwatch_import_indicators": False,
        "worldwatch_import_indicators_lookback": 86400,
        "worldwatch_import_threat_entities": False,
        "worldwatch_start_date": "2025-06-01",
        "reset_state": True,
    },
}


def build_stub_settings(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """Build a `ConnectorSettings` subclass reading the given dict instead of env/config vars."""

    class StubConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(deepcopy(settings_dict))

    return StubConnectorSettings


StubConnectorSettings = build_stub_settings(STUB_SETTINGS_DICT)


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
    """Mock the Datalake client, with a token granted the `bulk_search` permission."""

    mocked_datalake = MagicMock()
    mocked_datalake.return_value.MyAccount.me.return_value = {
        "role": {"administration_permissions": [{"name": "bulk_search"}]}
    }
    monkeypatch.setattr("main.Datalake", mocked_datalake)
    return mocked_datalake


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
    assert helper.connect_name == "Orange Cyberdefense Cyber Threat Intelligence"
    assert helper.connect_scope == "Orange-Cyberdefense"
    assert helper.log_level == "ERROR"
    assert helper.connect_duration_period == "PT45M"


def test_connector_is_instantiated(
    monkeypatch, mock_opencti_connector_helper, mock_datalake
):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
        - the values read from `self.config` MUST reach the attributes used by the connector

    `OrangeCyberdefense.__init__` builds its own `ConnectorSettings` and its own Datalake client,
    so `main.ConnectorSettings` and `main.Datalake` are patched to keep the test hermetic.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_datalake: `Datalake` client is mocked during this test to avoid any external calls to Datalake API
    """
    monkeypatch.setattr("main.ConnectorSettings", StubConnectorSettings)

    connector = OrangeCyberdefense()

    assert isinstance(connector.config, StubConnectorSettings)
    assert isinstance(connector.helper, OpenCTIConnectorHelper)

    assert connector.ocd_import_datalake is True
    assert connector.ocd_import_threat_library is True
    assert connector.ocd_import_worldwatch is True
    assert connector.ocd_datalake_env == "preprod"
    assert connector.ocd_datalake_token == "test-datalake-token"
    assert connector.ocd_datalake_queries == DATALAKE_QUERIES
    assert connector.ocd_datalake_create_observables is False
    assert connector.ocd_datalake_ignore_unscored_indicators is False
    assert connector.ocd_datalake_ignore_whitelisted_indicators is False
    assert connector.ocd_datalake_fallback_score == 20
    assert connector.ocd_datalake_add_tags_as_labels is False
    assert connector.ocd_datalake_add_scores_as_labels is False
    assert connector.ocd_datalake_add_score is False
    assert connector.ocd_datalake_add_tlp is False
    assert connector.ocd_datalake_add_extref is False
    assert connector.ocd_datalake_add_summary is False
    assert connector.ocd_datalake_add_related is False
    assert connector.ocd_datalake_add_sightings is False
    assert connector.ocd_datalake_add_createdby is False
    assert connector.ocd_datalake_zip_file_path == "/tmp/ocd-data"
    assert connector.ocd_datalake_zip_file_delete is False
    assert connector.ocd_datalake_curate_labels is False
    assert connector.ocd_datalake_threat_actor_as_intrusion_set is False
    assert connector.ocd_worldwatch_api_key == "test-worldwatch-api-key"
    assert connector.ocd_worldwatch_import_indicators is False
    assert connector.ocd_worldwatch_import_indicators_lookback == 86400
    assert connector.ocd_worldwatch_import_threat_entities is False
    assert connector.ocd_worldwatch_start_date == "2025-06-01"
    assert connector.ocd_interval == 45
    assert connector.ocd_reset_state is True

    # The Datalake client receives the token and environment from the settings
    mock_datalake.assert_called_once_with(
        longterm_token="test-datalake-token", env="preprod"
    )


@pytest.mark.parametrize(
    "ocd_overrides, expected_error",
    [
        pytest.param(
            {"datalake_queries": None},
            "Parameter 'OCD_DATALAKE_QUERIES' is missing",
            id="missing_datalake_queries",
        ),
        pytest.param(
            {"worldwatch_api_key": None},
            "Parameter 'OCD_WORLDWATCH_API_KEY' is missing",
            id="missing_worldwatch_api_key",
        ),
        pytest.param(
            {"datalake_token": None},
            "Parameter 'OCD_DATALAKE_TOKEN' is missing",
            id="missing_datalake_token",
        ),
    ],
)
def test_connector_should_raise_when_conditionally_required_setting_is_missing(
    monkeypatch,
    mock_opencti_connector_helper,
    mock_datalake,
    ocd_overrides,
    expected_error,
):
    """
    Test that the connector keeps rejecting a configuration where an enabled import
    lacks its credentials or queries.
    """
    settings_dict = deepcopy(STUB_SETTINGS_DICT)
    settings_dict["ocd"].update(ocd_overrides)
    monkeypatch.setattr("main.ConnectorSettings", build_stub_settings(settings_dict))

    with pytest.raises(ValueError, match=expected_error):
        OrangeCyberdefense()


def test_connector_should_not_require_credentials_when_imports_are_disabled(
    monkeypatch, mock_opencti_connector_helper, mock_datalake
):
    """
    Test that the Datalake token, queries and World Watch API key are optional
    when every import is disabled, and that no Datalake client is built.
    """
    settings_dict = deepcopy(STUB_SETTINGS_DICT)
    settings_dict["ocd"].update(
        {
            "import_datalake": False,
            "import_threat_library": False,
            "import_worldwatch": False,
            "datalake_token": None,
            "datalake_queries": None,
            "worldwatch_api_key": None,
        }
    )
    monkeypatch.setattr("main.ConnectorSettings", build_stub_settings(settings_dict))

    connector = OrangeCyberdefense()

    assert connector.ocd_datalake_token is None
    assert connector.ocd_worldwatch_api_key is None
    mock_datalake.assert_not_called()
