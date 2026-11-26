from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, ConnectorState, RSTThreatLibrary
from main import RSTThreatLibraryConnector, build_data_processors
from pycti import OpenCTIConnectorHelper
from pycti.connector import opencti_connector_helper as helper_mod


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock heavy dependencies of OpenCTIConnectorHelper (avoid OpenCTI calls)."""

    monkeypatch.setattr(helper_mod, "killProgramHook", MagicMock(), raising=False)
    sched_mod = getattr(helper_mod, "sched", None)
    if sched_mod is not None:
        monkeypatch.setattr(sched_mod, "scheduler", MagicMock(), raising=False)
    for name in (
        "ConnectorInfo",
        "OpenCTIApiClient",
        "OpenCTIConnector",
        "OpenCTIMetricHandler",
        "PingAlive",
    ):
        monkeypatch.setattr(helper_mod, name, MagicMock(), raising=False)


class StubConnectorSettings(ConnectorSettings):
    """Stub ConnectorSettings with a valid in-memory config dict."""

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
                    "duration_period": "PT5M",
                },
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                    "auth_header": "x-api-key",
                    "object_types": "intrusion-sets,malware",
                    "merge_split": True,
                },
            }
        )


def test_connector_settings_is_instantiated():
    settings = StubConnectorSettings()
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    assert helper.opencti_url is not None


def test_engine_is_instantiated(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    engine = RSTThreatLibrary(config=settings, helper=helper)
    assert engine.config == settings
    assert engine.helper == helper


def test_build_data_processors_includes_import_and_merge_split():
    settings = StubConnectorSettings()
    processors = build_data_processors(settings)
    names = [type(p).__name__ for p in processors]
    assert names.count("ThreatObjectImportProcessor") == 2
    assert names[-1] == "MergeSplitProcessor"


def test_external_import_connector_wires_processors(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    state = ConnectorState()
    processors = build_data_processors(settings)
    connector = RSTThreatLibraryConnector(
        settings=settings,
        state=state,
        data_processors=processors,
    )
    assert connector.settings is settings
    assert connector.state is state
    assert len(connector.data_processors) == 3
