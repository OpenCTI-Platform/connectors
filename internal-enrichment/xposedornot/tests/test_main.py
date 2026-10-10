import pathlib
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from src.xposedornot import ConnectorSettings, XposedOrNotConnector

from tests.conftest import make_settings


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    path = "pycti.connector.opencti_connector_helper"
    for attribute in (
        "killProgramHook",
        "ConnectorInfo",
        "OpenCTIApiClient",
        "OpenCTIConnector",
        "OpenCTIMetricHandler",
        "PingAlive",
    ):
        monkeypatch.setattr(f"{path}.{attribute}", MagicMock())
    monkeypatch.setattr(f"{path}.sched.scheduler", MagicMock())


def test_settings_feed_the_helper_and_the_connector(mock_opencti_connector_helper):
    settings = make_settings(api_key="test-api-key", max_tlp="TLP:AMBER+STRICT")
    assert isinstance(settings, ConnectorSettings)
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(), playbook_compatible=True
    )
    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.connect_id == "connector-id"
    assert helper.connect_scope == "Email-Addr"
    assert helper.connect_type == "INTERNAL_ENRICHMENT"
    connector = XposedOrNotConnector(config=settings, helper=helper)
    assert connector.config.xposedornot.max_tlp == "TLP:AMBER+STRICT"
    assert connector.client.api_key == "test-api-key"


def test_entrypoints_print_the_traceback_and_exit_non_zero():
    src = pathlib.Path(__file__).resolve().parents[1] / "src"
    for name in ("main.py", "__main__.py"):
        source = (src / name).read_text()
        assert "traceback.print_exc()" in source and "sys.exit(1)" in source, name
