"""Test the manager-supported wiring used by ``main.py``.

Configuration is loaded through Pydantic ``ConnectorSettings`` and handed to
``OpenCTIConnectorHelper`` via ``to_helper_config()``.
"""

import runpy
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, IsMaliciousConnector
from pycti import OpenCTIConnectorHelper

CONFIG_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://opencti:8080",
        "token": "test-opencti-token",
    },
    "connector": {
        "id": "test-connector-id",
        "name": "isMalicious",
        "scope": "IPv4-Addr,IPv6-Addr,Domain-Name",
        "log_level": "info",
        "auto": False,
    },
    "ismalicious": {
        "api_url": "https://api.ismalicious.com",
        "api_key": "test-api-key",
        "max_tlp": "TLP:AMBER",
        "enrich_ipv4": True,
        "enrich_ipv6": True,
        "enrich_domain": True,
        "min_score": 0,
    },
}


class StubConnectorSettings(ConnectorSettings):
    """ConnectorSettings that reads a fixed dict instead of env/config vars."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(CONFIG_DICT)


@pytest.fixture(name="mock_opencti_connector_helper")
def fixture_mock_opencti_connector_helper(monkeypatch):
    """Neutralize pycti side effects (network, threads, schedulers)."""
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    """Settings expose a pycti-compatible config dict."""
    settings = StubConnectorSettings()

    helper_config = settings.to_helper_config()

    assert isinstance(helper_config, dict)
    assert helper_config["opencti"]["url"].rstrip("/") == "http://opencti:8080"
    # pycti needs the real token, so it must not be masked.
    assert helper_config["opencti"]["token"] == "test-opencti-token"
    assert helper_config["connector"]["type"] == "INTERNAL_ENRICHMENT"
    assert helper_config["connector"]["scope"] == "IPv4-Addr,IPv6-Addr,Domain-Name"


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """The helper is built from ``to_helper_config()``, as ``main.py`` does."""
    settings = StubConnectorSettings()

    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://opencti:8080/"
    assert helper.opencti_token == "test-opencti-token"
    assert helper.connect_id == "test-connector-id"
    assert helper.connect_name == "isMalicious"
    assert helper.connect_scope == "IPv4-Addr,IPv6-Addr,Domain-Name"
    assert helper.connect_auto is False
    assert helper.log_level == "INFO"


def test_connector_is_instantiated(mock_opencti_connector_helper):
    """The connector accepts the settings object and the helper."""
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = IsMaliciousConnector(settings, helper)

    assert connector.config is settings
    assert connector.helper is helper
    assert connector.api_url == "https://api.ismalicious.com"
    assert connector.api_key == "test-api-key"


def test_main_builds_a_playbook_compatible_helper(monkeypatch):
    """The manifest declares playbook support: the helper MUST be playbook compatible."""
    helper_cls = MagicMock()
    connector_cls = MagicMock()
    monkeypatch.setattr("pycti.OpenCTIConnectorHelper", helper_cls)
    monkeypatch.setattr("connector.IsMaliciousConnector", connector_cls)
    monkeypatch.setattr("connector.ConnectorSettings", MagicMock())

    main_path = Path(__file__).parent.parent / "src" / "main.py"
    runpy.run_path(str(main_path), run_name="__main__")

    assert helper_cls.call_args.kwargs["playbook_compatible"] is True
    connector_cls.return_value.run.assert_called_once()
