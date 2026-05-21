from unittest.mock import patch

import pytest

from internal_enrichment_connector.config_loader import ConfigConnector, TLP_MARKING_IDS


@pytest.fixture(autouse=True)
def clear_splunk_env(monkeypatch):
    for key in (
        "SPLUNK_HOST",
        "SPLUNK_PORT",
        "SPLUNK_TOKEN",
        "SPLUNK_APP",
        "SPLUNK_SCHEME",
        "SPLUNK_VERIFY_SSL",
        "SPLUNK_SEARCH_EARLIEST",
        "SPLUNK_SEARCH_LATEST",
        "SPLUNK_SEARCH_TIMEOUT",
        "SPLUNK_WAIT_SECONDS",
        "SPLUNK_MAX_RESULTS",
        "SPLUNK_SIGHTING_TLP",
        "SPLUNK_OBSERVABLE_TLP",
    ):
        monkeypatch.delenv(key, raising=False)


def _build_config(load):
    with patch.object(ConfigConnector, "_load_config", return_value=load):
        return ConfigConnector()


def test_config_loads_yaml_values(monkeypatch):
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    config = _build_config(
        {
            "splunk-search": {
                "host": "splunk.local",
                "token": "yaml-token",
                "port": 8090,
                "app": "enterprise-security",
                "scheme": "http",
                "verify_ssl": False,
                "earliest_time": "-7d@d",
                "latest_time": "now",
                "timeout": 45,
                "wait_seconds": 5,
                "max_results": 250,
                "sighting_tlp": "TLP:GREEN",
                "observable_tlp": "TLP:RED",
            }
        }
    )

    assert config.splunk_host == "splunk.local"
    assert config.splunk_token == "yaml-token"
    assert config.splunk_port == 8090
    assert config.splunk_app == "enterprise-security"
    assert config.splunk_scheme == "http"
    assert config.splunk_verify_ssl is False
    assert config.splunk_search_earliest == "-7d@d"
    assert config.splunk_timeout == 45
    assert config.splunk_wait_seconds == 5
    assert config.splunk_max_results == 250
    assert config.sighting_tlp == TLP_MARKING_IDS["TLP:GREEN"]
    assert config.observable_tlp == TLP_MARKING_IDS["TLP:RED"]


def test_config_env_overrides_yaml(monkeypatch):
    monkeypatch.setenv("SPLUNK_HOST", "env-splunk")
    monkeypatch.setenv("SPLUNK_TOKEN", "env-token")
    monkeypatch.setenv("SPLUNK_PORT", "9999")
    config = _build_config(
        {"splunk-search": {"host": "yaml-splunk", "token": "yaml-token"}}
    )

    assert config.splunk_host == "env-splunk"
    assert config.splunk_token == "env-token"
    assert config.splunk_port == 9999


def test_config_uses_defaults(monkeypatch):
    monkeypatch.setenv("SPLUNK_HOST", "splunk")
    monkeypatch.setenv("SPLUNK_TOKEN", "token")
    config = _build_config({})

    assert config.splunk_port == 8089
    assert config.splunk_app == "search"
    assert config.splunk_scheme == "https"
    assert config.splunk_verify_ssl is True
    assert config.splunk_search_earliest == "-30d@d"
    assert config.splunk_search_latest == "now"
    assert config.splunk_timeout == 60
    assert config.splunk_wait_seconds == 2
    assert config.splunk_max_results == 1000
    assert config.sighting_tlp == TLP_MARKING_IDS["TLP:AMBER"]
    assert config.observable_tlp == TLP_MARKING_IDS["TLP:AMBER"]


def test_config_requires_host_and_token(monkeypatch):
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)

    with pytest.raises(ValueError, match="SPLUNK_HOST, SPLUNK_TOKEN"):
        _build_config({})


def test_config_rejects_unknown_tlp(monkeypatch):
    monkeypatch.setenv("SPLUNK_HOST", "splunk")
    monkeypatch.setenv("SPLUNK_TOKEN", "token")

    with pytest.raises(ValueError, match="Unsupported TLP"):
        _build_config({"splunk-search": {"observable_tlp": "TLP:BLUE"}})
