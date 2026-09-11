"""Integration-style smoke tests for the Zetalytics DNS connector."""

import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from zetalytics_dns.connector import Connector
from zetalytics_dns.settings import ConfigLoader


def make_stub_config(stub_config_dict: dict[str, Any]) -> ConfigLoader:
    """Return a ConfigLoader instance backed by stub_config_dict.

    Uses a closure so Pydantic never sees the dict as a private model field.
    """

    class _Stub(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:  # type: ignore[override]
            return handler(stub_config_dict)

    return _Stub()  # type: ignore[call-arg]


def test_config_loader_instantiates(stub_config_dict):
    """ConfigLoader should load successfully from a valid config dict."""
    config = make_stub_config(stub_config_dict)

    assert config.zetalytics.mode == "manual"
    assert config.zetalytics.max_results == 100
    assert config.zetalytics.include_live_dns is True
    assert config.zetalytics.include_subdomains is True
    assert config.zetalytics.include_historical_whois is False


def test_config_loader_to_helper_config(stub_config_dict):
    """to_helper_config() must return a dict compatible with OpenCTIConnectorHelper."""
    config = make_stub_config(stub_config_dict)
    helper_config = config.to_helper_config()

    assert isinstance(helper_config, dict)
    assert helper_config["opencti"]["url"] == "http://localhost:8080/"


def test_opencti_helper_instantiates(mock_opencti_helper, stub_config_dict):
    """OpenCTIConnectorHelper should initialise from the settings dict."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    # lookback_days=90 in stub_config_dict -> "3 months" is appended to the connector name.
    assert helper.connect_name == "Zetalytics DNS - Test (3 months)"


def test_connector_instantiates(mock_opencti_helper, stub_config_dict):
    """Connector should initialise and expose config and helper."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    assert connector.config is config
    assert connector.helper is helper
    assert connector.client is mock_client


def test_connector_skips_high_tlp(mock_opencti_helper, stub_config_dict):
    """process_message should skip enrichment when the observable TLP is too high."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=False)
    helper.connector_logger = MagicMock()
    helper.connector_logger.info = MagicMock(return_value="skipped")

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
        },
        "stix_entity": {
            "type": "domain-name",
            "value": "example.com",
            "id": "domain-name--00000000-0000-4000-8000-000000000001",
        },
        "stix_objects": [],
    }

    connector.process_message(data)
    mock_client.passive_dns_for_domain.assert_not_called()


def test_connector_skips_unsupported_type(mock_opencti_helper, stub_config_dict):
    """process_message should skip enrichment for unsupported observable types."""
    config = make_stub_config(stub_config_dict)
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    helper.check_max_tlp = MagicMock(return_value=True)
    helper.connector_logger = MagicMock()
    helper.connector_logger.info = MagicMock(return_value="skipped")

    mock_client = MagicMock()
    connector = Connector(config=config, helper=helper, client=mock_client)

    data = {
        "enrichment_entity": {"objectMarking": []},
        "stix_entity": {
            "type": "url",
            "value": "https://example.com",
            "id": "url--00000000-0000-4000-8000-000000000002",
        },
        "stix_objects": [],
    }

    connector.process_message(data)
    mock_client.passive_dns_for_domain.assert_not_called()
    mock_client.passive_dns_for_ip.assert_not_called()


def test_main_syncs_connector_name_env_var_before_helper_init(monkeypatch):
    """main() must sync CONNECTOR_NAME in the environment to the lookback-suffixed name.

    pycti's get_config_variable() checks the raw environment variable *before* the
    config dict passed to OpenCTIConnectorHelper, so without this sync it would
    silently ignore ConfigLoader's suffixed name (e.g. "... (2 years)") and register
    the connector in OpenCTI using whatever CONNECTOR_NAME is set to in the
    environment/compose file.
    """
    monkeypatch.setenv("CONNECTOR_NAME", "Zetalytics DNS - Deep Investigation")

    fake_config = MagicMock()
    fake_config.connector.name = "Zetalytics DNS - Deep Investigation (2 years)"
    fake_config.to_helper_config.return_value = {
        "connector": {"name": fake_config.connector.name}
    }
    fake_config.zetalytics.token.get_secret_value.return_value = "zt-token"
    fake_config.zetalytics.request_timeout = 30

    mock_config_loader_cls = MagicMock(return_value=fake_config)
    mock_helper_cls = MagicMock()
    mock_client_cls = MagicMock()
    mock_connector_cls = MagicMock()

    monkeypatch.setattr("zetalytics_dns.settings.ConfigLoader", mock_config_loader_cls)
    monkeypatch.setattr("pycti.OpenCTIConnectorHelper", mock_helper_cls)
    monkeypatch.setattr("zetalytics_dns.client.ZetalyticsClient", mock_client_cls)
    monkeypatch.setattr("zetalytics_dns.connector.Connector", mock_connector_cls)

    from zetalytics_dns.__main__ import main

    main()

    assert os.environ["CONNECTOR_NAME"] == "Zetalytics DNS - Deep Investigation (2 years)"
    _, helper_kwargs = mock_helper_cls.call_args
    assert helper_kwargs["config"]["connector"]["name"] == "Zetalytics DNS - Deep Investigation (2 years)"
    mock_connector_cls.return_value.run.assert_called_once()
