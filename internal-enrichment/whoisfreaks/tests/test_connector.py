from unittest.mock import MagicMock

import main
import pytest
from main import WhoisFreaksConnector


@pytest.fixture
def mock_dependencies(monkeypatch):
    # Mock ConfigVariables
    mock_cfg = MagicMock()
    mock_cfg.opencti_url = "http://localhost:8080"
    mock_cfg.opencti_token = "mock-token"
    mock_cfg.connector_id = "mock-connector-id"
    mock_cfg.connector_type = "INTERNAL_ENRICHMENT"
    mock_cfg.connector_name = "WhoisFreaks"
    mock_cfg.connector_scope = "Domain-Name,IPv4-Addr,IPv6-Addr"
    mock_cfg.connector_auto = False
    mock_cfg.connector_log_level = "INFO"
    mock_cfg.connector_confidence_level = 100
    mock_cfg.whoisfreaks_api_key = "mock-api-key"
    mock_cfg.tlp_level = "amber+strict"

    # Mock OpenCTIConnectorHelper
    mock_h = MagicMock()
    mock_h.api.work.initiate_work.return_value = "mock-work-id"
    mock_h.stix2_create_bundle.return_value = {"id": "bundle--123"}
    mock_h.send_stix2_bundle.return_value = [{"id": "bundle--123"}]

    # Apply monkeypatch mocks
    monkeypatch.setattr(main, "ConfigVariables", MagicMock(return_value=mock_cfg))
    monkeypatch.setattr(main, "OpenCTIConnectorHelper", MagicMock(return_value=mock_h))

    return mock_cfg, mock_h


def test_connector_init(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    assert connector.config == cfg
    assert connector.helper == helper
    assert connector.client.api_key == "mock-api-key"
    assert connector.builder.author.name == "WhoisFreaks"


def test_process_message_empty_entity(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    result = connector.process_message({"stix_objects": [], "entity_id": "entity-123"})
    assert result == "Sent 1 bundle(s)" or result == "No STIX objects to send"


def test_process_message_unsupported_type(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    data = {
        "stix_objects": [{"id": "file--123"}],
        "enrichment_entity": {
            "entity_type": "StixFile",
            "observable_value": "test.exe",
        },
    }

    result = connector.process_message(data)
    assert result == "Sent 1 bundle(s)"


def test_process_message_domain_enrichment(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    # Mock client lookups to return valid dicts
    connector.client.live_whois_lookup = MagicMock(
        return_value={"registrar_name": "GoDaddy"}
    )
    connector.client.live_dns_lookup = MagicMock(
        return_value={"dns_records": [{"type": "A", "address": "1.2.3.4"}]}
    )
    connector.client.ssl_lookup = MagicMock(return_value={"sslCertificates": []})
    connector.client.subdomains_lookup = MagicMock(return_value={"subdomains": []})

    data = {
        "stix_objects": [{"id": "domain--123"}],
        "enrichment_entity": {
            "entity_type": "Domain-Name",
            "observable_value": "example.com",
        },
    }

    result = connector.process_message(data)

    assert "Successfully enriched example.com with" in result
    assert helper.send_stix2_bundle.call_count == 3
    helper.api.work.to_processed.assert_called_once()


def test_process_message_domain_enrichment_no_data(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    # Mock client lookups to return None
    connector.client.live_whois_lookup = MagicMock(return_value=None)
    connector.client.live_dns_lookup = MagicMock(return_value=None)
    connector.client.ssl_lookup = MagicMock(return_value=None)
    connector.client.subdomains_lookup = MagicMock(return_value=None)

    data = {
        "stix_objects": [{"id": "domain--123"}],
        "enrichment_entity": {
            "entity_type": "Domain-Name",
            "observable_value": "example.com",
        },
    }

    result = connector.process_message(data)

    assert result == "Sent 1 bundle(s)"
    helper.send_stix2_bundle.assert_called_once()


def test_process_message_ip_enrichment(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    # Mock client lookups
    connector.client.ip_geolocation_lookup = MagicMock(
        return_value={"location": {"country_name": "United States"}}
    )
    connector.client.ip_reputation_lookup = MagicMock(
        return_value={"security": {"threat_score": 85}}
    )
    connector.client.reverse_dns_lookup = MagicMock(return_value={"dns_records": []})

    data = {
        "stix_objects": [{"id": "ip--123"}],
        "enrichment_entity": {
            "entity_type": "IPv4-Addr",
            "observable_value": "1.2.3.4",
        },
    }

    result = connector.process_message(data)

    assert "Successfully enriched 1.2.3.4 with" in result
    assert helper.send_stix2_bundle.call_count == 3
    helper.api.work.to_processed.assert_called_once()


def test_process_message_exception(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    # Cause lookup to raise exception
    connector.client.live_whois_lookup = MagicMock(side_effect=Exception("API failure"))

    data = {
        "stix_objects": [{"id": "domain--123"}],
        "enrichment_entity": {
            "entity_type": "Domain-Name",
            "observable_value": "example.com",
        },
    }

    result = connector.process_message(data)

    # Enrichment fails before any bundles are produced, so initiate_work is never
    # called (VC317). process_message still returns a clear, formatted error.
    assert "Error during processing of example.com: API failure" in result
    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()


def test_connector_start(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()

    connector.start()
    helper.listen.assert_called_once_with(connector.process_message)
