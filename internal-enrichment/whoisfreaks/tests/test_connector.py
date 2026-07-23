import pytest
from unittest.mock import MagicMock, patch
import main
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
    
    # Mock OpenCTIConnectorHelper
    mock_h = MagicMock()
    mock_h.api.work.initiate_work.return_value = "mock-work-id"
    
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

def test_get_entity_info_cyber_observable(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    
    # Mock cyber observable read
    helper.api.stix_cyber_observable.read.return_value = {
        "entity_type": "Domain-Name",
        "observable_value": "example.com"
    }
    
    obs_type, obs_val = connector._get_entity_info("entity-123")
    assert obs_type == "Domain-Name"
    assert obs_val == "example.com"
    helper.api.stix_cyber_observable.read.assert_called_once_with(id="entity-123")

def test_get_entity_info_domain_object(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    
    # Mock cyber observable read returns None, domain object read returns entity
    helper.api.stix_cyber_observable.read.return_value = None
    helper.api.stix_domain_object.read.return_value = {
        "entity_type": "Domain-Name",
        "value": "domain-obj.com"
    }
    
    obs_type, obs_val = connector._get_entity_info("entity-456")
    assert obs_type == "Domain-Name"
    assert obs_val == "domain-obj.com"
    helper.api.stix_cyber_observable.read.assert_called_once_with(id="entity-456")
    helper.api.stix_domain_object.read.assert_called_once_with(id="entity-456")

def test_get_entity_info_not_found(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    
    helper.api.stix_cyber_observable.read.return_value = None
    helper.api.stix_domain_object.read.return_value = None
    
    obs_type, obs_val = connector._get_entity_info("entity-789")
    assert obs_type is None
    assert obs_val is None

def test_process_message_empty_entity(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    connector._get_entity_info = MagicMock(return_value=(None, None))
    
    result = connector.process_message({"entity_id": "entity-123"})
    assert result == "Entity or value missing"

def test_process_message_unsupported_type(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    connector._get_entity_info = MagicMock(return_value=("File", "test.exe"))
    
    result = connector.process_message({"entity_id": "entity-123"})
    assert result == "Unsupported observable type"
    helper.api.work.to_processed.assert_called_once_with("mock-work-id", "Unsupported observable type")

def test_process_message_domain_enrichment(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    connector._get_entity_info = MagicMock(return_value=("Domain-Name", "example.com"))
    
    # Mock client lookups to return valid dicts
    connector.client.live_whois_lookup = MagicMock(return_value={"registrar_name": "GoDaddy"})
    connector.client.live_dns_lookup = MagicMock(return_value={"dns_records": [{"type": "A", "address": "1.2.3.4"}]})
    connector.client.ssl_lookup = MagicMock(return_value={"sslCertificates": []})
    connector.client.subdomains_lookup = MagicMock(return_value={"subdomains": []})
    
    result = connector.process_message({"entity_id": "entity-123"})
    
    assert "Successfully enriched example.com with" in result
    assert helper.send_stix2_bundle.call_count == 4
    helper.api.work.to_processed.assert_called_once()

def test_process_message_domain_enrichment_no_data(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    connector._get_entity_info = MagicMock(return_value=("Domain-Name", "example.com"))
    
    # Mock client lookups to return None
    connector.client.live_whois_lookup = MagicMock(return_value=None)
    connector.client.live_dns_lookup = MagicMock(return_value=None)
    connector.client.ssl_lookup = MagicMock(return_value=None)
    connector.client.subdomains_lookup = MagicMock(return_value=None)
    
    result = connector.process_message({"entity_id": "entity-123"})
    
    assert "No threat intelligence data found on WhoisFreaks for example.com." in result
    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.to_processed.assert_called_once_with("mock-work-id", "No threat intelligence data found on WhoisFreaks for example.com.")

def test_process_message_ip_enrichment(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    connector._get_entity_info = MagicMock(return_value=("IPv4-Addr", "1.2.3.4"))
    
    # Mock client lookups
    connector.client.ip_geolocation_lookup = MagicMock(return_value={"location": {"country_name": "United States"}})
    connector.client.ip_reputation_lookup = MagicMock(return_value={"security": {"threat_score": 85}})
    connector.client.reverse_dns_lookup = MagicMock(return_value={"dns_records": []})
    
    result = connector.process_message({"entity_id": "entity-123"})
    
    assert "Successfully enriched 1.2.3.4 with" in result
    assert helper.send_stix2_bundle.call_count == 3
    helper.api.work.to_processed.assert_called_once()

def test_process_message_exception(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    connector._get_entity_info = MagicMock(return_value=("Domain-Name", "example.com"))
    
    # Cause lookup to raise exception
    connector.client.live_whois_lookup = MagicMock(side_effect=Exception("API failure"))
    
    result = connector.process_message({"entity_id": "entity-123"})
    
    assert "Error during processing of example.com: API failure" in result
    helper.api.work.to_processed.assert_called_once_with("mock-work-id", "Error during processing of example.com: API failure", in_error=True)

def test_connector_start(mock_dependencies):
    cfg, helper = mock_dependencies
    connector = WhoisFreaksConnector()
    
    connector.start()
    helper.listen.assert_called_once_with(connector.process_message)
