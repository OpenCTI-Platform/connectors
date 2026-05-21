from unittest.mock import Mock

import pytest
import stix2
from pycti import CustomObservableHostname, CustomObservableUserAgent, Identity

from internal_enrichment_connector.splunk_result_parser import (
    parse_observables_and_incident,
)


@pytest.fixture
def helper():
    mock = Mock()
    mock.connector_logger = Mock()
    mock.connector_logger.debug = Mock()
    mock.connector_logger.info = Mock()
    mock.connector_logger.error = Mock()
    mock.connector_logger.warning = Mock()
    return mock


@pytest.fixture
def author():
    return stix2.Identity(
        id="identity--be770ee6-7a09-43ac-af89-f61ddcd8777d",
        name="SIEM Platform",
        identity_class="securityplatform",
        created_by_ref=Identity.generate_id(
            name="SIEM Platform", identity_class="securityplatform"
        ),
        allow_custom=True,
        custom_properties={
            "x_opencti_identity_type": "Security Platform",
            "x_opencti_identity_subtype": "SIEM",
        },
    )


@pytest.fixture
def tlp_marking():
    return "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"


def test_parse_web_traffic(helper, author):
    result = {
        "sourcetype": "suricata:http",
        "vendor_product": "Suricata IDS",
        "http_method": "GET",
        "url": "https://example.com",
        "http_user_agent": "Mozilla/5.0",
        "src": "192.168.1.1",
        "src_ip": "192.168.1.1",
        "dest": "93.184.216.34",
        "dest_ip": "93.184.216.34",
        "host": "sensor-01",
        "status": 200,
        "bytes": 1234,
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        helper, result=result, author=author
    )

    assert len(observables) >= 4
    assert any(isinstance(obs, stix2.URL) for obs in observables)
    assert any(isinstance(obs, stix2.IPv4Address) for obs in observables)
    assert any(isinstance(obs, CustomObservableUserAgent) for obs in observables)
    assert any(isinstance(obs, stix2.Software) for obs in observables)
    assert source_identity is not None
    assert source_identity.name == "sensor-01"
    assert source_identity.identity_class == "system"
    assert all(sighting.where_sighted_refs == [source_identity.id] for sighting in sightings)


def test_parse_web_traffic_with_threat_intel(helper, author):
    result = {
        "sourcetype": "suricata:http",
        "url": "https://example.com",
        "src": "192.168.1.1",
        "threat_key": "abc123",
        "threat_match_value": "192.168.1.1",
        "threat_match_type": "ip",
        "threat_label": "malicious-actor,c2",
        "threat_source": "AlienVault",
        "confidence": "90",
        "threat_description": "Known C2 IP address",
    }
    observables, _, sightings = parse_observables_and_incident(
        helper, result, author=author
    )

    ip_observable = next(
        obs for obs in observables if isinstance(obs, stix2.IPv4Address)
    )
    assert ip_observable.x_opencti_score == 90
    assert "malicious-actor" in ip_observable.x_opencti_labels
    assert ip_observable.x_opencti_description == "Known C2 IP address"
    assert all(sighting.confidence == 90 for sighting in sightings)
    assert all(sighting.description == "Known C2 IP address" for sighting in sightings)


def test_parse_network_traffic(helper, author):
    result = {
        "sourcetype": "firewall",
        "src": "10.0.0.1",
        "dest": "192.168.1.1",
        "dest_port": 443,
        "protocol": "tcp",
    }
    observables, _, sightings = parse_observables_and_incident(
        helper, result, author=author
    )
    assert len(observables) >= 3
    assert len(sightings) == len(observables)


def test_parse_dns_traffic(helper, author):
    result = {
        "sourcetype": "dns",
        "src": "192.168.1.10",
        "query": "example.com",
        "answer": "93.184.216.34",
    }
    observables, _, sightings = parse_observables_and_incident(
        helper, result, author=author
    )
    assert len(observables) >= 3
    assert len(sightings) == len(observables)


def test_with_tlp_marking(helper, author, tlp_marking):
    result = {"sourcetype": "test", "url": "https://example.com"}
    observables, _, _ = parse_observables_and_incident(
        helper, result, author=author, marking_id=tlp_marking
    )
    for obs in observables:
        assert obs.object_marking_refs == [tlp_marking]


def test_empty_result(helper, author):
    observables, source_identity, sightings = parse_observables_and_incident(
        helper, {}, author=author
    )
    assert observables == []
    assert source_identity is None
    assert sightings == []


def test_unknown_values_filtered(helper, author):
    result = {
        "sourcetype": "test",
        "user": "unknown",
        "src": "0.0.0.0",
        "dest": "unknown",
    }
    observables, _, _ = parse_observables_and_incident(helper, result, author=author)
    assert len(observables) == 1
    assert isinstance(observables[0], stix2.Software)


def test_system_identity_creation_from_host(helper, author):
    result = {
        "sourcetype": "zeek:conn",
        "vendor_product": "Zeek Network Monitor",
        "host": "zeek-sensor",
    }
    _, source_identity, _ = parse_observables_and_incident(
        helper, result, author=author
    )
    assert source_identity is not None
    assert source_identity.name == "zeek-sensor"
    assert source_identity.identity_class == "system"
    assert "sourcetype::zeek:conn" in source_identity.objectLabel


def test_sighting_attribution(helper, author):
    result = {"sourcetype": "test", "src": "192.168.1.1"}
    _, source_identity, sightings = parse_observables_and_incident(
        helper, result=result, author=author
    )
    assert source_identity is None
    for sighting in sightings:
        assert sighting.where_sighted_refs == [author.id]
        assert sighting.created_by_ref == author.id


def test_sighting_structure(helper, author):
    result = {
        "sourcetype": "test",
        "src": "192.168.1.1",
        "threat_description": "Test description",
        "confidence": "90",
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        helper, result, author=author
    )
    ip_observable = next(
        obs for obs in observables if isinstance(obs, stix2.IPv4Address)
    )

    ip_sighting = next(
        sighting
        for sighting in sightings
        if sighting.get("x_opencti_sighting_of_ref") == ip_observable.id
    )
    assert ip_sighting.sighting_of_ref == "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
    assert ip_sighting.confidence == 90
    assert ip_sighting.description == "Test description"
    assert source_identity is None
    assert ip_sighting.where_sighted_refs == [author.id]
    assert ip_sighting.created_by_ref == author.id
    assert "first_seen" in ip_sighting
    assert "last_seen" in ip_sighting
