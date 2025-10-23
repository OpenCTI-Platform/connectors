import pytest
from src.internal_enrichment_connector.splunk_result_parser import (
    parse_observables_and_incident,
)
import stix2
from pycti import CustomObservableHostname, CustomObservableUserAgent, Identity


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


def test_parse_web_traffic(author: Identity):
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
        "status": 200,
        "bytes": 1234,
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        result=result, author=author
    )

    # Check observables (should include Software but it won't have a sighting)
    assert len(observables) >= 4  # URL, IPs, User-Agent, Software(sourcetype)
    assert any(isinstance(obs, stix2.URL) for obs in observables)
    assert any(isinstance(obs, stix2.IPv4Address) for obs in observables)
    assert any(isinstance(obs, CustomObservableUserAgent) for obs in observables)
    assert any(isinstance(obs, stix2.Software) for obs in observables)

    # Check source identity
    assert source_identity is not None
    assert source_identity.name == "Suricata IDS"
    assert source_identity.identity_class == "system"

    # Check sightings (should not include Software)
    sightable_observables = [
        obs for obs in observables if not isinstance(obs, stix2.Software)
    ]
    assert len(sightings) == len(sightable_observables)
    for sighting in sightings:
        assert isinstance(sighting, stix2.Sighting)
        assert sighting.where_sighted_refs == [source_identity.id]


def test_parse_web_traffic_with_threat_intel(author: Identity):
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
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )

    # Check that threat intel data is added to custom properties
    ip_observable = next(
        obs for obs in observables if isinstance(obs, stix2.IPv4Address)
    )
    assert ip_observable.x_opencti_score == 90
    assert "malicious-actor" in ip_observable.x_opencti_labels
    assert ip_observable.x_opencti_description == "Known C2 IP address"

    # Check sightings include threat intel context
    for sighting in sightings:
        assert sighting.confidence == 90
        assert sighting.description == "Known C2 IP address"


def test_parse_network_traffic(author: Identity):
    result = {
        "sourcetype": "firewall",
        "src": "10.0.0.1",
        "dest": "192.168.1.1",
        "dest_port": 443,
        "protocol": "tcp",
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )
    assert len(observables) >= 3  # Source IP, Dest IP, Software(sourcetype)
    assert len(sightings) == len(observables)


def test_parse_dns_traffic(author: Identity):
    result = {
        "sourcetype": "dns",
        "src": "192.168.1.10",
        "query": "example.com",
        "answer": "93.184.216.34",
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )
    assert len(observables) >= 3  # Domain, IP, Software(sourcetype)
    assert len(sightings) == len(observables)


def test_with_tlp_marking(author: Identity):
    result = {"sourcetype": "test", "url": "https://example.com"}
    tlp = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author, tlp=tlp
    )
    for obs in observables:
        assert obs.object_marking_refs == [tlp]


def test_empty_result(author: Identity):
    result = {}
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )
    assert len(observables) == 0
    assert source_identity is None
    assert len(sightings) == 0


def test_unknown_values_filtered(author: Identity):
    result = {
        "sourcetype": "test",
        "user": "unknown",
        "src": "0.0.0.0",
        "dest": "unknown",
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )
    # Should only have sourcetype Software observable
    assert len(observables) == 1
    assert isinstance(observables[0], stix2.Software)


def test_sourcetype_identity_creation(author: Identity):
    result = {"sourcetype": "zeek:conn", "vendor_product": "Zeek Network Monitor"}
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )
    assert source_identity is not None
    assert source_identity.name == "Zeek Network Monitor"
    assert source_identity.identity_class == "system"
    assert source_identity.x_opencti_identity_subtype == "splunk_sourcetype"


def test_sighting_attribution(author: Identity):
    result = {"sourcetype": "test", "src": "192.168.1.1"}
    observables, source_identity, sightings = parse_observables_and_incident(
        result=result, author=author
    )
    for sighting in sightings:
        assert sighting.where_sighted_refs == [source_identity.id]
        assert sighting.created_by_ref == author.id


def test_sighting_structure(author: Identity):
    """Test that sightings are created with the correct structure."""
    result = {
        "sourcetype": "test",
        "src": "192.168.1.1",
        "threat_description": "Test description",
        "confidence": "90",
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        result, author=author
    )

    # Get the IP observable
    ip_observable = next(
        obs for obs in observables if isinstance(obs, stix2.IPv4Address)
    )

    for sighting in sightings:
        if "x_opencti_sighting_of_ref" in sighting.custom_properties:
            # Check the sighting references the observable correctly
            assert (
                sighting.custom_properties["x_opencti_sighting_of_ref"]
                == ip_observable.id
            )
            # Check the fake indicator ID is used
            assert (
                sighting.sighting_of_ref
                == "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
            )
            # Check other properties
            assert sighting.confidence == 90
            assert sighting.description == "Test description"
            assert sighting.where_sighted_refs == [source_identity.id]
            assert sighting.created_by_ref == author.id
            assert "first_seen" in sighting
            assert "last_seen" in sighting
