from unittest.mock import Mock

import pytest
import stix2
from internal_enrichment_connector.splunk_result_parser import (
    create_negative_sighting,
    is_no_results_row,
    parse_observables_and_incident,
)
from internal_enrichment_connector.utils.utils import detect_observable_type
from pycti import CustomObservableHostname, CustomObservableUserAgent, Identity


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


# ---------------------------------------------------------------------------
# is_no_results_row
# ---------------------------------------------------------------------------


def test_is_no_results_row_canonical_no_results():
    """observable_value == 'No Results' → True."""
    assert is_no_results_row({"observable_value": "No Results"})


def test_is_no_results_row_canonical_na():
    """observable_value == 'N/A' (case-insensitive) → True."""
    assert is_no_results_row({"observable_value": "N/A"})
    assert is_no_results_row({"observable_value": "n/a"})


def test_is_no_results_row_canonical_empty():
    """observable_value present but empty → True."""
    assert is_no_results_row({"observable_value": ""})
    assert is_no_results_row({"observable_value": "   "})


def test_is_no_results_row_valid_observable_value():
    """Real observable_value → False even when sourcetype/index are 'N/A'."""
    row = {"observable_value": "10.0.0.1", "sourcetype": "N/A", "index": "N/A"}
    assert not is_no_results_row(row)


def test_is_no_results_row_valid_ip():
    """A genuine IP as observable_value → False."""
    assert not is_no_results_row({"observable_value": "192.168.1.1"})


def test_is_no_results_row_fallback_both_na():
    """No observable_value key; sourcetype == 'N/A' AND index == 'N/A' → True."""
    assert is_no_results_row({"sourcetype": "N/A", "index": "N/A"})


def test_is_no_results_row_fallback_only_sourcetype():
    """No observable_value key; only sourcetype is 'N/A' (index is real) → False."""
    assert not is_no_results_row({"sourcetype": "N/A", "index": "main"})


def test_is_no_results_row_empty_dict():
    """Empty row without observable_value key and no N/A fields → False."""
    assert not is_no_results_row({})


# ---------------------------------------------------------------------------
# create_negative_sighting
# ---------------------------------------------------------------------------


def test_create_negative_sighting_fields(author):
    indicator_stix_id = "indicator--59e1c61c-a9fb-429b-a1c1-c80116cc8e1e"
    sighting = create_negative_sighting(
        indicator_stix_id=indicator_stix_id,
        indicator_name="Test Indicator",
        search_type="dest",
        earliest="-30d@d",
        latest="now",
        splunk_host="splunk.example.com",
        query="| tstats count from datamodel=Network_Traffic",
        author=author,
        confidence=100,
        sighting_marking_id=None,
    )

    assert sighting.type == "sighting"
    # Must be the real indicator STIX ID, not the fake placeholder
    assert sighting.sighting_of_ref == indicator_stix_id
    assert sighting.sighting_of_ref.startswith("indicator--")
    assert sighting.where_sighted_refs == [author.id]
    assert sighting.get("x_opencti_negative") is True
    assert sighting.confidence == 100
    assert "No results found" in sighting.description
    assert "dest" in sighting.description
    assert "splunk.example.com" in sighting.description
    # The negative flag is the authoritative signal — the STIX spec requires a
    # count field on Sighting objects, but x_opencti_negative=True conveys absence


def test_create_negative_sighting_query_abbreviated(author):
    """Negative sighting description follows the new structured format; query is omitted."""
    long_query = "| tstats " + "x" * 200
    sighting = create_negative_sighting(
        indicator_stix_id="indicator--59e1c61c-a9fb-429b-a1c1-c80116cc8e1e",
        indicator_name="Test",
        search_type="custom",
        earliest="-7d@d",
        latest="now",
        splunk_host="splunk.example.com",
        query=long_query,
        author=author,
        template_name="My Search Template",
    )
    # Query is no longer embedded in the description
    assert long_query not in sighting.description
    # Template name must appear
    assert "My Search Template" in sighting.description
    # Time range must appear
    assert "-7d@d" in sighting.description
    assert "now" in sighting.description


def test_create_negative_sighting_with_marking(author):
    marking = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    sighting = create_negative_sighting(
        indicator_stix_id="indicator--59e1c61c-a9fb-429b-a1c1-c80116cc8e1e",
        indicator_name="Test",
        search_type="src",
        earliest="-30d@d",
        latest="now",
        splunk_host="splunk.example.com",
        query="| search *",
        author=author,
        sighting_marking_id=marking,
    )
    assert marking in sighting.object_marking_refs


# ---------------------------------------------------------------------------
# parse_observables_and_incident — main function tests
# ---------------------------------------------------------------------------


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
    # sourcetype (suricata:http → Infrastructure) produces vendor + SecurityPlatform identities
    assert any(
        isinstance(obs, stix2.Identity) and obs.identity_class == "organization"
        for obs in observables
    )
    assert source_identity is not None
    assert source_identity.name == "OISF Suricata"  # vendor + product from YAML
    assert source_identity.identity_class == "system"
    # Sighting description must include sourcetype metadata
    for sighting in sightings:
        assert "sourcetype: suricata:http" in sighting.description
    assert all(
        sighting.where_sighted_refs == [source_identity.id] for sighting in sightings
    )


def test_sighting_count_from_result(helper, author):
    """Sighting count must reflect the Splunk event count field."""
    result = {
        "src": "10.0.0.1",
        "count": "42",
        "sourcetype": "fw",
        "index": "main",
    }
    _, _, sightings = parse_observables_and_incident(helper, result, author=author)
    assert sightings, "Expected at least one sighting"
    assert all(s.count == 42 for s in sightings)


def test_sighting_count_invalid_defaults_to_one(helper, author):
    """Non-integer count field → sighting count defaults to 1."""
    result = {"src": "10.0.0.1", "count": "N/A"}
    _, _, sightings = parse_observables_and_incident(helper, result, author=author)
    assert all(s.count == 1 for s in sightings)


def test_sighting_observable_value_stored(helper, author):
    """Sightings must carry x_opencti_observable_value for merge-key use."""
    result = {"src": "172.16.0.1"}
    _, _, sightings = parse_observables_and_incident(helper, result, author=author)
    assert sightings
    ip_sighting = next(
        (s for s in sightings if s.get("x_opencti_observable_value") == "172.16.0.1"),
        None,
    )
    assert ip_sighting is not None


def test_structured_sighting_description(helper, author):
    """Sighting description must include the structured metadata template."""
    result = {
        "src": "10.1.1.1",
        "sourcetype": "aws:cloudwatchlogs:vpcflow",
        "index": "security",
        "action": "allow",
        "total_bytes": "1024",
        "count": "5",
    }
    _, _, sightings = parse_observables_and_incident(
        helper, result, author=author, template_name="VPC Flow Search"
    )
    assert sightings
    desc = sightings[0].description
    # Vendor/product header replaces the old "Observed in Splunk" header
    assert "Observed in Amazon Web Services VPC Flow Logs" in desc
    assert "Search template: VPC Flow Search" in desc
    assert "sourcetype: aws:cloudwatchlogs:vpcflow" in desc
    assert "index: security" in desc
    assert "action: allow" in desc
    assert "bytes: 1024" in desc
    assert "events: 5" in desc


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
    assert len(observables) >= 2
    # Each sightable observable (IPv4 addresses) gets a sighting; Identity objects do not
    ip_observables = [o for o in observables if isinstance(o, stix2.IPv4Address)]
    assert len(sightings) == len(ip_observables)


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
    # Sightings are created for sightable observables only (Identity objects excluded)
    sightable = [
        o for o in observables
        if isinstance(o, (stix2.IPv4Address, stix2.DomainName))
    ]
    assert len(sightings) == len(sightable)


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
    # sourcetype (unknown) produces a vendor Organization Identity; invalid src/dest/user are filtered
    assert any(
        isinstance(obs, stix2.Identity) and obs.identity_class == "organization"
        for obs in observables
    )
    assert len(observables) == 1


def test_system_identity_creation_from_host(helper, author):
    # suricata:http is mapped as Infrastructure (OISF/Suricata) in sourcetype_map.yaml;
    # this should produce a SecurityPlatform Identity as source_identity.
    result = {
        "sourcetype": "suricata:http",
        "src": "10.0.0.1",
    }
    _, source_identity, _ = parse_observables_and_incident(
        helper, result, author=author
    )
    assert source_identity is not None
    assert source_identity.name == "OISF Suricata"
    assert source_identity.identity_class == "system"
    assert source_identity.x_opencti_identity_type == "SecurityPlatform"


def test_sighting_attribution(helper, author):
    # sourcetype="test" (not in YAML) → vendor Identity "Unknown" (organization) created;
    # entity_type=Software → source_identity stays None → where_sighted_refs=[author.id].
    # created_by_ref is overridden to the vendor Identity ID.
    from pycti import Identity as _Identity
    result = {"sourcetype": "test", "src": "192.168.1.1"}
    _, source_identity, sightings = parse_observables_and_incident(
        helper, result=result, author=author
    )
    assert source_identity is None
    unknown_vendor_id = _Identity.generate_id("Unknown", "organization")
    for sighting in sightings:
        assert sighting.where_sighted_refs == [author.id]
        assert sighting.created_by_ref == unknown_vendor_id


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
    from pycti import Identity as _Identity
    assert (
        ip_sighting.sighting_of_ref == "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
    )
    assert ip_sighting.confidence == 90
    assert ip_sighting.description == "Test description"
    assert source_identity is None
    assert ip_sighting.where_sighted_refs == [author.id]
    # Vendor Identity ("Unknown" org) overrides created_by_ref when sourcetype is present
    assert ip_sighting.created_by_ref == _Identity.generate_id("Unknown", "organization")
    assert "first_seen" in ip_sighting
    assert "last_seen" in ip_sighting


def test_splunk_identity_id_sets_created_by_ref(helper, author):
    """When splunk_identity_id is provided and no sourcetype is present,
    sightings carry it as created_by_ref (fallback path)."""
    from pycti import Identity

    splunk_id = Identity.generate_id("Splunk", "system")
    # No sourcetype → resolver not invoked → splunk_identity_id is the fallback
    result = {"src": "10.10.10.10"}
    _, _, sightings = parse_observables_and_incident(
        helper, result, author=author, splunk_identity_id=splunk_id
    )
    assert sightings
    for sighting in sightings:
        assert sighting.created_by_ref == splunk_id


def test_negative_sighting_splunk_identity_id(author):
    """Negative sightings carry splunk_identity_id as created_by_ref when provided."""
    from pycti import Identity

    splunk_id = Identity.generate_id("Splunk", "system")
    sighting = create_negative_sighting(
        indicator_stix_id="indicator--59e1c61c-a9fb-429b-a1c1-c80116cc8e1e",
        indicator_name="Test",
        search_type="dest",
        earliest="-30d@d",
        latest="now",
        splunk_host="splunk.example.com",
        query="| search *",
        author=author,
        splunk_identity_id=splunk_id,
    )
    assert sighting.created_by_ref == splunk_id


def test_negative_sighting_template_name_in_description(author):
    """template_name appears in the negative sighting description."""
    sighting = create_negative_sighting(
        indicator_stix_id="indicator--59e1c61c-a9fb-429b-a1c1-c80116cc8e1e",
        indicator_name="Test Indicator",
        search_type="src",
        earliest="-7d@d",
        latest="now",
        splunk_host="splunk.example.com",
        query="| search *",
        author=author,
        template_name="IP Source Search",
    )
    assert "Search template: IP Source Search" in sighting.description
    assert "Time range: -7d@d" in sighting.description


# ---------------------------------------------------------------------------
# detect_observable_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.1", "IPv4-Addr"),
        ("10.0.0.255", "IPv4-Addr"),
        ("2001:db8::1", "IPv6-Addr"),
        ("::1", "IPv6-Addr"),
        ("https://example.com/path", "Url"),
        ("http://malware.example/payload", "Url"),
        ("user@example.com", "Email-Addr"),
        ("d41d8cd98f00b204e9800998ecf8427e", "StixFile"),  # 32 hex = MD5
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "StixFile"),  # 40 hex = SHA-1
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "StixFile",
        ),  # 64 hex = SHA-256
        ("example.com", "Domain-Name"),
        ("sub.domain.co.uk", "Domain-Name"),
        ("not-a-real-observable-just-text-!!!", "Text"),
    ],
)
def test_detect_observable_type(value, expected):
    assert detect_observable_type(value) == expected


# ---------------------------------------------------------------------------
# No-results row → parse_observables_and_incident produces no observables
# ---------------------------------------------------------------------------


def test_no_results_row_produces_no_observables(helper, author):
    """The appendpipe synthetic no-results row must produce zero observables."""
    no_results_row = {
        "observable_value": "No Results",
        "dest": "No Results",
        "sourcetype": "N/A",
        "index": "N/A",
        "count": "0",
    }
    observables, source_identity, sightings = parse_observables_and_incident(
        helper, no_results_row, author=author
    )
    assert observables == []
    assert sightings == []


# ---------------------------------------------------------------------------
# Custom observable_field / observable_type_override
# ---------------------------------------------------------------------------


def test_custom_observable_field_ipv4(helper, author):
    """When observable_field is set, create observable from that field."""
    result = {
        "my_ip_field": "10.20.30.40",
        "sourcetype": "custom",
        "index": "main",
    }
    observables, _, sightings = parse_observables_and_incident(
        helper,
        result,
        author=author,
        observable_field="my_ip_field",
    )
    ip_obs = next((o for o in observables if isinstance(o, stix2.IPv4Address)), None)
    assert ip_obs is not None
    assert ip_obs.value == "10.20.30.40"
    assert sightings


def test_custom_observable_type_override_domain(helper, author):
    """observable_type_override forces the STIX type regardless of auto-detection."""
    result = {
        "observable_value": "malware.example.com",
        "sourcetype": "custom",
    }
    observables, _, _ = parse_observables_and_incident(
        helper,
        result,
        author=author,
        observable_field="observable_value",
        observable_type_override="Domain-Name",
    )
    domain_obs = next((o for o in observables if isinstance(o, stix2.DomainName)), None)
    assert domain_obs is not None
    assert domain_obs.value == "malware.example.com"


def test_custom_observable_type_url(helper, author):
    """observable_type_override=Url creates a URL observable."""
    result = {"observable_value": "https://evil.example/path"}
    observables, _, _ = parse_observables_and_incident(
        helper,
        result,
        author=author,
        observable_type_override="Url",
    )
    url_obs = next((o for o in observables if isinstance(o, stix2.URL)), None)
    assert url_obs is not None


def test_custom_observable_type_stixfile_sha256(helper, author):
    """SHA-256 hash with StixFile type override creates a File observable."""
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = {"observable_value": sha256}
    observables, _, _ = parse_observables_and_incident(
        helper,
        result,
        author=author,
        observable_type_override="StixFile",
    )
    file_obs = next((o for o in observables if isinstance(o, stix2.File)), None)
    assert file_obs is not None
    assert file_obs.hashes.get("SHA-256") == sha256
