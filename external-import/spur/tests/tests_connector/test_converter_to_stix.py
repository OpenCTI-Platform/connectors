from unittest.mock import MagicMock

import pytest
import stix2
from connector.converter_to_stix import ConverterToStix
from connector.settings import SpurConfig


def make_config(**overrides) -> SpurConfig:
    base = {
        "api_key": "test-api-key",
        "tlp_level": "amber",
        "create_indicators": True,
        "create_asns": True,
        "create_locations": True,
        "default_score": 70,
        "batch_size": 5000,
    }
    base.update(overrides)
    return SpurConfig.model_validate(base)


@pytest.fixture
def converter():
    return ConverterToStix(helper=MagicMock(), config=make_config())


def test_author_is_spur_organization(converter):
    assert converter.author.name == "Spur"
    assert converter.author.identity_class == "organization"
    assert converter.author.external_references[0].url == "https://spur.us"


@pytest.mark.parametrize(
    "level, expected",
    [
        ("white", stix2.TLP_WHITE),
        ("clear", stix2.TLP_WHITE),
        ("green", stix2.TLP_GREEN),
        ("amber", stix2.TLP_AMBER),
        ("red", stix2.TLP_RED),
    ],
)
def test_tlp_marking_standard_levels(level, expected):
    conv = ConverterToStix(helper=MagicMock(), config=make_config(tlp_level=level))
    assert conv.tlp_marking == expected


def test_tlp_marking_amber_strict_is_custom():
    conv = ConverterToStix(
        helper=MagicMock(), config=make_config(tlp_level="amber+strict")
    )
    assert conv.tlp_marking.definition_type == "statement"
    assert conv.tlp_marking.x_opencti_definition == "TLP:AMBER+STRICT"


OBS_ID = "ipv4-addr--a1b2c3d4-1111-4111-8111-000000000001"


def test_create_relationship(converter):
    target = "autonomous-system--a1b2c3d4-2222-4222-8222-000000000002"
    rel = converter.create_relationship(OBS_ID, "belongs-to", target)
    assert rel.relationship_type == "belongs-to"
    assert rel.source_ref == OBS_ID
    assert rel.target_ref == target
    assert rel.created_by_ref == converter.author.id


def test_convert_ip_context_empty_ip_returns_empty(converter):
    assert converter.convert_ip_context({}) == []
    assert converter.convert_ip_context({"ip": ""}) == []


def test_convert_ip_context_minimal_ipv4(converter):
    objects = converter.convert_ip_context({"ip": "8.8.8.8"})
    assert len(objects) == 1
    assert isinstance(objects[0], stix2.IPv4Address)
    assert objects[0].value == "8.8.8.8"


def test_convert_ip_context_full_record(converter):
    record = {
        "ip": "1.2.3.4",
        "as": {"number": 15169, "organization": "Google"},
        "location": {"city": "Mountain View", "state": "CA", "country": "US"},
        "risks": ["TUNNEL", "PROXY"],
        "tunnels": [{"type": "VPN", "operator": "NordVPN"}],
        "infrastructure": "DATACENTER",
    }
    objects = converter.convert_ip_context(record)
    types = [type(o).__name__ for o in objects]
    assert types.count("IPv4Address") == 1
    assert types.count("AutonomousSystem") == 1
    assert types.count("Location") == 1
    assert types.count("Indicator") == 1
    assert types.count("Relationship") == 3


def test_convert_ip_context_toggles_disabled(converter):
    conv = ConverterToStix(
        helper=MagicMock(),
        config=make_config(
            create_indicators=False, create_asns=False, create_locations=False
        ),
    )
    record = {
        "ip": "1.2.3.4",
        "as": {"number": 15169, "organization": "Google"},
        "location": {"city": "Mountain View", "country": "US"},
        "risks": ["TUNNEL"],
    }
    objects = conv.convert_ip_context(record)
    assert len(objects) == 1
    assert isinstance(objects[0], stix2.IPv4Address)


def test_convert_ip_context_invalid_ip_returns_empty(converter):
    assert converter.convert_ip_context({"ip": "not-an-ip"}) == []
    converter.helper.connector_logger.warning.assert_called_once()


def test_compute_score_caps_at_100(converter):
    assert converter._compute_score({"risks": []}) == 70
    assert converter._compute_score({"risks": ["a", "b"]}) == 80
    assert converter._compute_score({"risks": ["r"] * 20}) == 100


def test_compute_labels(converter):
    labels = converter._compute_labels(
        {
            "risks": ["TUNNEL"],
            "infrastructure": "DATA_CENTER",
            "tunnels": [
                {"type": "VPN", "operator": "NordVPN"},
                {"type": "VPN", "operator": "NordVPN"},
            ],
        }
    )
    assert "tunnel" in labels
    assert "data-center" in labels
    assert "vpn" in labels
    assert "nordvpn" in labels
    # dedup keeps single vpn/nordvpn
    assert labels.count("vpn") == 1


def test_compute_labels_empty(converter):
    assert converter._compute_labels({}) == []


def test_build_description_full(converter):
    desc = converter._build_description(
        {
            "as": {"number": 15169, "organization": "Google"},
            "organization": "Google LLC",
            "location": {"city": "Mountain View", "state": "CA", "country": "US"},
            "infrastructure": "DATACENTER",
            "services": ["HTTP", "SSH"],
            "risks": ["PROXY"],
            "tunnels": [{"operator": "NordVPN", "type": "VPN"}],
            "client": {"types": ["MOBILE"], "count": 5, "countries": 3},
            "ai": {"operator": "OpenAI", "types": ["CRAWLER"]},
        }
    )
    assert "AS15169 Google" in desc
    assert "**Organization**: Google LLC" in desc
    assert "Mountain View" in desc
    assert "**Services**: HTTP, SSH" in desc
    assert "**Risks**: PROXY" in desc
    assert "NordVPN (VPN)" in desc
    assert "MOBILE" in desc
    assert "OpenAI" in desc


def test_build_description_empty(converter):
    assert converter._build_description({}) == ""


def test_create_ip_observable_ipv6(converter):
    obs = converter._create_ip_observable("2001:db8::1", 70, [], "desc")
    assert isinstance(obs, stix2.IPv6Address)


def test_create_ip_observable_invalid_returns_none(converter):
    assert converter._create_ip_observable("bad", 70, [], "d") is None
    converter.helper.connector_logger.warning.assert_called_once()


def test_create_ip_observable_stix_error_returns_none(converter, monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("stix rejected value")

    monkeypatch.setattr("connector.converter_to_stix.stix2.IPv4Address", boom)
    assert converter._create_ip_observable("1.2.3.4", 70, [], "d") is None
    converter.helper.connector_logger.error.assert_called_once()


def test_create_asn(converter):
    asn, rel = converter._create_asn(
        {"number": 15169, "organization": "Google"}, OBS_ID
    )
    assert asn.number == 15169
    assert asn.name == "Google"
    assert rel.relationship_type == "belongs-to"


def test_create_asn_default_name(converter):
    asn, _ = converter._create_asn({"number": 42}, OBS_ID)
    assert asn.name == "AS42"


def test_create_location_city(converter):
    loc, rel = converter._create_location({"city": "Paris", "country": "FR"}, OBS_ID)
    assert loc.city == "Paris"
    assert rel.relationship_type == "located-at"


def test_create_location_country_only(converter):
    loc, _ = converter._create_location({"country": "FR"}, OBS_ID)
    assert loc.country == "FR"
    assert loc.x_opencti_location_type == "Country"


def test_create_location_empty_returns_none(converter):
    assert converter._create_location({}, OBS_ID) == (None, None)


def test_create_indicator_ipv4_with_risks(converter):
    ind, rel = converter._create_indicator("1.2.3.4", OBS_ID, {"risks": ["PROXY"]})
    assert ind.pattern == "[ipv4-addr:value = '1.2.3.4']"
    assert ind.labels == ["malicious-activity"]
    assert rel.relationship_type == "based-on"


def test_create_indicator_ipv6_no_risks(converter):
    ind, _ = converter._create_indicator("2001:db8::1", OBS_ID, {})
    assert ind.pattern == "[ipv6-addr:value = '2001:db8::1']"
    assert ind.labels == ["anomalous-activity"]


def test_is_ipv6(converter):
    assert converter._is_ipv6("2001:db8::1") is True
    assert converter._is_ipv6("1.2.3.4") is False


def test_is_ipv4(converter):
    assert converter._is_ipv4("1.2.3.4") is True
    assert converter._is_ipv4("2001:db8::1") is False
