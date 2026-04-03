import json

import pytest
from pycti import Identity as PyctiIdentity
from rflib.rf_to_stix2 import ENTITY_TYPE_MAPPER
from rflib.rf_to_stix2 import IPAddress as RFIPAddress
from rflib.rf_to_stix2 import Vulnerability as RFVulnerability
from stix2 import (
    URL,
    AttackPattern,
    Campaign,
    DomainName,
    File,
    Identity,
    Indicator,
    IntrusionSet,
    IPv4Address,
    Location,
    Malware,
    Relationship,
    Software,
    ThreatActor,
    Vulnerability,
)

# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rf_type, name, created_objs",
    [
        ("IpAddress", "1.1.1.1", [Indicator, IPv4Address, Relationship]),
        (
            "InternetDomainName",
            "http://test.com",
            [Indicator, DomainName, Relationship],
        ),
        ("URL", "test.com", [Indicator, URL, Relationship]),
        (
            "Hash",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            [Indicator, File, Relationship],
        ),
        ("MitreAttackIdentifier", "test mitreattack", [Identity, AttackPattern]),
        ("Company", "test company", [Identity, Identity]),
        ("Person", "test person", [Identity, Identity]),
        ("Organization", "test organization", [Identity, Identity]),
        ("Malware", "test malware", [Identity, Malware]),
        ("CyberVulnerability", "test cybervuln", [Vulnerability]),
        ("Product", "test product", [Software]),
        ("Country", "test country", [Location]),
        ("City", "test city", [Location]),
        ("ProvinceOrState", "test province", [Location]),
        ("Industry", "test industry", [Identity, Identity]),
        ("Operation", "test operation", [Campaign]),
        ("Threat Actor", "test threat actor", [Identity, ThreatActor]),
    ],
)
# Scenario: Each Recorded Future entity type maps to the expected STIX2 object type(s)
def test_maps_rf_types_to_the_corresponding_stix_object(rf_type, name, created_objs):
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an RF entity of type <rf_type> with name <name> resolved via ENTITY_TYPE_MAPPER
    rf_object = _given_rf_entity(rf_type, name, author, tlp)

    # When the entity is converted to STIX objects
    stix_objects = _when_to_stix_objects(rf_object)

    # Then each resulting STIX object matches the expected type at the corresponding index
    _then_stix_types_match(stix_objects, created_objs)


# Scenario: Threat Actor related to a Vulnerability risk list row is ingested as an IntrusionSet
def test_vulnerability_map_data_produces_intrusion_set_for_threat_actor():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And a Vulnerability entity for CVE-2023-1234
    vuln = _given_vulnerability("CVE-2023-1234", author, tlp)
    # And a risk list CSV row with risk score 75
    # And the row's Links contain a related entity of type "Threat Actor" named "APT28"
    rf_row = _given_vuln_risk_row(risk=75, threat_actor_name="APT28")

    # When the vulnerability processes the risk row with risk_list enabled in ta_to_intrusion_set
    _when_vuln_map_data_with_ta_scope(
        vuln,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=["risk_list"],
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(vuln.related_entities)
    # And no ThreatActor object is present in the resolved related entities
    _then_contains_no_threat_actor(vuln.related_entities)


# Scenario: Threat Actor related to an Indicator risk list row is ingested as an IntrusionSet
def test_indicator_map_data_produces_intrusion_set_for_threat_actor():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an IP address indicator for "1.1.1.1"
    indicator = _given_ip_indicator("1.1.1.1", author, tlp)
    # And a risk list CSV row with risk score 75
    # And the row's Links hits contain a related entity of type "Threat Actor" named "APT28"
    rf_row = _given_indicator_risk_row(risk=75, threat_actor_name="APT28")

    # When the indicator processes the risk row with risk_list enabled in ta_to_intrusion_set
    _when_indicator_map_data_with_ta_scope(
        indicator,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=["risk_list"],
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(indicator.related_entities)
    # And no ThreatActor object is present in the resolved related entities
    _then_contains_no_threat_actor(indicator.related_entities)


# Scenario: Vulnerability Threat Actor → IntrusionSet when risk_list is in ta_to_intrusion_set
def test_vulnerability_map_data_respects_risk_list_enabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And a Vulnerability entity for CVE-2024-9999
    vuln = _given_vulnerability("CVE-2024-9999", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_vuln_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=["risk_list"]
    _when_vuln_map_data_with_ta_scope(
        vuln,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=["risk_list"],
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(vuln.related_entities)
    # And no ThreatActor object is present
    _then_contains_no_threat_actor(vuln.related_entities)


# Scenario: Vulnerability Threat Actor → ThreatActor when risk_list NOT in ta_to_intrusion_set
def test_vulnerability_map_data_respects_risk_list_disabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And a Vulnerability entity for CVE-2024-9999
    vuln = _given_vulnerability("CVE-2024-9999", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_vuln_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=[] (risk_list disabled)
    _when_vuln_map_data_with_ta_scope(
        vuln,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=[],
    )

    # Then exactly one ThreatActor is present in the resolved related entities
    _then_contains_threat_actor(vuln.related_entities)
    # And no IntrusionSet object is present
    _then_contains_no_intrusion_set(vuln.related_entities)


# Scenario: Indicator Threat Actor → IntrusionSet when risk_list is in ta_to_intrusion_set
def test_indicator_map_data_respects_risk_list_enabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an IP address indicator for "2.2.2.2"
    indicator = _given_ip_indicator("2.2.2.2", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_indicator_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=["risk_list"]
    _when_indicator_map_data_with_ta_scope(
        indicator,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=["risk_list"],
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(indicator.related_entities)
    # And no ThreatActor object is present
    _then_contains_no_threat_actor(indicator.related_entities)


# Scenario: Indicator Threat Actor → ThreatActor when risk_list NOT in ta_to_intrusion_set
def test_indicator_map_data_respects_risk_list_disabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an IP address indicator for "2.2.2.2"
    indicator = _given_ip_indicator("2.2.2.2", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_indicator_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=[] (risk_list disabled)
    _when_indicator_map_data_with_ta_scope(
        indicator,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=[],
    )

    # Then exactly one ThreatActor is present in the resolved related entities
    _then_contains_threat_actor(indicator.related_entities)
    # And no IntrusionSet object is present
    _then_contains_no_intrusion_set(indicator.related_entities)


# ── Given helpers ────────────────────────────────────────────────────────────


def _given_author():
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        id=PyctiIdentity.generate_id("Fake author", "organization"),
        name="Fake author",
        identity_class="organization",
    )


def _given_tlp():
    return "red"


def _given_rf_entity(rf_type, name, author, tlp):
    return ENTITY_TYPE_MAPPER[rf_type](name, rf_type, author, tlp)


def _given_vulnerability(name, author, tlp):
    return RFVulnerability(name, "CyberVulnerability", author, tlp)


def _given_ip_indicator(ip, author, tlp):
    return RFIPAddress(ip, "IpAddress", author, tlp)


def _given_vuln_risk_row(risk, threat_actor_name):
    links = [
        {
            "sections": [
                {
                    "section_id": {"name": "Indicators"},
                    "lists": [
                        {
                            "type": {"name": "Threat Actor"},
                            "entities": [{"name": threat_actor_name}],
                        }
                    ],
                }
            ]
        }
    ]
    return {"Risk": str(risk), "Links": json.dumps(links)}


def _given_indicator_risk_row(risk, threat_actor_name):
    links = {
        "hits": [
            {
                "sections": [
                    {
                        "section_id": {"name": "Indicators"},
                        "lists": [
                            {
                                "type": {"name": "Threat Actor"},
                                "entities": [{"name": threat_actor_name}],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    return {"Risk": str(risk), "Links": json.dumps(links)}


# ── When helpers ─────────────────────────────────────────────────────────────


def _when_to_stix_objects(rf_object):
    return rf_object.to_stix_objects()


def _when_vuln_map_data(vuln, rf_row, tlp, related_entity_types):
    vuln.map_data(rf_row, tlp, risklist_related_entities=related_entity_types)


def _when_indicator_map_data(indicator, rf_row, tlp, related_entity_types):
    indicator.map_data(rf_row, tlp, risklist_related_entities=related_entity_types)


def _when_vuln_map_data_with_ta_scope(
    vuln, rf_row, tlp, related_entity_types, ta_to_intrusion_set
):
    vuln.map_data(
        rf_row,
        tlp,
        risklist_related_entities=related_entity_types,
        ta_to_intrusion_set=ta_to_intrusion_set,
    )


def _when_indicator_map_data_with_ta_scope(
    indicator, rf_row, tlp, related_entity_types, ta_to_intrusion_set
):
    indicator.map_data(
        rf_row,
        tlp,
        risklist_related_entities=related_entity_types,
        ta_to_intrusion_set=ta_to_intrusion_set,
    )


# ── Then helpers ─────────────────────────────────────────────────────────────


def _then_stix_types_match(stix_objects, expected_types):
    for i, stix_obj in enumerate(stix_objects):
        assert isinstance(stix_obj, expected_types[i])


def _then_contains_intrusion_set(related_entities, expected_count=1):
    found = [e for e in related_entities if isinstance(e, IntrusionSet)]
    assert (
        len(found) == expected_count
    ), f"Expected {expected_count} IntrusionSet in related_entities, got {len(found)}"


def _then_contains_no_threat_actor(related_entities):
    found = [e for e in related_entities if isinstance(e, ThreatActor)]
    assert (
        len(found) == 0
    ), f"Expected 0 ThreatActor in related_entities, got {len(found)}"


def _then_contains_threat_actor(related_entities, expected_count=1):
    found = [e for e in related_entities if isinstance(e, ThreatActor)]
    assert (
        len(found) == expected_count
    ), f"Expected {expected_count} ThreatActor in related_entities, got {len(found)}"


def _then_contains_no_intrusion_set(related_entities):
    found = [e for e in related_entities if isinstance(e, IntrusionSet)]
    assert (
        len(found) == 0
    ), f"Expected 0 IntrusionSet in related_entities, got {len(found)}"
